import platform
import select
import socket
import struct
from typing import List, Tuple, Optional
import ctypes

from .utils import get_interface_ips, get_default_gateway_iface_ip, validate_mcast_ip, MulticastExpertError
from . import os_multicast, LOCALHOST_IPV6, LOCALHOST_IPV4

is_windows = platform.system() == "Windows"

class McastRxSocket:
    """
    Class to wrap a socket that receives from one or more multicast groups.
    """

    def __init__(self, addr_family: int, mcast_ips: List[str], port: int, iface_ip: str=None, source_ips: List[str]=None, blocking=True):
        """
        Create a socket which receives UDP datagrams over multicast.  The socket must be opened
        (e.g. using a with statement) before it can be used.

        Note: This socket can only receive multicast traffic, not regular unicast traffic.

        Note 2: 

        :param addr_family: Sets IPv4 or IPv6 operation.  Either socket.AF_INET or socket.AF_INET6.
        :param mcast_ips: List of all possible multicast IPs that this socket can receive from.
        :param port: The port to listen on.
        :param iface_ip: Interface IP that this socket sends on.  If left as None, multicast_expert will
            attempt to guess an interface by using the interface your default gateway is on (aka
            the one your PC uses to access the internet).  Be careful, this default may not be desired
            in many cases.  See the docs for details.
        :param source_ips: Optional, list of source addresses to restrict the multicast subscription to.  The
            OS will drop messages not from one of these IPs, and may even use special IGMPv3 source-specific
            subscription packets to ask for only those specific multicasts from switches/routers.
            This option is only supported for IPv4, currently no major OS supports it with IPv6.
        :param blocking: Whether reception from this socket blocks.
        """
        self.addr_family = addr_family
        self.iface_ip = iface_ip
        self.mcast_ips = mcast_ips
        self.port = port
        self.source_ips = source_ips

        self.is_opened = False
        self.timeout = None if blocking else 0

        if self.iface_ip is None:
            self.iface_ip = get_default_gateway_iface_ip(self.addr_family)

            if self.iface_ip is None:
                raise MulticastExpertError(
                    "iface_ip not specified but unable to determine the default gateway on this machine")

        # Resolve the interface
        try:
            self.iface_info = os_multicast.get_iface_info(self.iface_ip)
        except KeyError:
            raise MulticastExpertError(
                "iface_ip %s does not seem to correspond to a valid interface.  Valid interfaces: %s" %
                (self.iface_ip, ", ".join(get_interface_ips())))

        # Sanity check multicast addresses
        for mcast_ip in self.mcast_ips:
            validate_mcast_ip(mcast_ip, self.addr_family)

        # Sanity check source_ips
        self.is_source_specific = not (source_ips is None or len(source_ips) == 0)
        if self.is_source_specific and self.addr_family == socket.AF_INET6:
            raise MulticastExpertError("Source-specific multicast currently cannot be used with IPv6!")

    def __enter__(self):
        if self.is_opened:
            raise MulticastExpertError("Attempt to open an McastRxSocket that is already open!")

        # On Windows, we just have to create one socket and bind it to the interface address, then subscribe
        # to all multicast addresses.
        # On Unix, we need one socket bound to each multicast address.
        if is_windows:
            bind_ip_and_mcast_ips_list = [(self.iface_ip, self.mcast_ips)]
        else:
            bind_ip_and_mcast_ips_list = [(mcast_ip, [mcast_ip]) for mcast_ip in self.mcast_ips]

        # Create the sockets and set options
        self.sockets = []
        for bind_ip_and_mcast_ips in bind_ip_and_mcast_ips_list:

            bind_address = bind_ip_and_mcast_ips[0]
            mcast_ips = bind_ip_and_mcast_ips[1]

            new_socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
            new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if self.addr_family == socket.AF_INET6 and not (is_windows):
                # Note: for Unix IPv6, need to specify the scope ID in the bind address in order for link-local mcast addresses to work
                new_socket.bind((bind_address, self.port, 0, self.iface_info.iface_idx))
            else:
                new_socket.bind((bind_address, self.port))

            if self.is_source_specific:
                os_multicast.add_source_specific_memberships(new_socket, mcast_ips, self.source_ips, self.iface_info)
            else:
                os_multicast.add_memberships(new_socket, mcast_ips, self.iface_info, self.addr_family)

            # On Windows, by default, sent packets are looped back to local sockets on the same interface, even for interfaces
            # that are not loopback.  Change this by disabling IP_MULTICAST_LOOP unless the loopback interface is used.
            # Note that this is *completely and totally different* from what the Win32 docs say that this option does.

            if is_windows:  
                loop_enabled = (self.iface_ip == LOCALHOST_IPV4 or self.iface_ip == LOCALHOST_IPV6)
                if self.addr_family == socket.AF_INET:
                    new_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop_enabled)
                else:
                    new_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, loop_enabled)

            self.sockets.append(new_socket)

        self.is_opened = True

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        if not self.is_opened:
            raise MulticastExpertError("Attempt to close an McastRxSocket that is already closed!")

        # Close socket
        for socket in self.sockets:
            socket.close()
        self.is_opened = False

    def recvfrom(self, bufsize=4096, flags=0) -> Optional[Tuple[bytes, Tuple]]:
        """
        Receive a UDP packet from the socket, returning the bytes and the sender address.
        This respects the current blocking and timeout settings.

        The "bufsize" and "flags" arguments have the same meaning as the arguments to socket.recv(), see the
        manual for that function for details.

        :return: Tuple of (bytes, address).  For IPv4, address is a tuple of IP address (str) and port number.
            For IPv6, address is a tuple of IP address (str), port number, flow info, and scope ID.
            If no packets were received (nonblocking mode or timeout), None is returned.
        """

        # Use select() to find a socket that is ready for reading
        read_list, write_list, exception_list = select.select(self.sockets, [], [], self.timeout)

        if len(read_list) == 0:
            # No data read
            return None

        # Since we only want to return one packet at a time, just pick the first readable socket.
        return read_list[0].recvfrom(bufsize, flags)

    def recv(self, bufsize=4096, flags=0) -> Optional[bytes]:
        """
        Receive a UDP packet from the socket, returning the bytes.
        This respects the current blocking and timeout settings.

        Note: If you need information about the sender of the packet, use recvfrom() instead.

        The "bufsize" and "flags" arguments have the same meaning as the arguments to socket.recv(), see the
        manual for that function for details.

        :return: Bytes received.
        """
        packet_and_addr = self.recvfrom(bufsize, flags)
        if packet_and_addr is None:
            return None
        else:
            return packet_and_addr[0]

    def filenos(self) -> List[int]:
        """
        Get a list of the socket file descriptor(s) used by this socket.  You can use this with the select module
        to implement blocking I/O on multiple different multicast sockets.
        """
        return [socket.fileno() for socket in self.sockets]

    def settimeout(self, timeout: float):
        """
        Set the timeout on socket operations.  Behavior depends on the value passed for timeout:

        * Number > 0: Receiving packets will abort if more than timeout seconds elapse while waiting for a packet.
        * 0: Socket will be put in nonblocking mode
        * None: Socket will block forever (the default)
        """

        self.timeout = timeout