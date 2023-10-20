from __future__ import annotations

import platform

import netifaces
import select
import socket
import struct
from typing import List, Tuple, Optional, Type, cast, Union
from types import TracebackType
import ctypes

from .utils import get_interface_ips, get_default_gateway_iface_ip, validate_mcast_ip, MulticastExpertError, is_mac, is_windows, IPv4Or6Address
from . import os_multicast, LOCALHOST_IPV6, LOCALHOST_IPV4

class McastRxSocket:
    """
    Class to wrap a socket that receives from one or more multicast groups.
    """

    def __init__(self, addr_family: int, mcast_ips: List[str], port: int, iface_ip: Optional[str] = None, iface_ips: Optional[List[str]] = None, source_ips: Optional[List[str]] = None, timeout: Optional[float] = None, blocking: Optional[bool] = None):
        """
        Create a socket which receives UDP datagrams over multicast.  The socket must be opened
        (e.g. using a with statement) before it can be used.

        Note: This socket can only receive multicast traffic, not regular unicast traffic.

        Note 2: 

        :param addr_family: Sets IPv4 or IPv6 operation.  Either socket.AF_INET or socket.AF_INET6.
        :param mcast_ips: List of all possible multicast IPs that this socket can receive from.
        :param port: The port to listen on.
        :param iface_ips: Interface IPs that this socket receives from.  If left as None, multicast_expert will
            attempt to listen on all (non-loopback) interfaces discovered on your machine.  Be careful, this default 
            may not be desired in many cases.  See the docs for details.
        :param iface_ip: Legacy alias for iface_ips.  If this is given and iface_ips is not, this adds the
            given interface IP to iface_ips.
        :param source_ips: Optional, list of source addresses to restrict the multicast subscription to.  The
            OS will drop messages not from one of these IPs, and may even use special IGMPv3 source-specific
            subscription packets to ask for only those specific multicasts from switches/routers.
            This option is only supported for IPv4, currently no major OS supports it with IPv6.
        :param timeout: Timeout for receive operations using this socket.  See settimeout() for how
            this value is processed.
        :param blocking: Legacy alias for timeout.  If set to True, timeout is set to None (block forever).  If set to
            False, timeout is set to 0 (nonblocking).
        """
        self.addr_family = addr_family
        self.mcast_ips = mcast_ips
        self.port = port
        self.source_ips = source_ips

        self.is_opened = False

        # blocking overrides timeout if set
        if blocking is not None:
            self.timeout: Optional[float] = None if blocking else 0.0
        else:
            self.timeout = timeout

        # Handle legacy iface_ip argument if given
        self.iface_ips: List[str]
        if iface_ip is not None:
            if iface_ips is not None:
                raise MulticastExpertError("Both iface_ips and iface_ip may not be specified at the same time!")

            self.iface_ips = [iface_ip]

        elif iface_ips is None:
            self.iface_ips = get_interface_ips(addr_family == socket.AF_INET, addr_family == socket.AF_INET6)

            # Don't include the localhost IPs when listening on all interfaces, as that would cause
            # us to receive all mcasts sent by the current machine.
            if self.addr_family == socket.AF_INET6 and LOCALHOST_IPV6 in self.iface_ips:
                self.iface_ips.remove(LOCALHOST_IPV6)
            if self.addr_family == socket.AF_INET and LOCALHOST_IPV4 in self.iface_ips:
                self.iface_ips.remove(LOCALHOST_IPV4)

            if len(self.iface_ips) == 0:
                raise MulticastExpertError(
                    "Unable to discover any listenable interfaces on this machine.")
        else:
            self.iface_ips = iface_ips

        # Resolve the interfaces now.  This prevents having to do this relatively expensive call
        # multiple times later.
        self.iface_infos = {}
        for iface_ip in self.iface_ips:
            try:
                self.iface_infos[iface_ip] = os_multicast.get_iface_info(iface_ip)
            except KeyError:
                raise MulticastExpertError(
                    "Interface IP %s does not seem to correspond to a valid interface.  Valid interfaces: %s" %
                    (iface_ip, ", ".join(get_interface_ips())))

        # Sanity check multicast addresses
        for mcast_ip in self.mcast_ips:
            validate_mcast_ip(mcast_ip, self.addr_family)

        # Sanity check source_ips
        self.is_source_specific = not (source_ips is None or len(source_ips) == 0)
        if self.is_source_specific and self.addr_family == socket.AF_INET6:
            raise MulticastExpertError("Source-specific multicast currently cannot be used with IPv6!")

    def __enter__(self) -> McastRxSocket:
        if self.is_opened:
            raise MulticastExpertError("Attempt to open an McastRxSocket that is already open!")

        # Create the sockets and set options
        self.sockets = []

        # On Windows, we have to create a socket and bind it for each interface address, then subscribe
        # to all multicast addresses on each of those sockets
        # On Unix, we need one socket bound to each multicast address.
        if is_windows:
            for iface_ip in self.iface_ips:
                new_socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
                new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                new_socket.bind((iface_ip, self.port))

                if self.is_source_specific:
                    os_multicast.add_source_specific_memberships(new_socket, self.mcast_ips, cast(List[str], self.source_ips), self.iface_infos[iface_ip])
                else:
                    os_multicast.add_memberships(new_socket, self.mcast_ips, self.iface_infos[iface_ip], self.addr_family)

                # On Windows, by default, sent packets are looped back to local sockets on the same interface, even for interfaces
                # that are not loopback.  Change this by disabling IP_MULTICAST_LOOP unless the loopback interface is used.
                # Note: multicast_expert submitted a PR to clarify this in the Windows docs, and it was accepted!
                loop_enabled = (iface_ip == LOCALHOST_IPV4 or iface_ip == LOCALHOST_IPV6)
                if self.addr_family == socket.AF_INET:
                    new_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop_enabled)
                else:
                    new_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, loop_enabled)

                self.sockets.append(new_socket)
        else:
            for mcast_ip in self.mcast_ips:

                # For IPv6 on Unix, we need to create one socket for each mcast_ip - iface_ip permutation.
                # For IPv4, on the systems I tested at least, you can get away with subscribing to multiple
                # interfaces on one socket.
                if self.addr_family == socket.AF_INET6:
                    iface_ip_groups = [[iface_ip] for iface_ip in self.iface_ips]
                else:
                    iface_ip_groups = [self.iface_ips]

                for iface_ips_this_group in iface_ip_groups:

                    new_socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
                    new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                    if self.addr_family == socket.AF_INET6:
                        # Note: for Unix IPv6, need to specify the scope ID in the bind address in order for link-local mcast addresses to work.
                        new_socket.bind((mcast_ip, self.port, 0, self.iface_infos[iface_ips_this_group[0]].iface_idx))
                    else:
                        new_socket.bind((mcast_ip, self.port))

                    for iface_ip in iface_ips_this_group:
                        if self.is_source_specific:
                            os_multicast.add_source_specific_memberships(new_socket, [mcast_ip], cast(List[str], self.source_ips), self.iface_infos[iface_ip])
                        else:
                            os_multicast.add_memberships(new_socket, [mcast_ip], self.iface_infos[iface_ip], self.addr_family)

                    self.sockets.append(new_socket)

        self.is_opened = True

        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], traceback: Optional[TracebackType]) -> None:

        if not self.is_opened:
            raise MulticastExpertError("Attempt to close an McastRxSocket that is already closed!")

        # Close socket
        for socket in self.sockets:
            socket.close()
        self.is_opened = False

    def recvfrom(self, bufsize: int = 4096, flags: int = 0) -> Optional[Tuple[bytes, IPv4Or6Address]]:
        """
        Receive a UDP packet from the socket, returning the bytes and the sender address.
        This respects the current blocking and timeout settings.

        The "bufsize" and "flags" arguments have the same meaning as the arguments to socket.recv(), see the
        manual for that function for details.

        :return: Tuple of (bytes, address).  For IPv4, address is a tuple of IP address (str) and port number.
            For IPv6, address is a tuple of IP address (str), port number, flow info (int), and scope ID (int).
            If no packets were received (nonblocking mode or timeout), None is returned.
        """

        # Use select() to find a socket that is ready for reading
        read_list, write_list, exception_list = select.select(self.sockets, [], [], self.timeout)

        if len(read_list) == 0:
            # No data to read
            return None

        # Since we only want to return one packet at a time, just pick the first readable socket.
        return cast(Tuple[bytes, IPv4Or6Address], read_list[0].recvfrom(bufsize, flags))

    def recv(self, bufsize: int = 4096, flags: int = 0) -> Optional[bytes]:
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

    def settimeout(self, timeout: Optional[float]) -> None:
        """
        Set the timeout on socket operations.  Behavior depends on the value passed for timeout:

        * Number > 0: Receiving packets will abort if more than timeout seconds elapse while waiting for a packet.
        * 0: Socket will be put in nonblocking mode
        * None: Socket will block forever (the default)
        """

        self.timeout = timeout