import platform
import socket
import struct
from typing import List, Tuple
import ctypes

from .utils import get_interface_ips, get_default_gateway_iface_ip, validate_mcast_ip, MulticastExpertError
from . import os_multicast


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
        self.blocking = blocking

        self.is_opened = False

        if self.iface_ip is None:
            self.iface_ip = get_default_gateway_iface_ip(self.addr_family)

            if self.iface_ip is None:
                raise MulticastExpertError(
                    "iface_ip not specified but unable to determine the default gateway on this machine")

        # Sanity check that the iface_ip actually exists
        if os_multicast.iface_ip_to_index(self.iface_ip) is None:
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

        # Open the socket and set options
        self.socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
        self.socket.setblocking(self.blocking)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # As for the bind address, we basically have two options for Linux.
        # Option 1: Bind to INADDR_ANY.  On Linux, this allows all UDP traffic coming in to the machine, on that port,
        # from any interface, to be recieved by the socket.  This is bad because it means that traffic from other interfaces can potentially
        # enter the socket.
        # Option 2: Bind to individual multicast address.  This makes Linux act like Windows, but Linux can only bind to one 
        # mcast address per socket so we need multiple sockets.  
        # NOTE: Maybe the cleanest option would be to just bind to the interface address, and this works on Windows, but Linux doesn't support that.
        self.socket.bind(("", self.port))

        if self.is_source_specific:
            os_multicast.add_source_specific_memberships(self.socket, self.mcast_ips, self.source_ips, self.iface_ip)
        else:
            os_multicast.add_memberships(self.socket, self.mcast_ips, self.iface_ip, self.addr_family)

        self.is_opened = True

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        if not self.is_opened:
            raise MulticastExpertError("Attempt to close an McastRxSocket that is already closed!")

        # Close socket
        self.socket.close()
        self.is_opened = False

    def recvfrom(self, bufsize=4096, flags=0) -> Tuple[bytes, Tuple]:
        """
        Receive a UDP packet from the socket, returning the bytes and the sender address.
        This respects the current blocking and timeout settings.

        The "bufsize" and "flags" arguments have the same meaning as the arguments to socket.recv(), see the
        manual for that function for details.

        :return: Tuple of (bytes, address).  For IPv4, address is a tuple of IP address (str) and port number.
        For IPv6, address is a tuple of IP address (str), port number, flow info, and scope ID.
        """
        return self.socket.recvfrom(bufsize, flags)

    def recv(self, bufsize=4096, flags=0) -> bytes:
        """
        Receive a UDP packet from the socket, returning the bytes.
        This respects the current blocking and timeout settings.

        Note: If you need information about the sender of the packet, use recvfrom() instead.

        The "bufsize" and "flags" arguments have the same meaning as the arguments to socket.recv(), see the
        manual for that function for details.

        :return: Bytes received.
        """
        return self.socket.recv(bufsize, flags)

    def fileno(self) -> int:
        """
        Get the file descriptor for this socket.  Enables use of McastRxSocket with select().
        """
        return self.socket.fileno()

    def settimeout(self, timeout: float):
        """
        Set the timeout on socket operations.  Behavior depends on the value passed for timeout:

        * Number > 0: Receiving packets will throw a socket.timeout if more than timeout seconds elapse while waiting for a packet.
        * 0: Socket will be put in nonblocking mode
        * None: Socket will block forever (the default)
        """

        self.socket.settimeout(timeout)