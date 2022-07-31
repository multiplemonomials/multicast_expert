import platform
import socket
import struct
from typing import List, Tuple
import ctypes

from .utils import get_interface_ips, make_ip_mreq_struct, iface_ip_to_index, get_default_gateway_iface_ip, MulticastExpertError

is_windows = platform.system() == "Windows"

class McastTxSocket:
    """
    Class to wrap a socket that sends to a multicast group.
    """

    def __init__(self, addr_family: int, mcast_ips: List[str], iface_ip: str=None, ttl: int=1):
        """
        Create a socket which transmits UDP datagrams over multicast.  The socket must be opened
        (e.g. using a with statement) before it can be used.

        :param addr_family: Sets IPv4 or IPv6 operation.  Either socket.AF_INET or socket.AF_INET6.
        :param mcast_ips: List of all possible multicast IPs that this socket can send to.
        :param iface_ip: Interface IP that this socket sends on.  If left as None, multicast_expert will
            attempt to guess an interface by using the interface your default gateway is on (aka
            the one your PC uses to access the internet).  Be careful, this default may not be desired
            in many cases.  See the docs for details.
        :param ttl: Time-to-live parameter to set on the packets sent by this socket, AKA hop limit for ipv6.
            This controls the number of routers that the packets may pass through until they are dropped.  The
            default value of 1 prevents the multicast packets from passing through any routers.
        """

        self.addr_family = addr_family
        self.iface_ip = iface_ip
        self.mcast_ips = mcast_ips
        self.mcast_ips_set = set(mcast_ips) # Used for checking IPs in send()
        self.ttl = ttl
        self.is_opened = False

        if self.iface_ip is None:
            self.iface_ip = get_default_gateway_iface_ip(self.addr_family)

            if self.iface_ip is None:
                raise MulticastExpertError("iface_ip not specified but unable to determine the default gateway on this machine")

        # Sanity check that the iface_ip actually exists
        if iface_ip_to_index(self.iface_ip) is None:
            raise MulticastExpertError("iface_ip %s does not seem to correspond to a valid interface.  Valid interfaces: %s" %
                                       (self.iface_ip, ", ".join(get_interface_ips())))

    def __enter__(self):
        if self.is_opened:
            raise MulticastExpertError("Attempt to open a McastTxSocket that is already open!")

        # Open the socket and set options
        self.socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)

        # Use the IP_MULTICAST_IF option to set the interface to use.
        if is_windows:
            iface_index = iface_ip_to_index(self.iface_ip)

            # On Windows, IP_MULTICAST_IF takes just the interface index
            # See docs here: https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
            if self.addr_family == socket.AF_INET:
                # IPv4 is in *network* byte order
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, struct.pack("!I", iface_index))
            else: # IPv6
                # IPv6 is in *host* byte order
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("I", iface_index))

        else:
            if self.addr_family == socket.AF_INET:
                # On Linux/Mac IPv4, IP_MULTICAST_IF takes an ip_mreq struct and needs to be specified for each
                # multicast address that we're sending to.
                for ip in self.mcast_ips:
                    self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, make_ip_mreq_struct(ip, self.iface_ip))
            else: # IPv6
                # On Linux/Mac IPv6, we have to pass a _pointer to_ the if index.  Yeah, you heard that right, a pointer.
                # So, some additional hijinks are required
                iface_index_int = ctypes.c_int(iface_ip_to_index(self.iface_ip))
                iface_index_ptr = ctypes.pointer(iface_index_int)
                ifact_index_address = ctypes.addressof(iface_index_ptr)

                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("P", ifact_index_address))

        # Now set the time-to-live (thank goodness, this is the same on all platforms)
        if self.addr_family == socket.AF_INET:
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
        else: # IPv6
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, self.ttl)

        self.is_opened = True

        return self


    def __exit__(self, exc_type, exc_val, exc_tb):

        if not self.is_opened:
            raise MulticastExpertError("Attempt to clost a McastTxSocket that is already closed!")

        # Close socket
        self.socket.close()
        self.is_opened = False

    def sendto(self, bytes: bytes, address: Tuple[str, int]):
        """
        Send a UDP datagram containing the given bytes out of the socket to the given destination
        address.

        :param bytes Bytes to send:
        :param address Tuple of the destination multicast address and the destination port:
        """

        if address[0] not in self.mcast_ips_set:
            raise MulticastExpertError("The given destination address (%s) was not one of the addresses given for this McastTxSocket to transmit to!" % (address[0], ))

        self.socket.sendto(bytes, address)