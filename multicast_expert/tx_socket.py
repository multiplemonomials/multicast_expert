from __future__ import annotations

import platform
import socket
import struct
from typing import List, Tuple, Optional, Type
from types import TracebackType
import ctypes

from .utils import get_interface_ips, validate_mcast_ip, get_default_gateway_iface_ip, MulticastExpertError, is_mac, is_windows, IPv4Or6Address
from . import os_multicast, LOCALHOST_IPV4, LOCALHOST_IPV6


class McastTxSocket:
    """
    Class to wrap a socket that sends to one or more multicast groups.
    """

    def __init__(self, addr_family: int, mcast_ips: List[str], iface_ip: Optional[str] = None, ttl: int = 1):
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

        # Resolve the interface
        try:
            self.iface_info = os_multicast.get_iface_info(self.iface_ip)
        except KeyError:
            raise MulticastExpertError("iface_ip %s does not seem to correspond to a valid interface.  Valid interfaces: %s" %
                                       (self.iface_ip, ", ".join(get_interface_ips())))

        # Sanity check multicast addresses
        for mcast_ip in self.mcast_ips:
            validate_mcast_ip(mcast_ip, self.addr_family)

    def __enter__(self) -> McastTxSocket:
        if self.is_opened:
            raise MulticastExpertError("Attempt to open an McastTxSocket that is already open!")

        # Open the socket and set options
        self.socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
        self.socket.bind((self.iface_ip, 0)) # Bind to any available port

        # Use the IP_MULTICAST_IF option to set the interface to use.
        os_multicast.set_multicast_if(self.socket, self.mcast_ips, self.iface_info, self.addr_family)

        # Now set the time-to-live (thank goodness, this is the same on all platforms)
        if self.addr_family == socket.AF_INET:
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
        else: # IPv6
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, self.ttl)

        # On Unix, we need to disable multicast loop here.  Otherwise, sent packets will get looped back to local
        # sockets on the same interface.
        if not is_windows:

            # On Mac, we do want to keep loopback enabled but only on the loopback interface.
            # On Linux, always disable it.
            enable_loopback = is_mac and (self.iface_ip == LOCALHOST_IPV4 or self.iface_ip == LOCALHOST_IPV6)

            if self.addr_family == socket.AF_INET:
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, enable_loopback)
            else:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, enable_loopback)

        self.is_opened = True

        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], traceback: Optional[TracebackType]) -> None:

        if not self.is_opened:
            raise MulticastExpertError("Attempt to close an McastTxSocket that is already closed!")

        # Close socket
        self.socket.close()
        self.is_opened = False

    def sendto(self, bytes: bytes, address: IPv4Or6Address) -> None:
        """
        Send a UDP datagram containing the given bytes out of the socket to the given destination
        address.

        :param bytes: Bytes to send
        :param address: Tuple of the destination multicast address and the destination port
        """

        if address[0] not in self.mcast_ips_set:
            raise MulticastExpertError("The given destination address (%s) was not one of the addresses given for this McastTxSocket to transmit to!" % (address[0], ))

        self.socket.sendto(bytes, address)

    def fileno(self) -> int:
        """
        Get the file descriptor for this socket.
        """
        return self.socket.fileno()

    def getsockname(self) -> Tuple[str, int]:
        """
        Get the local IP and port that this socket bound itself to.
        """
        return self.socket.getsockname()  # type: ignore[no-any-return]
