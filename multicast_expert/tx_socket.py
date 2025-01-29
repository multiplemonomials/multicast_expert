from __future__ import annotations

import socket
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Self

from multicast_expert import LOCALHOST_IPV4, LOCALHOST_IPV6, os_multicast
from multicast_expert.utils import (
    IPv4Or6Address,
    MulticastExpertError,
    get_default_gateway_iface_ip,
    get_interface_ips,
    is_mac,
    is_windows,
    validate_mcast_ip,
)


class McastTxSocket:
    """
    Class to wrap a socket that sends to one or more multicast groups.
    """

    def __init__(
        self,
        addr_family: int,
        mcast_ips: list[str],
        iface_ip: str | None = None,
        ttl: int = 1,
        enable_external_loopback: bool = False,
    ):
        """
        Create a socket which transmits UDP datagrams over multicast.

        The socket must be opened (e.g. using a with statement) before it can be used.

        :param addr_family: Sets IPv4 or IPv6 operation.  Either socket.AF_INET or socket.AF_INET6.
        :param mcast_ips: List of all possible multicast IPs that this socket can send to.
        :param iface_ip: Interface IP that this socket sends on.  If left as None, multicast_expert will
            attempt to guess an interface by using the interface your default gateway is on (aka
            the one your PC uses to access the internet).  Be careful, this default may not be desired
            in many cases.  See the docs for details.
        :param ttl: Time-to-live parameter to set on the packets sent by this socket, AKA hop limit for ipv6.
            This controls the number of routers that the packets may pass through until they are dropped.  The
            default value of 1 prevents the multicast packets from passing through any routers.
        :param enable_external_loopback: Enable receiving multicast packets sent over external interfaces. If and only
            if this option is set to True, McastRxSockets will be able to receive packets sent by McastTxSockets open on
            the same address, port, and interface.
        """
        self.addr_family = addr_family
        self.iface_ip = iface_ip
        self.mcast_ips = mcast_ips
        self.mcast_ips_set = set(mcast_ips)  # Used for checking IPs in send()
        self.ttl = ttl
        self.is_opened = False

        if self.iface_ip is None:
            self.iface_ip = get_default_gateway_iface_ip(self.addr_family)

            if self.iface_ip is None:
                message = "iface_ip not specified but unable to determine the default gateway on this machine"
                raise MulticastExpertError(message)

        # Resolve the interface
        try:
            self.iface_info = os_multicast.get_iface_info(self.iface_ip)
        except KeyError as ex:
            message = f"iface_ip {self.iface_ip} does not seem to correspond to a valid interface.  Valid interfaces: {', '.join(get_interface_ips())}"
            raise MulticastExpertError(message) from ex

        # Sanity check multicast addresses
        for mcast_ip in self.mcast_ips:
            validate_mcast_ip(mcast_ip, self.addr_family)

        self.enable_external_loopback = enable_external_loopback

    def __enter__(self) -> Self:
        if self.is_opened:
            message = "Attempt to open an McastTxSocket that is already open!"
            raise MulticastExpertError(message)

        # Open the socket and set options
        self.socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)

        # Note: for Unix IPv6, need to specify the scope ID in the bind address
        if self.addr_family == socket.AF_INET6 and not is_windows:
            self.socket.bind((self.iface_ip, 0, 0, self.iface_info.iface_idx))
        else:
            self.socket.bind((self.iface_ip, 0))  # Bind to any available port

        # Use the IP_MULTICAST_IF option to set the interface to use.
        os_multicast.set_multicast_if(self.socket, self.mcast_ips, self.iface_info, self.addr_family)

        # Now set the time-to-live (thank goodness, this is the same on all platforms)
        if self.addr_family == socket.AF_INET:
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
        else:  # IPv6
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, self.ttl)

        # On Unix, we need to disable multicast loop if we do not want sent packets to get looped back to local
        # sockets on the same interface.
        if not is_windows:
            # Enable loopback if enable_external_loopback is set or if using a loopback interface on Mac.
            # Otherwise, disable loopback.
            enable_loopback = self.enable_external_loopback or (
                is_mac and (self.iface_ip in (LOCALHOST_IPV4, LOCALHOST_IPV6))
            )

            if self.addr_family == socket.AF_INET:
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, enable_loopback)
            else:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, enable_loopback)

        self.is_opened = True

        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        if not self.is_opened:
            message = "Attempt to close an McastTxSocket that is already closed!"
            raise MulticastExpertError(message)

        # Close socket
        self.socket.close()
        self.is_opened = False

    def sendto(self, tx_bytes: bytes, address: IPv4Or6Address) -> None:
        """
        Send a UDP datagram containing the given bytes out of the socket to the given destination address.

        :param tx_bytes: Bytes to send
        :param address: Tuple of the destination multicast address and the destination port
        """
        if address[0] not in self.mcast_ips_set:
            message = f"The given destination address ({address[0]}) was not one of the addresses given for this McastTxSocket to transmit to!"
            raise MulticastExpertError(message)

        self.socket.sendto(tx_bytes, address)

    def fileno(self) -> int:
        """
        Get the file descriptor for this socket.

        :return: File descriptor for this socket.
        """
        return self.socket.fileno()

    def getsockname(self) -> tuple[str, int]:
        """
        Get the local IP and port that this socket bound itself to.

        :return: Tuple of local IP and local port
        """
        return self.socket.getsockname()  # type: ignore[no-any-return]
