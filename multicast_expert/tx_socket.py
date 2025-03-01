from __future__ import annotations

import ipaddress
import socket
import sys
from collections.abc import Sequence
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Self

from multicast_expert import os_multicast
from multicast_expert.interfaces import IfaceInfo, IfaceSpecifier, find_interfaces, get_default_gateway_iface_ip
from multicast_expert.utils import (
    IPv4Or6Address,
    MulticastAddress,
    MulticastExpertError,
    ip_interface_to_ip_string,
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
        mcast_ips: Sequence[MulticastAddress],
        iface: IfaceSpecifier | None = None,
        ttl: int = 1,
        enable_external_loopback: bool = False,
        iface_ip: IfaceSpecifier | None = None,
    ):
        """
        Create a socket which transmits UDP datagrams over multicast.

        The socket must be opened (e.g. using a with statement) before it can be used.

        It is recommended to manually specify the interface to open the socket on. If no interface is passed, multicast_expert will
        attempt to guess an interface from your default gateway (aka the interface your PC uses to access the internet).
        Be careful, this default may not be desired in many cases.  See the docs for details.

        ``multicast_expert.scan_interfaces()`` may be used to obtain a list of interfaces on the machine,
        and ``multicast_expert.find_interfaces()`` may be used to find interfaces matching a given specifier.
        Passing in an IfaceInfo obtained from one of those functions to this function will make opening multiple
        sockets more performant as there will be no need to scan interface info from the machine again.

        .. note::
            If two interfaces on this machine have the same IP address, passing an IP address for the interface
            argument will result in an exception, because this situation is ambiguous.

        :param addr_family: Sets IPv4 or IPv6 operation.  Either socket.AF_INET or socket.AF_INET6.
        :param mcast_ips: List of all possible multicast IPs that this socket can send to.
        :param iface: Interface that this socket sends on. May be an interface IP (as a string or object),
            an interface name, or an IfaceInfo object.
        :param ttl: Time-to-live parameter to set on the packets sent by this socket, AKA hop limit for ipv6.
            This controls the number of routers that the packets may pass through until they are dropped.  The
            default value of 1 prevents the multicast packets from passing through any routers.
        :param enable_external_loopback: Enable receiving multicast packets sent over external interfaces. If and only
            if this option is set to True, McastRxSockets will be able to receive packets sent by McastTxSockets open on
            the same address, port, and interface.
        :param iface_ip: Legacy alias for ``iface``. Deprecated.
        """
        self.addr_family = addr_family
        self.mcast_ips = [ipaddress.ip_address(mcast_ip) for mcast_ip in mcast_ips]
        self.mcast_ips_set = {str(ip) for ip in self.mcast_ips}  # Used for checking IPs in send()
        self.ttl = ttl
        self.is_opened = False

        # Figure out what interface to use
        if iface is not None and iface_ip is not None:
            message = "iface and iface_ip may not both be specified!"
            raise MulticastExpertError(message)
        if iface is None:
            iface = iface_ip

        if iface is None:
            iface = get_default_gateway_iface_ip(self.addr_family)
            if iface is None:
                message = "iface not specified but unable to determine the default gateway on this machine"
                raise MulticastExpertError(message)

        found_interfaces = find_interfaces([iface])
        if len(found_interfaces) > 1:
            message = (
                f"Interface specifier {iface!s} matches multiple interfaces ({found_interfaces[0].machine_name} "
                f"and {found_interfaces[1].machine_name})! To disambiguate in this situation, you need to pass "
                f"an IfaceInfo object returned by scan_interfaces() or find_interfaces() instead of the "
                f"interface address."
            )
            raise MulticastExpertError(message)
        self._iface_info = found_interfaces[0]

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

        # Bind the socket to the interface address.
        # If the interface has multiple addresses, just pick one, as I am 99% sure it doesn't matter to multicast which one we use.
        iface_ips = self._iface_info.ip_addrs(self.addr_family)
        if len(iface_ips) == 0:
            message = (
                "Interface does not have at least one IP address of the selected address family, cannot open socket!"
            )
            raise MulticastExpertError(message)
        if self.addr_family == socket.AF_INET6 and not is_windows:
            # Note: for Unix IPv6, need to specify the scope ID in the bind address
            self.socket.bind((ip_interface_to_ip_string(iface_ips[0]), 0, 0, self._iface_info.index))
        else:
            self.socket.bind((ip_interface_to_ip_string(iface_ips[0]), 0))  # Bind to any available port

        # Use the IP_MULTICAST_IF option to set the interface to use.
        os_multicast.set_multicast_if(self.socket, self.mcast_ips, self._iface_info, self.addr_family)

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
            enable_loopback = self.enable_external_loopback or (is_mac and self._iface_info.is_localhost())

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

        try:
            self.socket.sendto(tx_bytes, address)
        except OSError as ex:
            if sys.platform == "win32":
                # Windows will fail a sendto() call on the loopback address if it knows that no Rx socket is available
                # to receive the packet. That's kinda nice but it's incompatible with the behavior of every other platform,
                # and it also doesn't do it consistently.
                # So, we just swallow the exception in this case.
                if ex.winerror == 10051:
                    return

            raise

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

    @property
    def network_interface(self) -> IfaceInfo:
        """Get the interface used by this socket."""
        return self._iface_info
