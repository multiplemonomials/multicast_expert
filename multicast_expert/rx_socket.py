from __future__ import annotations

import ipaddress
import select
import socket
import sys
from collections.abc import Sequence
from types import TracebackType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing_extensions import Self

from multicast_expert import os_multicast
from multicast_expert.interfaces import IfaceInfo, IfaceSpecifier, find_interfaces, scan_interfaces
from multicast_expert.utils import (
    IPv4Or6Address,
    MulticastAddress,
    MulticastExpertError,
    ip_interface_to_ip_string,
    is_windows,
    validate_mcast_ip,
)


class McastRxSocket:
    """
    Class to wrap a socket that receives from one or more multicast groups.
    """

    def __init__(
        self,
        addr_family: int,
        mcast_ips: Sequence[MulticastAddress],
        port: int,
        iface: IfaceSpecifier | None = None,
        ifaces: Sequence[IfaceSpecifier] | None = None,
        source_ips: Sequence[str | ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None,
        timeout: float | None = None,
        blocking: bool | None = None,
        enable_external_loopback: bool = False,
        iface_ip: str | None = None,
        iface_ips: Sequence[str] | None = None,
    ):
        """
        Create a socket which receives UDP datagrams over multicast.

        The socket must be opened (e.g. using a with statement) before it can be used.

        By default (if no arguments are passed), the Rx socket will listen on all non-loopback interfaces of
        the machine that have addresses in the given family (IPv4 or IPv6). If you wish to select a specific
        interface or interfaces, pass them using the ``iface`` or ``ifaces`` arguments.

        ``multicast_expert.scan_interfaces()`` may be used to obtain a list of interfaces on the machine,
        and ``multicast_expert.find_interfaces()`` may be used to find interfaces matching a given specifier.
        Passing in an IfaceInfo obtained from one of those functions to this function will make opening multiple
        sockets more performant as there will be no need to scan interface info from the machine again.

        :param addr_family: Sets IPv4 or IPv6 operation.  Either socket.AF_INET or socket.AF_INET6.
        :param mcast_ips: List of all possible multicast IPs that this socket can receive from.
        :param port: The port to listen on.
        :param iface_ips: Interface IPs that this socket receives from.  If left as None, multicast_expert will
            attempt to listen on all (non-loopback) interfaces discovered on your machine.  Be careful, this default
            may not be desired in many cases.  See the docs for details.
        :param iface: Specify one interface to open the Rx socket on.
        :param ifaces: Specify multiple interfaces to open the Rx socket on.
        :param source_ips: Optional, list of source addresses to restrict the multicast subscription to.  The
            OS will drop messages not from one of these IPs, and may even use special IGMPv3 source-specific
            subscription packets to ask for only those specific multicasts from switches/routers.
            This option is only supported for IPv4, currently no major OS supports it with IPv6.
        :param timeout: Timeout for receive operations using this socket.  See settimeout() for how
            this value is processed.
        :param blocking: Legacy alias for timeout.  If set to True, timeout is set to None (block forever).  If set to
            False, timeout is set to 0 (nonblocking).
        :param enable_external_loopback: Enable loopback of multicast packets sent on external interfaces. If and only
            if this option is set to True, McastRxSockets will be able to receive packets sent by McastTxSockets open on
            the same address, port, and interface.
        :param iface_ip: Legacy alias for iface.
        :param iface_ips: Legacy alias for iface_ips
        """
        self.addr_family = addr_family

        # Convert all addresses from strings to IP addresses
        self.mcast_ips = [ipaddress.ip_address(ip) for ip in mcast_ips]
        if source_ips is not None:
            self.source_ips = [ipaddress.ip_address(ip) for ip in source_ips]

        self.port = port
        self.is_opened = False

        # blocking overrides timeout if set
        if blocking is not None:
            self.timeout: float | None = None if blocking else 0.0
        else:
            self.timeout = timeout

        # Handle legacy iface_ip arguments
        iface_specifiers: list[IfaceSpecifier] = [] if ifaces is None else list(ifaces)
        if iface is not None:
            if len(iface_specifiers) > 0:
                message = "'iface' may not be specified at the same time as 'ifaces'"
                raise MulticastExpertError(message)
            iface_specifiers = [iface]
        if iface_ips is not None:
            if len(iface_specifiers) > 0:
                message = "'iface_ips' may not be specified at the same time as other interface arguments"
                raise MulticastExpertError(message)
            iface_specifiers.extend(iface_ips)
        if iface_ip is not None:
            if len(iface_specifiers) > 0:
                message = "'iface_ip' may not be specified at the same time as other interface arguments"
                raise MulticastExpertError(message)
            iface_specifiers = [iface_ip]

        # Scanning the interfaces is expensive, so only do it if we need to
        scanned_ifaces = None
        if len(iface_specifiers) == 0 or any(not isinstance(specifier, IfaceInfo) for specifier in iface_specifiers):
            scanned_ifaces = scan_interfaces()

        # If no interfaces passed, select all interfaces with IP addresses in the desired family
        if len(iface_specifiers) == 0:
            # Tell mypy that scanned_ifaces cannot be None
            scanned_ifaces = cast(list[IfaceInfo], scanned_ifaces)

            for scanned_iface in scanned_ifaces:
                if (addr_family == socket.AF_INET and len(scanned_iface.ip4_addrs) > 0) or (
                    addr_family == socket.AF_INET6 and len(scanned_iface.ip6_addrs) > 0
                ):
                    # Don't include the localhost IPs when listening on all interfaces, as that would cause
                    # us to receive all mcasts sent by the current machine.
                    if not scanned_iface.is_localhost():
                        iface_specifiers.append(scanned_iface)

            if len(iface_specifiers) == 0:
                message = "Unable to discover any listenable interfaces on this machine."
                raise MulticastExpertError(message)

        # Resolve the interfaces now.
        self._iface_infos = find_interfaces(iface_specifiers, ifaces=scanned_ifaces)

        # Sanity check multicast addresses
        for mcast_ip in self.mcast_ips:
            validate_mcast_ip(mcast_ip, self.addr_family)

        # Sanity check source_ips
        self.is_source_specific = not (source_ips is None or len(source_ips) == 0)
        if self.is_source_specific and self.addr_family == socket.AF_INET6:
            message = "Source-specific multicast currently cannot be used with IPv6!"
            raise MulticastExpertError(message)

        self.enable_external_loopback = enable_external_loopback

    def __enter__(self) -> Self:
        if self.is_opened:
            message = "Attempt to open an McastRxSocket that is already open!"
            raise MulticastExpertError(message)

        # Create the sockets and set options
        self.sockets = []

        # On Windows, we have to create a socket and bind it for each interface address, then subscribe
        # to all multicast addresses on each of those sockets
        if is_windows:
            for iface_info in self._iface_infos:
                new_socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
                new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                new_socket.bind((ip_interface_to_ip_string(iface_info.ip_addrs(self.addr_family)[0]), self.port))

                if self.is_source_specific:
                    os_multicast.add_source_specific_memberships(
                        new_socket, self.mcast_ips, self.source_ips, iface_info
                    )
                else:
                    os_multicast.add_memberships(new_socket, self.mcast_ips, iface_info, self.addr_family)

                # On Windows, by default, sent packets are looped back to local sockets on the same interface, even for interfaces
                # that are not loopback. Change this by disabling IP_MULTICAST_LOOP unless the loopback interface is used or
                # if enable_external_loopback is set.
                # Note: multicast_expert submitted a PR to clarify this in the Windows docs, and it was accepted!
                loop_enabled = self.enable_external_loopback or iface_info.is_localhost()
                if self.addr_family == socket.AF_INET:
                    new_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop_enabled)
                else:
                    new_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, loop_enabled)

                self.sockets.append(new_socket)
        else:
            if self.addr_family == socket.AF_INET6:
                # For IPv6 on Unix, we need to create one socket for each mcast_ip - iface permutation.
                for mcast_ip in self.mcast_ips:
                    for iface_info in self._iface_infos:
                        new_socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
                        new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                        # Note: for Unix IPv6, need to specify the scope ID in the bind address in order for link-local mcast addresses to work.
                        new_socket.bind((str(mcast_ip), self.port, 0, iface_info.index))

                        os_multicast.add_memberships(new_socket, [mcast_ip], iface_info, self.addr_family)

                        self.sockets.append(new_socket)
            else:
                # Unix IPv4 -- just open one socket and bind it to the needed interfaces and groups.
                all_group_socket = socket.socket(family=self.addr_family, type=socket.SOCK_DGRAM)
                all_group_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                if sys.platform == "darwin":
                    # On MacOS we need to set SO_REUSEPORT as well as SO_REUSEADDR in order to bind multiple sockets
                    # to 0.0.0.0:<port>, so that opening another mcast socket on this port won't fail.
                    # https://stackoverflow.com/questions/32661091/behavior-of-so-reuseaddr-and-so-reuseport-changed
                    all_group_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

                if sys.platform == "linux":
                    # On Linux, we need to disable the IP_MULTICAST_ALL option (enabled by default) to prevent
                    # receiving packets to the same interface + port but a different multicast address.
                    # Sadly the IP_MULTICAST_ALL constant is not available in python yet
                    # (no bug open, but mentioned here)
                    # https://github.com/python/cpython/pull/10294#issuecomment-1374345142
                    IP_MULTICAST_ALL = 49  # noqa: N806
                    all_group_socket.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)

                all_group_socket.bind(("0.0.0.0", self.port))

                for iface_info in self._iface_infos:
                    if self.is_source_specific:
                        os_multicast.add_source_specific_memberships(
                            all_group_socket, self.mcast_ips, self.source_ips, iface_info
                        )
                    else:
                        os_multicast.add_memberships(all_group_socket, self.mcast_ips, iface_info, self.addr_family)

                self.sockets.append(all_group_socket)

        self.is_opened = True

        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        if not self.is_opened:
            message = "Attempt to open an McastRxSocket that is already open!"
            raise MulticastExpertError(message)

        # Close socket
        for sock in self.sockets:
            sock.close()
        self.is_opened = False

    def recvfrom(self, bufsize: int = 4096, flags: int = 0) -> tuple[bytes, IPv4Or6Address] | None:
        """
        Receive a UDP packet from the socket, returning the bytes and the sender address.

        This respects the current blocking and timeout settings.

        The "bufsize" and "flags" arguments have the same meaning as the arguments to socket.recv(), see the
        manual for that function for details.

        :param bufsize: Maximum amount of data to be received at once.
        :param flags: Flags that will be passed to the OS.

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
        return cast(tuple[bytes, IPv4Or6Address], read_list[0].recvfrom(bufsize, flags))

    def recv(self, bufsize: int = 4096, flags: int = 0) -> bytes | None:
        """
        Receive a UDP packet from the socket, returning the bytes.

        This respects the current blocking and timeout settings.

        Note: If you need information about the sender of the packet, use recvfrom() instead.

        The "bufsize" and "flags" arguments have the same meaning as the arguments to socket.recv(), see the
        manual for that function for details.

        :param bufsize: Maximum amount of data to be received at once.
        :param flags: Flags that will be passed to the OS.

        :return: Bytes received.
        """
        packet_and_addr = self.recvfrom(bufsize, flags)
        if packet_and_addr is None:
            return None
        else:
            return packet_and_addr[0]

    def filenos(self) -> list[int]:
        """
        Get a list of the socket file descriptor(s) used by this socket.

        You can use this with the select module to implement blocking I/O on multiple different multicast sockets.

        :return: socket file descriptor(s) used by this socket.
        """
        return [socket.fileno() for socket in self.sockets]

    def settimeout(self, timeout: float | None) -> None:
        """
        Set the timeout on socket operations.

        :param timeout: The timeout. Possible values:
            - Number > 0: Receiving packets will abort if more than timeout seconds elapse while waiting for a packet.
            - 0: Socket will be put in nonblocking mode
            - None: Socket will block forever (the default)

        """
        self.timeout = timeout

    @property
    def network_interfaces(self) -> list[IfaceInfo]:
        """Get the interface(s) used by this socket."""
        return self._iface_infos
