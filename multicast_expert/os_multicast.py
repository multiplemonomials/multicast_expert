# Script containing the nitty-gritty OS level functions of multicast_expert.

# docsig: disable

from __future__ import annotations

import ctypes
import socket
import struct
import sys
from dataclasses import dataclass

import netifaces

from multicast_expert.utils import is_mac, is_windows

# Import needed Win32 DLL functions
if sys.platform == "win32":
    iphlpapi = ctypes.WinDLL("iphlpapi")
    win32_GetAdapterIndex = iphlpapi.GetAdapterIndex  # noqa: N816
    win32_GetAdapterIndex.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]


def iface_ip_to_name(iface_ip: str) -> str:
    """
    Convert a network interface's interface IP into its interface name.
    """
    # Go from IP to interface name using netifaces.  To do that, we have to iterate through
    # all of the machine's interfaces
    iface_name: str | None = None
    for interface in netifaces.interfaces():
        addresses_at_each_level: dict[int, list[dict[str, str]]] = netifaces.ifaddresses(interface)
        for address_family in [netifaces.AF_INET, netifaces.AF_INET6]:
            if address_family in addresses_at_each_level:
                for address in addresses_at_each_level[address_family]:
                    if address["addr"] == iface_ip:
                        iface_name = interface

    if iface_name is None:
        raise KeyError("Could not find network address with local IP " + iface_ip)

    return iface_name


def iface_name_to_index(iface_name: str) -> int:
    """
    Convert a network interface's name into its interface index.
    """
    if sys.platform == "win32":
        # To get the if index on Windows we have to use the GetAdapterIndex() function.
        # docs here: https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadapterindex

        if_idx = ctypes.c_ulong()  # value is returned here

        # For reasons I don't really understand, this string has to be prepended to the names returned by netifaces
        # in order for the win32 API to recognize them.
        iface_name_string = ctypes.c_wchar_p("\\DEVICE\\TCPIP_" + iface_name)

        ret = win32_GetAdapterIndex(iface_name_string, ctypes.byref(if_idx))
        if ret != 0:
            raise ctypes.WinError(ret, "GetAdapterIndex() failed")

        return if_idx.value
    else:
        # Unix implementation is easy, we can just use the socket function
        return socket.if_nametoindex(iface_name)


@dataclass
class IfaceInfo:
    """
    Class to store data about an interface.

    Parameters
    ----------
    iface_ip:
        IP address of the interface as a string
    iface_name:
        Name of the interface as returned by netifaces.
        On Windows this is a guid, on unix it's the name you'd get from e.g. `ip link`.
    iface_idx:
        Index of this interface with the OS.  This is an internal value used in some system calls.
    """

    iface_ip: str
    iface_name: str
    iface_idx: int


def get_iface_info(iface_ip: str) -> IfaceInfo:
    """
    Return an IfaceInfo object for a network interface from its IP address
    """
    iface_name = iface_ip_to_name(iface_ip)
    return IfaceInfo(iface_ip, iface_name, iface_name_to_index(iface_name))


def make_ip_mreqn_struct(mcast_addr: str, iface_info: IfaceInfo) -> bytes:
    """
    Generates an ip_mreqn structure (used for setsockopt) from an IPv4 address and an interface.
    """
    # Structure documented here: https://linux.die.net/man/7/ip
    # Note: Despite the fact that imr_ifindex is supposed to replace imr_address, some Linux systems
    # tested (older kernels??) seem to require the imr_address field to be populated even if you provide
    # the imr_ifindex.
    return struct.pack(
        "@4s4si",
        socket.inet_aton(mcast_addr),  # imr_multiaddr
        socket.inet_aton(iface_info.iface_ip),  # imr_address
        iface_info.iface_idx,
    )  # imr_ifindex


def make_ipv6_mreq_struct(mcast_ip: str, iface_info: IfaceInfo) -> bytes:
    """
    Generates an ipv6_mreq structure to be used with IPV6_ADD_MEMBERSHIP.
    """
    # Structure documented here on Windows: https://docs.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-ipv6_mreq
    # and here on Linux: https://github.com/torvalds/linux/blob/3d7cb6b04c3f3115719235cc6866b10326de34cd/include/uapi/linux/in6.h#L60
    return struct.pack("=16sI", socket.inet_pton(socket.AF_INET6, mcast_ip), iface_info.iface_idx)


def set_multicast_if(
    mcast_socket: socket.socket, mcast_ips: list[str], iface_info: IfaceInfo, addr_family: int
) -> None:
    """
    Set the IP_MULTICAST_IF / IPV6_MULTICAST_IF socket option to an interface on a given socket.

    Note that this option needs 4 different code paths to set it, on Windows IPv6 / Windows IPv4 / Unix IPv6 / Unix IPv4
    """
    if is_windows:
        # On Windows, IP_MULTICAST_IF takes just the interface index
        # See docs here: https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        if addr_family == socket.AF_INET:
            # IPv4 has if index in *network* byte order
            mcast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, struct.pack("!I", iface_info.iface_idx))
        else:  # IPv6
            # IPv6 has if index in *host* byte order
            mcast_socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("I", iface_info.iface_idx)
            )

    elif addr_family == socket.AF_INET:
        # On Linux/Mac IPv4, IP_MULTICAST_IF takes an ip_mreq struct and needs to be specified for each
        # multicast address that we're sending to.
        for ip in mcast_ips:
            mcast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, make_ip_mreqn_struct(ip, iface_info))
    else:  # IPv6
        # Linux/Mac IPv6 is same as Windows IPv6.
        # Note: Documentation is very misleading, it does not take a pointer from the Python perspective,
        # it just takes an int!
        mcast_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("I", iface_info.iface_idx))


def add_memberships(mcast_socket: socket.socket, mcast_ips: list[str], iface_info: IfaceInfo, addr_family: int) -> None:
    """
    Add a non-source-specific membership for the given multicast IPs on the given socket.
    """
    for mcast_ip in mcast_ips:
        if is_windows:
            # See docs here: https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
            if addr_family == socket.AF_INET:
                # For IPv4, we pass the mcast addr and the if index in *network* byte order
                mreq_bytes = struct.pack("!4sI", socket.inet_aton(mcast_ip), iface_info.iface_idx)
                mcast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq_bytes)
            else:  # IPv6
                # Note: Docs call the option "IPV6_ADD_MEMBERSHIP" but Python only has "IPV6_JOIN_GROUP"
                mcast_socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, make_ipv6_mreq_struct(mcast_ip, iface_info)
                )

        elif addr_family == socket.AF_INET:
            mcast_socket.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, make_ip_mreqn_struct(mcast_ip, iface_info)
            )
        else:  # IPv6
            # Note: Docs call the option "IPV6_ADD_MEMBERSHIP" but Python only has "IPV6_JOIN_GROUP"
            mcast_socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, make_ipv6_mreq_struct(mcast_ip, iface_info)
            )


def add_source_specific_memberships(
    mcast_socket: socket.socket, mcast_ips: list[str], source_ips: list[str], iface_info: IfaceInfo
) -> None:
    """
    Add a source-specific membership for the given multicast IPs on the given socket, with the given sources.

    Currently only supports IPv4.
    """
    for mcast_ip in mcast_ips:
        for source_ip in source_ips:
            if is_windows:
                # Struct documented here:
                # https://docs.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-ip_mreq_source
                # Note: imr_interface is in network byte order
                mreq_source_bytes = struct.pack(
                    "!4s4sI",
                    socket.inet_aton(mcast_ip),  # imr_multiaddr
                    socket.inet_aton(source_ip),  # imr_sourceaddr
                    iface_info.iface_idx,
                )  # imr_interface

            elif is_mac:
                # Struct documented here:
                # https://opensource.apple.com/source/xnu/xnu-4570.1.46/bsd/netinet/in.h.auto.html
                mreq_source_bytes = struct.pack(
                    "@4s4s4s",
                    socket.inet_aton(mcast_ip),  # imr_multiaddr
                    socket.inet_aton(source_ip),  # imr_sourceaddr
                    socket.inet_aton(iface_info.iface_ip),
                )  # imr_interface
            else:
                # Struct documented here: https://linux.die.net/man/7/ip
                mreq_source_bytes = struct.pack(
                    "@4s4s4s",
                    socket.inet_aton(mcast_ip),  # imr_multiaddr
                    socket.inet_aton(iface_info.iface_ip),  # imr_interface
                    socket.inet_aton(source_ip),
                )  # imr_sourceaddr

            mcast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_SOURCE_MEMBERSHIP, mreq_source_bytes)  # type: ignore[attr-defined]
