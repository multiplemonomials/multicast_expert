from __future__ import annotations

import ipaddress
import socket
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from typing import Union

import netifaces

from multicast_expert import LOCALHOST_IPV4, LOCALHOST_IPV6
from multicast_expert.name_to_index import iface_name_to_index
from multicast_expert.utils import MulticastExpertError, ip_interface_to_ip_string


@dataclass(frozen=True)
class IfaceInfo:
    """
    Class to store data about an interface.
    """

    machine_name: str
    """
    Unique machine-readable name of this interface.

    On UNIX platforms this looks like 'eno1' or 'enp5s0f0'. On Windows platforms this is GUID,
    like '{E61AD7AD-0125-4162-9967-98BE8A9CB330}'
    """

    # NOTE: I would love to add a new member like 'friendly_name' which would have the interface
    # human readable name in Windows. However, this functionality is not available in netifaces.
    # It is available in psutil but psutil doesn't have a way to get the interface index OR the
    # GUID, which we need one of.
    # It will have to wait for netifaces-2 support...

    index: int
    """ Unique integer index of this interface. """

    ip4_addrs: Sequence[IPv4Interface]
    """
    IPv4 addresses assigned to this interface.

    Most interfaces only have one IPv4 address, but some can have multiple.
    """

    ip6_addrs: Sequence[IPv6Interface]
    """
    IPv6 addresses assigned to this interface.

    Most interfaces only have one IPv6 address, but some can have multiple.
    """

    def is_localhost(self) -> bool:
        """
        :return: Whether this interface is the loopback/localhost interface based on its IP address
        """
        # Note: on Mac, the localhost interface appears to have two IPv6 IPs, "::1" and "fe80::1%lo0".
        # But this still works because we just need ::1 to be one of its IPs.

        return IPv6Interface(LOCALHOST_IPV6) in self.ip6_addrs or IPv4Interface(LOCALHOST_IPV4) in self.ip4_addrs

    def ip_addrs(self, family: int) -> Sequence[IPv4Interface] | Sequence[IPv6Interface]:
        """
        Get the IP addresses of this interface on a given address family.

        :param family: Address family (socket.AF_INET or socket.AF_INET6)

        :return: IP addresses of the given addr family
        """
        if family == socket.AF_INET:
            return self.ip4_addrs
        elif family == socket.AF_INET6:
            return self.ip6_addrs
        message = "Unknown family!"
        raise KeyError(message)


IfaceSpecifier = Union[str, IPv4Address, IPv6Address, IfaceInfo]
""" Type for something that can specify an interface in multicast expert.

May be:
   - An IPv4 address assigned to the interface, as a string or IPv4Address
   - An IPv6 address assigned to the interface, as a string or IPv6Address
   - An interface machine readable name
   - An IfaceInfo object
"""


def scan_interfaces() -> list[IfaceInfo]:
    """
    Scan the IP interfaces on the machine and return a list containing info for each interface.

    This is a wrapper around netifaces functionality. It allows all of the interface info to be queried up
    front, saving the significant amount of CPU needed to query it each time a socket is created.

    .. note::
        If an interface is currently down, it will appear in the list, but it is undefined whether
        it will show any IP addresses or not. This is a limitation of the underlying netifaces library,
        and we hope to clarify this behavior eventually.

    :return: IfaceInfo objects scanned from the current machine.
    """
    result = []
    for iface_name in netifaces.interfaces():
        ip4_addrs = []
        ip6_addrs = []

        addresses_at_each_level = netifaces.ifaddresses(iface_name)

        # Note: Check needed because some interfaces do not have an ipv4 or ipv6 address
        if netifaces.AF_INET in addresses_at_each_level:
            for addr_info in addresses_at_each_level[netifaces.AF_INET]:
                ip4_addrs.append(IPv4Interface((addr_info["addr"], addr_info["netmask"])))

        if netifaces.AF_INET6 in addresses_at_each_level:
            for addr_info in addresses_at_each_level[netifaces.AF_INET6]:
                # Netifaces implements its own method of converting IPv6 netmasks to strings that produces strings like
                # "ffff:ffff:ffff:ffff::/64". As far as I can tell, this is not a standard notation, and in fact
                # the concept of a "subnet mask string" for an IPv6 address is... dubious at best, standards-wise.
                # Meanwhile, IPv6Address just wants the prefix length in bits.
                prefix_len = int(addr_info["netmask"].split("/")[1])

                ip6_addrs.append(IPv6Interface((addr_info["addr"], prefix_len)))

        result.append(
            IfaceInfo(
                machine_name=iface_name,
                index=iface_name_to_index(iface_name),
                ip4_addrs=ip4_addrs,
                ip6_addrs=ip6_addrs,
            )
        )

    return result


def find_interfaces(specifier: IfaceSpecifier, *, ifaces: Sequence[IfaceInfo] | None = None) -> list[IfaceInfo]:
    """
    Find one or more IfaceInfos based on an interface specifier.

    If no interfaces match the specifier, a MulticastExpertError is raised.

    :param specifier: Specifier for the interface you want to find. If this is an IfaceInfo already, it will simply be returned.
    :param ifaces: If set, and ``specifier`` is not an IfaceInfo, these interfaces will be searched using the specifier.
        If not set, then the current set of interfaces will be scanned from the machine.

    :return: Found interface(s). Note that multiple interfaces can only be returned if the specifier
        is an IP address.
    """
    # Easy case, we already have the interface
    if isinstance(specifier, IfaceInfo):
        return [specifier]

    # Now we need to actually scan the interfaces
    if ifaces is None:
        ifaces = scan_interfaces()

    # Try to match the specifier to any known interface name.
    # (please ${DEITY} do not let anyone name an interface with an IP address)
    if isinstance(specifier, str):
        for iface in ifaces:
            if iface.machine_name == specifier:
                # Found a match!
                return [iface]

    if isinstance(specifier, str):
        try:
            ip_addr = ipaddress.ip_address(specifier)
        except Exception as ex:
            message = f"Specifier '{specifier}' does not appear to be a valid interface name or IP address!"
            raise MulticastExpertError(message) from ex
    else:
        ip_addr = specifier

    is_ipv6 = isinstance(ip_addr, IPv6Address)

    result = []
    for iface in ifaces:
        # Annoyingly IPv[4/6]Network does not compare as equal to IPv[4/6]Address, so we have to convert
        addrs_to_check: set[IPv4Address] | set[IPv6Address]
        if is_ipv6:
            # go through string to work around https://github.com/python/cpython/issues/129538
            addrs_to_check = {IPv6Address(ip_interface_to_ip_string(addr)) for addr in iface.ip6_addrs}
        else:
            addrs_to_check = {addr.ip for addr in iface.ip4_addrs}

        if ip_addr in addrs_to_check:
            result.append(iface)

    if len(result) == 0:
        message = f"No matches found for interface IP address {ip_addr!s}"
        raise MulticastExpertError(message)

    return result


def get_interface_ips(include_ipv4: bool = True, include_ipv6: bool = True) -> list[str]:
    """
    Use this function to get a list of all the interface IP addresses available on this machine.

    This is the legacy way to query this information; it implicitly assumes a 1:1 mapping between interfaces and
    IP addresses. It is recommended to use scan_interfaces() instead because that function can disambiguate multiple
    interfaces with the same IP.

    :param include_ipv4: If true, IPv4 addresses will be included in the results
    :param include_ipv6: If true, IPv6 addresses will be included in the results

    .. note::
        If two interfaces on this machine have the same IP address, this function will warn and return only one of the interfaces.

    :return: List of the interface IP of every interface on your machine, as a string.
    """
    interfaces = scan_interfaces()
    ip_set: set[str] = set()
    for iface in interfaces:
        this_iface_addresses: list[str] = []
        if include_ipv4:
            this_iface_addresses.extend(ip_interface_to_ip_string(addr) for addr in iface.ip4_addrs)
        if include_ipv6:
            this_iface_addresses.extend(ip_interface_to_ip_string(addr) for addr in iface.ip6_addrs)

        for addr_str in this_iface_addresses:
            if addr_str in ip_set:
                warnings.warn(
                    f"Interface {iface.machine_name} has IP {addr_str} which is also used by another interface. "
                    f"Passing this interface IP to multicast_expert will result in an error. We recommend using "
                    f"multicast_expert.scan_interfaces() instead to handle this situation cleanly.",
                    stacklevel=2,
                )
            ip_set.add(addr_str)

    return list(ip_set)


def get_default_gateway_iface_ip_v6(*, ifaces: list[IfaceInfo] | None = None) -> str | None:
    """
    Get the IP address of the interface that connects to the default IPv6 gateway.

    :param ifaces: List of interfaces to search. If not provided, interfaces will be scanned.
    :return: IP address as a string, or None if it cannot be determined.
    """
    return get_default_gateway_iface_ip(netifaces.AF_INET6, ifaces=ifaces)


def get_default_gateway_iface_ip_v4(*, ifaces: list[IfaceInfo] | None = None) -> str | None:
    """
    Get the IP address of the interface that connects to the default IPv4 gateway.

    :param ifaces: List of interfaces to search. If not provided, interfaces will be scanned.
    :return: IP address as a string, or None if it cannot be determined.
    """
    return get_default_gateway_iface_ip(netifaces.AF_INET, ifaces=ifaces)


def get_default_gateway_iface(addr_family: int, *, ifaces: list[IfaceInfo] | None = None) -> IfaceInfo | None:
    """
    Get the info of the interface that connects to the default gateway of the given addr_family.

    :param addr_family: Address family to use (netifaces.AF_INET or netifaces.AF_INET6).
    :param ifaces: List of interfaces to search. If not provided, interfaces will be scanned.
    :return: IfaceInfo for the default gateway interface, or None if it cannot be determined.
    """
    # Enumerate all gateways using netifaces
    try:
        gateways = netifaces.gateways()
    except OSError:
        return None

    # If it can, it will identify one of those as the default gateway for traffic.
    # If not, return none.
    if not "default" in gateways:
        return None
    if not addr_family in gateways["default"]:
        return None

    default_gateway = gateways["default"][addr_family]
    default_gateway_iface = default_gateway[1]  # element 1 is the iface name, per the docs

    # Now, use the interface info to get the IP address of that interface.
    if ifaces is None:
        ifaces = scan_interfaces()

    try:
        # Note: guaranteed to return only 1 element because we are passing the iface name
        return find_interfaces(default_gateway_iface, ifaces=ifaces)[0]
    except MulticastExpertError:
        return None


def get_default_gateway_iface_ip(addr_family: int, *, ifaces: list[IfaceInfo] | None = None) -> str | None:
    """
    Get the IP address of the interface that connects to the default gateway of the given addr_family.

    :param addr_family: Address family to use (netifaces.AF_INET or netifaces.AF_INET6).
    :param ifaces: List of interfaces to search

    :return: IP address as a string, or None if it cannot be determined.
    """
    iface_info = get_default_gateway_iface(addr_family, ifaces=ifaces)
    if iface_info is None:
        return None

    if addr_family == netifaces.AF_INET and len(iface_info.ip4_addrs) > 0:
        return ip_interface_to_ip_string(iface_info.ip4_addrs[0])
    elif addr_family == netifaces.AF_INET6 and len(iface_info.ip6_addrs) > 0:
        return ip_interface_to_ip_string(iface_info.ip6_addrs[0])
    else:
        return None
