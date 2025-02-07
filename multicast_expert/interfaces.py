from __future__ import annotations

import ipaddress
import socket
import warnings
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from typing import Union, cast

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

    link_layer_address: str | None
    """
    Link layer address of this interface, as a string, or None if it could not be detected.

    For most network connections, this is a 6 octet MAC address, e.g. 00:01:02:03:04:05. However,
    it might also be something else if that's what your link uses. See the netifaces README for details.

    Note: the loopback interface generally does not have a link layer address.
    """

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
   - An IPv6 address assigned to the interface, as a string or IPv6Address. Scope ID is optional, i.e.
       '1234::abcd%5' and '1234::abcd' will both work. Scope ID is required if you wish to uniquely identify
       an interface on a machine with multiple IPv6 interfaces with the same address.
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

        if netifaces.AF_LINK in addresses_at_each_level and len(addresses_at_each_level[netifaces.AF_LINK]) > 0:
            link_layer_addr = addresses_at_each_level[netifaces.AF_LINK][0]["addr"]
        else:
            link_layer_addr = None

        result.append(
            IfaceInfo(
                machine_name=iface_name,
                index=iface_name_to_index(iface_name),
                link_layer_address=link_layer_addr,
                ip4_addrs=ip4_addrs,
                ip6_addrs=ip6_addrs,
            )
        )

    return result


def _find_interfaces_for_specifier(specifier: IfaceSpecifier, ifaces: Sequence[IfaceInfo]) -> list[IfaceInfo]:
    """
    Find one or more IfaceInfos based on an interface specifier.

    If no interfaces match the specifier, a MulticastExpertError is raised.

    :param specifier: Specifier for the interface you want to find. If this is an IfaceInfo already, it will simply be returned.
    :param ifaces: If ``specifier`` is not an IfaceInfo, these interfaces will be searched using the specifier.

    :return: Found interface(s). Note that multiple interfaces can only be returned if the specifier
        is an IP address.
    """
    # Easy case, we already have the interface
    if isinstance(specifier, IfaceInfo):
        return [specifier]

    # Try to match the specifier to any known interface name.
    # (please ${DEITY} do not let anyone name an interface with an IP address)
    if isinstance(specifier, str):
        for iface in ifaces:
            if iface.machine_name == specifier:
                # Found a match!
                return [iface]

    if isinstance(specifier, str):
        try:
            specifier_ip_addr = ipaddress.ip_address(specifier)
        except Exception as ex:
            message = f"Specifier '{specifier}' does not appear to be a valid interface name or IP address!"
            raise MulticastExpertError(message) from ex
    else:
        specifier_ip_addr = specifier

    result = []
    for iface in ifaces:
        # Annoyingly IPv[4/6]Network does not compare as equal to IPv[4/6]Address, so we have to convert
        addrs_to_check: set[IPv4Address | IPv6Address] = set()
        if isinstance(specifier_ip_addr, IPv6Address):
            for addr in iface.ip6_addrs:
                # go through string to work around https://github.com/python/cpython/issues/129538
                addr_string = ip_interface_to_ip_string(addr)
                if specifier_ip_addr.scope_id is None:
                    # Trim off the scope ID from the address string
                    addr_string = addr_string.split("%")[0]
                addrs_to_check.add(IPv6Address(addr_string))
        else:
            addrs_to_check.update(addr.ip for addr in iface.ip4_addrs)

        if specifier_ip_addr in addrs_to_check:
            result.append(iface)

    if len(result) == 0:
        message = f"No matches found for interface IP address {specifier_ip_addr!s}"
        raise MulticastExpertError(message)

    return result


def find_interfaces(
    specifiers: Iterable[IfaceSpecifier], *, ifaces: Sequence[IfaceInfo] | None = None
) -> list[IfaceInfo]:
    """
    Find interfaces (represented by IfaceInfo objects) based on a collection of interface specifiers.

    If no interfaces match any individual specifier, a MulticastExpertError is raised.

    :param specifiers: Specifier for each interface you want to find. If a specifier is an IfaceInfo already,
        it will simply be added to the result list.
    :param ifaces: If set, these interfaces will be searched using the specifier.
        If not set, then the current set of interfaces will be scanned from the machine.

    :return: Found interface(s). This function will usually return as many IfaceInfos as the number of
        specifiers you passed in. However, if one IP address is used on multiple interfaces, and you
        pass in that IP address as a specifier, multiple interfaces will be matched for that specifier. Also, if
        multiple specifiers matched the same interface, the results will be deduplicated.
    """
    # First check if we were passed all IfaceInfos. If so we can return early without scanning interfaces
    specifiers = list(specifiers)
    if all(isinstance(x, IfaceInfo) for x in specifiers):
        return cast(list[IfaceInfo], specifiers)

    # Now we must scan interfaces if not passed them earlier
    if ifaces is None:
        ifaces = scan_interfaces()

    # Find candidate interfaces for each specifier
    results = [iface for specifier in specifiers for iface in _find_interfaces_for_specifier(specifier, ifaces=ifaces)]
    result_dict = {iface.index: iface for iface in results}  # deduplicate interfaces
    return list(result_dict.values())


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
        return _find_interfaces_for_specifier(default_gateway_iface, ifaces=ifaces)[0]
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
