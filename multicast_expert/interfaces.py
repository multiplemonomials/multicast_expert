from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import ipaddress

from multicast_expert import MulticastExpertError
from multicast_expert.os_multicast import iface_name_to_index

import netifaces

@dataclass(frozen=True)
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

    ip4_addrs: list[IPv4Address]
    """ 
    IPv4 addresses assigned to this interface.
    
    Most interfaces only have one IPv4 address, but some can have multiple.
    """

    ip4_networks: list[IPv4Network]
    """ 
    IPv4 networks for each of the addresses in ip4_addrs.

    The network objects include the network address and the subnet mask.
    """

    ip6_addrs: list[IPv6Address]
    """ 
    IPv6 addresses assigned to this interface.

    Most interfaces only have one IPv6 address, but some can have multiple.
    """

    ip6_networks: list[IPv6Network]
    """ 
    IPv6 networks for each of the addresses in ip6_addrs.

    The network objects include the network address and the subnet mask.
    """

def scan_interfaces() -> list[IfaceInfo]:
    """
    Scan the IP interfaces on the machine and return a list containing info for each interface.

    This is a wrapper around netifaces functionality. It allows all of the interface info to be queried up
    front, saving the significant amount of CPU needed to query it each time a socket is created.
    """

    result = []
    for iface_name in netifaces.interfaces():
        ip4_addrs = []
        ip4_networks = []
        ip6_addrs = []
        ip6_networks = []

        addresses_at_each_level = netifaces.ifaddresses(iface_name)

        # Note: Check needed because some interfaces do not have an ipv4 or ipv6 address
        if netifaces.AF_INET in addresses_at_each_level:
            for addr_info in addresses_at_each_level[netifaces.AF_INET]:
                ip4_addrs.append(IPv4Address(addr_info["addr"]))

                # use strict=False to compute the network address from an IP on the network
                ip4_networks.append(IPv4Network((addr_info["addr"], addr_info["netmask"]), strict=False))

        if netifaces.AF_INET6 in addresses_at_each_level:
            for addr_info in addresses_at_each_level[netifaces.AF_INET6]:
                ip6_addrs.append(IPv6Address(addr_info["addr"]))

                # use strict=False to compute the network address from an IP on the network
                ip6_networks.append(IPv6Network((addr_info["addr"], addr_info["netmask"]), strict=False))

        result.append(IfaceInfo(machine_name=iface_name, index=iface_name_to_index(iface_name),
                                ip4_addrs=ip4_addrs, ip4_networks=ip4_networks,
                                ip6_addrs=ip6_addrs, ip6_networks=ip6_networks))

    return result

def find_iface_by_ip(ifaces: list[IfaceInfo], ip_addr: str | IPv4Address | IPv6Address) -> IfaceInfo:
    """
    Find an IfaceInfo based on (one of) the interface's addresses.

    If there are multiple possible interfaces with this IP address, or no interface with this address,
    a MulticastExpertError is raised.

    :param ifaces: List of interfaces to search
    :param ip_addr: Address as a string or an object

    :return: Found interface
    """

    # Convert string to address object
    if isinstance(ip_addr, str):
        ip_addr_obj = ipaddress.ip_address(ip_addr)
    else:
        ip_addr_obj = ip_addr

    is_ipv6 = isinstance(ip_addr, IPv6Address)

    result = None
    for iface in ifaces:
        if (is_ipv6 and ip_addr_obj in iface.ip6_addrs) or (not is_ipv6 and ip_addr_obj in iface.ip4_addrs):
            if result is not None:
                message = f"Interface IP {ip_addr!s} matches multiple interfaces ({result.machine_name} and {iface.machine_name})! To dis-ambiguate in this situation, you need to pass an IfaceInfo object returned by scan_interfaces() instead of the interface address."
                raise MulticastExpertError(message)
            result = iface

    if result is None:
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

    :return: List of the interface IP of every interface on your machine, as a string.
    """

    interfaces = scan_interfaces()
    ip_set: set[str] = []
    for iface in interfaces:
        if include_ipv4:
            for addr in iface.ip4_addrs:
                addr_str = str(addr)
                if addr_str in ip_set:

