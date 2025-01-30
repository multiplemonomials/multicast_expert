from __future__ import annotations

import ipaddress
import platform
import socket
from typing import Union

import netifaces

# docsig: disable

is_windows = platform.system() == "Windows"
is_mac = platform.system() == "Darwin"


# Type which can represent an IPv4 or an IPv6 address.
# For IPv4, address is a tuple of IP address (str) and port number.
# For IPv6, address is a tuple of IP address (str), port number, flow info (int), and scope ID (int).
# NOTE: Since we still support python 3.9, we cannot use new style type annotations here. We have to use the
# old Union annotation which works in 3.9
IPv4Or6Address = Union[tuple[str, int], tuple[str, int, int, int]]


# Exception class for this library
class MulticastExpertError(RuntimeError):
    pass


def get_interface_ips(include_ipv4: bool = True, include_ipv6: bool = True) -> list[str]:
    """
    Use this function to get a list of all the interface IP addresses available on this machine.

    Should be useful for generating help menus / info messages / etc.
    This is a thin wrapper around the netifaces library's functionality.

    :param include_ipv4: If true, IPv4 addresses will be included in the results
    :param include_ipv6: If true, IPv6 addresses will be included in the results

    :return: List of the interface IP of every interface on your machine, as a string.
    """
    ip_list: list[str] = []
    for interface in netifaces.interfaces():
        all_addresses: list[dict[str, str]] = []
        addresses_at_each_level = netifaces.ifaddresses(interface)

        if include_ipv4:
            # Note: Check needed because some interfaces do not have an ipv4 or ipv6 address
            if netifaces.AF_INET in addresses_at_each_level:
                all_addresses.extend(addresses_at_each_level[netifaces.AF_INET])

        if include_ipv6:
            if netifaces.AF_INET6 in addresses_at_each_level:
                all_addresses.extend(addresses_at_each_level[netifaces.AF_INET6])

        ip_list.extend(address_dict["addr"] for address_dict in all_addresses)

    return ip_list


def get_default_gateway_iface_ip_v6() -> str | None:
    """
    Get the IP address of the interface that connects to the default IPv6 gateway.

    If this cannot be determined, None is returned.
    """
    return get_default_gateway_iface_ip(netifaces.AF_INET6)


def get_default_gateway_iface_ip_v4() -> str | None:
    """
    Get the IP address of the interface that connects to the default IPv4 gateway.

    If this cannot be determined, None is returned.
    """
    return get_default_gateway_iface_ip(netifaces.AF_INET)


def get_default_gateway_iface_ip(addr_family: int) -> str | None:
    """
    Get the IP address of the interface that connects to the default gateway of the given addr_family.

    If this cannot be determined, None is returned.
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

    # Now, use the interface name to get the IP address of that interface
    interface_addresses: dict[int, list[dict[str, str]]] = netifaces.ifaddresses(default_gateway_iface)
    if addr_family not in interface_addresses:
        return None
    return interface_addresses[addr_family][0]["addr"]


def validate_mcast_ip(mcast_ip: str, addr_family: int) -> None:
    """
    Validate that the given mcast_ip is a valid multicast address in the given addr family (IPv4 or IPv6).

    An exception is thrown if validation fails.
    """
    address_obj = ipaddress.ip_address(mcast_ip)
    if not address_obj.is_multicast:
        message = f"mcast_ip {mcast_ip} is not a multicast address!"
        raise MulticastExpertError(message)

    if address_obj is ipaddress.IPv4Address and addr_family == socket.AF_INET6:
        message = f"mcast_ip {mcast_ip} is IPv4 but this is an AF_INET6 socket!"
        raise MulticastExpertError(message)

    if address_obj is ipaddress.IPv6Address and addr_family == socket.AF_INET:
        message = f"mcast_ip {mcast_ip} is IPv6 but this is an AF_INET socket!"
        raise MulticastExpertError(message)
