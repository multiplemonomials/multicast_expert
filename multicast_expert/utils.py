from __future__ import annotations

import ipaddress
import platform
import socket
from typing import Union

# docsig: disable

is_windows = platform.system() == "Windows"
is_mac = platform.system() == "Darwin"


# Type which can represent an IPv4 or an IPv6 source/dest address for a TCP/UDP packet.
# For IPv4, address is a tuple of IP address (str) and port number.
# For IPv6, address is a tuple of IP address (str), port number, flow info (int), and scope ID (int).
# NOTE: Since we still support python 3.9, we cannot use new style type annotations here. We have to use the
# old Union annotation which works in 3.9
IPv4Or6Address = Union[tuple[str, int], tuple[str, int, int, int]]

# Type which represents a multicast address passed to a socket.
# Accepts a string or object form of an IP address.
MulticastAddress = Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]


# Exception class for this library
class MulticastExpertError(RuntimeError):
    pass


def validate_mcast_ip(mcast_ip: MulticastAddress, addr_family: int) -> None:
    """
    Validate that the given mcast_ip is a valid multicast address in the given addr family (IPv4 or IPv6).

    An exception is thrown if validation fails.
    """
    ip_as_obj = ipaddress.ip_address(mcast_ip)
    if not ip_as_obj.is_multicast:
        message = f"mcast_ip {mcast_ip} is not a multicast address!"
        raise MulticastExpertError(message)

    if isinstance(ip_as_obj, ipaddress.IPv4Address) and addr_family == socket.AF_INET6:
        message = f"mcast_ip {mcast_ip} is IPv4 but this is an AF_INET6 socket!"
        raise MulticastExpertError(message)

    if isinstance(ip_as_obj, ipaddress.IPv6Address) and addr_family == socket.AF_INET:
        message = f"mcast_ip {mcast_ip} is IPv6 but this is an AF_INET socket!"
        raise MulticastExpertError(message)


def ip_interface_to_ip_string(ip_interface: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
    """
    Convert IPvxInterface object to string containing the IP address.

    Workaround for https://github.com/python/cpython/issues/88178

    :param ip_interface: IP interface object
    :return: String
    """
    if isinstance(ip_interface, ipaddress.IPv4Interface):
        return str(ip_interface.ip)
    else:
        # Use str() function from superclass, which prints the scope ID but ignores the prefix info
        return ipaddress.IPv6Address.__str__(ip_interface)
