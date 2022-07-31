import socket
import struct
import platform
import ctypes

import netifaces
from typing import List, Dict, Optional

# Import needed Win32 DLL functions
if platform.system() == "Windows":
    iphlpapi = ctypes.WinDLL('iphlpapi')
    win32_GetAdapterIndex = iphlpapi.GetAdapterIndex
    win32_GetAdapterIndex.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]


# Exception class for this library
def MulticastExpertError(RuntimeError):
    pass

def get_interface_ips(include_ipv4=True, include_ipv6=True) -> List[str]:
    """
    Use this function to get a list of all the interface IP addresses available on this machine.
    Should be useful for generating help menus / info messages / etc.
    This is a thin wrapper around the netifaces library's functionality.

    :param include_ipv4: If true, IPv4 addresses will be included in the results
    :param include_ipv6: If true, IPv6 addresses will be included in the results

    :return: List of the interface IP of every interface on your machine, as a string.
    """

    ip_list = []
    for interface in netifaces.interfaces():

        all_addresses: List[Dict] = []
        addresses_at_each_level = netifaces.ifaddresses(interface)

        if include_ipv4:
            # Note: Check needed because some interfaces do not have an ipv4 or ipv6 address
            if netifaces.AF_INET in addresses_at_each_level:
                all_addresses.extend(addresses_at_each_level[netifaces.AF_INET])

        if include_ipv6:
            if netifaces.AF_INET6 in addresses_at_each_level:
                all_addresses.extend(addresses_at_each_level[netifaces.AF_INET6])

        for address_dict in all_addresses:
            ip_list.append(address_dict["addr"])

    return ip_list


def get_default_gateway_iface_ip_v6() -> Optional[str]:
    """
    Get the IP address of the interface that connects to the default IPv6 gateway, if it
    can be determined.  If it cannot be determined, None is returned.
    """
    return get_default_gateway_iface_ip(netifaces.AF_INET6)


def get_default_gateway_iface_ip_v4() -> Optional[str]:
    """
    Get the IP address of the interface that connects to the default IPv4 gateway, if it
    can be determined.  If it cannot be determined, None is returned.
    """
    return get_default_gateway_iface_ip(netifaces.AF_INET)


def get_default_gateway_iface_ip(addr_family: int) -> Optional[str]:

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
    default_gateway_iface = default_gateway[1] # element 1 is the iface name, per the docs

    # Now, use the interface name to get the IP address of that interface
    interface_addresses = netifaces.ifaddresses(default_gateway_iface)
    if addr_family not in interface_addresses:
        return None
    return interface_addresses[addr_family][0]["addr"]


def make_ip_mreq_struct(mcast_addr: str, iface_addr: str) -> bytes:
    """
    Generates an ip_mreq structure (used for setsockopt) from two string IP addresses.
    """
    return struct.pack('4s4s', socket.inet_aton(mcast_addr), socket.inet_aton(iface_addr))


def iface_ip_to_index(iface_ip: str) -> int:
    """
    Convert a network interface's interface IP into its interface index.
    """

    # First, go from IP to interface name using netifaces.  To do that, we have to iterate through
    # all of the machine's interfaces
    iface_name = None
    for interface in netifaces.interfaces():
        addresses_at_each_level = netifaces.ifaddresses(interface)
        for address_family in [netifaces.AF_INET, netifaces.AF_INET6]:
            if address_family in addresses_at_each_level:
                for address in addresses_at_each_level[address_family]:
                    if address["addr"] == iface_ip:
                        iface_name = interface

    if iface_name is None:
        raise KeyError("Could not find network address with local IP " + iface_ip)

    # Now, go from interface name to its index
    if platform.system() == "Windows":

        # To get the if index on Windows we have to use the GetAdapterIndex() function.
        # docs here: https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadapterindex

        if_idx = ctypes.c_ulong() # value is returned here

        # For reasons I don't really understand, this string has to be prepended to the names returned by netifaces
        # in order for the win32 API to recognize them.
        iface_name_string = ctypes.c_wchar_p("\\DEVICE\\TCPIP_" + iface_name)

        ret = win32_GetAdapterIndex(iface_name_string, ctypes.byref(if_idx))
        if ret != 0:
            raise ctypes.WinError(ret, "GetAdapterIndex() failed")

        return if_idx.value
    else:
        # Unix implementation is easy, we can just use the socket function
        return socket.if_nameindex(iface_name)
