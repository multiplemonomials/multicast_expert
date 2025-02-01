# Windows-compatible version of if_nametoindex() using ctypes

from __future__ import annotations

import ctypes
import socket
import sys

# Import needed Win32 DLL functions
if sys.platform == "win32":
    iphlpapi = ctypes.WinDLL("iphlpapi")
    win32_GetAdapterIndex = iphlpapi.GetAdapterIndex  # noqa: N816
    win32_GetAdapterIndex.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]


def iface_name_to_index(iface_name: str) -> int:
    """
    Convert a network interface's name into its interface index.

    :param iface_name: Machine-readable name of the interface
    :return: Interface index
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
