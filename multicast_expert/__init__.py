import platform
import socket
import sys

# Constants section
# ------------------------------------------------------------------------------------------------------

# Add missing source-specific multicast constants
# (cpython bug #89415, fixed in python 3.12)
if sys.version_info < (3, 12, 0):
    if platform.system() == "Windows":
        if not hasattr(socket, "IP_ADD_SOURCE_MEMBERSHIP"):
            socket.IP_ADD_SOURCE_MEMBERSHIP = 15  # type: ignore[attr-defined]
        if not hasattr(socket, "IP_DROP_SOURCE_MEMBERSHIP"):
            socket.IP_DROP_SOURCE_MEMBERSHIP = 16  # type: ignore[attr-defined]
    elif platform.system() == "Darwin":
        if not hasattr(socket, "IP_ADD_SOURCE_MEMBERSHIP"):
            socket.IP_ADD_SOURCE_MEMBERSHIP = 70  # type: ignore[attr-defined]
        if not hasattr(socket, "IP_DROP_SOURCE_MEMBERSHIP"):
            socket.IP_DROP_SOURCE_MEMBERSHIP = 71  # type: ignore[attr-defined]
    else:  # Assume Linux/Unix
        if not hasattr(socket, "IP_ADD_SOURCE_MEMBERSHIP"):
            socket.IP_ADD_SOURCE_MEMBERSHIP = 39  # type: ignore[attr-defined]
        if not hasattr(socket, "IP_DROP_SOURCE_MEMBERSHIP"):
            socket.IP_DROP_SOURCE_MEMBERSHIP = 40  # type: ignore[attr-defined]

# Localhost / loopback addresses, for convenience
LOCALHOST_IPV4 = "127.0.0.1"
LOCALHOST_IPV6 = "::1"

# Utility functions
# ------------------------------------------------------------------------------------------------------

# Receive socket
# ------------------------------------------------------------------------------------------------------
from multicast_expert.rx_socket import McastRxSocket

# Transmit socket
# ------------------------------------------------------------------------------------------------------
from multicast_expert.tx_socket import McastTxSocket
from multicast_expert.utils import (
    MulticastExpertError,
    get_default_gateway_iface_ip,
    get_default_gateway_iface_ip_v4,
    get_default_gateway_iface_ip_v6,
    get_interface_ips,
)
