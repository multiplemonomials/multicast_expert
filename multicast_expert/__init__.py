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


from multicast_expert.interfaces import IfaceInfo as IfaceInfo
from multicast_expert.interfaces import IfaceSpecifier as IfaceSpecifier
from multicast_expert.interfaces import find_interfaces as find_interfaces
from multicast_expert.interfaces import get_default_gateway_iface as get_default_gateway_iface
from multicast_expert.interfaces import get_default_gateway_iface_ip as get_default_gateway_iface_ip
from multicast_expert.interfaces import get_default_gateway_iface_ip_v4 as get_default_gateway_iface_ip_v4
from multicast_expert.interfaces import get_default_gateway_iface_ip_v6 as get_default_gateway_iface_ip_v6
from multicast_expert.interfaces import get_interface_ips as get_interface_ips
from multicast_expert.interfaces import scan_interfaces as scan_interfaces
from multicast_expert.rx_socket import McastRxSocket as McastRxSocket
from multicast_expert.tx_socket import McastTxSocket as McastTxSocket
from multicast_expert.utils import IPv4Or6Address as IPv4Or6Address
from multicast_expert.utils import MulticastAddress as MulticastAddress
from multicast_expert.utils import MulticastExpertError as MulticastExpertError
from multicast_expert.utils import validate_mcast_ip as validate_mcast_ip
