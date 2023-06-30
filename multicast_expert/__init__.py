import socket
import platform

# Constants section
# ------------------------------------------------------------------------------------------------------

# Add missing source-specific multicast constants
# (cpython bug #89415)
if platform.system() == "Windows":
    if not hasattr(socket, "IP_ADD_SOURCE_MEMBERSHIP"):
        setattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 15)
    if not hasattr(socket, "IP_DROP_SOURCE_MEMBERSHIP"):
        setattr(socket, "IP_DROP_SOURCE_MEMBERSHIP", 16)
elif platform.system() == 'Darwin':
    if not hasattr(socket, "IP_ADD_SOURCE_MEMBERSHIP"):
        setattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 70)
    if not hasattr(socket, "IP_DROP_SOURCE_MEMBERSHIP"):
        setattr(socket, "IP_DROP_SOURCE_MEMBERSHIP", 71)
else: # Assume Linux/Unix
    if not hasattr(socket, "IP_ADD_SOURCE_MEMBERSHIP"):
        setattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 39)
    if not hasattr(socket, "IP_DROP_SOURCE_MEMBERSHIP"):
        setattr(socket, "IP_DROP_SOURCE_MEMBERSHIP", 40)

# Localhost / loopback addresses, for convenience
LOCALHOST_IPV4 = "127.0.0.1"
LOCALHOST_IPV6 = "::1"

# Utility functions
# ------------------------------------------------------------------------------------------------------

# Note: the "as" clause is needed to satisfy mypy's "no-implicit-reexport" check
from .utils import get_interface_ips as get_interface_ips
from .utils import get_default_gateway_iface_ip_v4 as get_default_gateway_iface_ip_v4
from .utils import get_default_gateway_iface_ip_v6 as get_default_gateway_iface_ip_v6
from .utils import get_default_gateway_iface_ip as get_default_gateway_iface_ip
from .utils import MulticastExpertError as MulticastExpertError

# Transmit socket
# ------------------------------------------------------------------------------------------------------
from .tx_socket import McastTxSocket as McastTxSocket

# Receive socket
# ------------------------------------------------------------------------------------------------------
from .rx_socket import McastRxSocket as McastRxSocket