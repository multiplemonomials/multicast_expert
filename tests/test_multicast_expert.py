import multicast_expert
import socket

def test_get_ifaces():
    """
    Simple test, just prints the interfaces available on the current machine
    :return:
    """
    print("\nIPv4 Interfaces: -----------------")
    print("\n".join(multicast_expert.get_interface_ips(include_ipv4=True, include_ipv6=False)))

    print("\nIPv6 Interfaces: -----------------")
    print("\n".join(multicast_expert.get_interface_ips(include_ipv4=False, include_ipv6=True)))


def test_get_default_gateway():
    """
    Simple test, just prints the default gateway ifaces on the current machine
    :return:
    """
    print("\nIPv4 Default Gateway Interface: " + multicast_expert.get_default_gateway_iface_ip_v4())
    print("IPv6 Default Gateway Interface: " + multicast_expert.get_default_gateway_iface_ip_v6())


def test_tx_v4_can_be_used():
    """
    Sanity check that a Tx IPv4 socket can be opened and used using the default gateway
    :return:
    """

    mcast_address = '239.2.2.2'

    with multicast_expert.McastTxSocket(socket.AF_INET, mcast_ips=[mcast_address]) as mcast_sock:
        mcast_sock.sendto(b'Hello IPv4', (mcast_address, 12345))

def test_tx_v6_can_be_used():
    """
    Sanity check that a Tx IPv6 socket can be opened and used using the default gateway
    :return:
    """

    mcast_address = 'ff18::abcd'

    with multicast_expert.McastTxSocket(socket.AF_INET6, mcast_ips=[mcast_address]) as mcast_sock:
        mcast_sock.sendto(b'Hello IPv6', (mcast_address, 12345))