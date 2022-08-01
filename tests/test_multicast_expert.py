import multicast_expert
import socket
import pytest

# Test constants
mcast_address_v4 = '239.2.2.2'
mcast_address_v6 = 'ff11::abcd'
test_string = b'Test of Multicast!'
port = 12345

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

    with multicast_expert.McastTxSocket(socket.AF_INET, mcast_ips=[mcast_address_v4]) as mcast_sock:
        mcast_sock.sendto(b'Hello IPv4', (mcast_address_v4, port))


def test_tx_v6_can_be_used():
    """
    Sanity check that a Tx IPv6 socket can be opened and used using the default gateway
    :return:
    """

    with multicast_expert.McastTxSocket(socket.AF_INET6, mcast_ips=[mcast_address_v6]) as mcast_sock:
        mcast_sock.sendto(b'Hello IPv6', (mcast_address_v6, port))


def test_non_mcast_raises_error():
    """
    Check that trying to use a non-multicast address raises an error
    """

    with pytest.raises(multicast_expert.MulticastExpertError, match="not a multicast address"):
        multicast_expert.McastTxSocket(socket.AF_INET, mcast_ips=['239.2.2.2', '192.168.5.1'])

    with pytest.raises(multicast_expert.MulticastExpertError, match="not a multicast address"):
        multicast_expert.McastTxSocket(socket.AF_INET6, mcast_ips=['abcd::'])


def test_rx_v4_can_be_opened():
    """
    Sanity check that a Rx IPv4 socket can be opened using the default gateway
    """

    with multicast_expert.McastRxSocket(socket.AF_INET, mcast_ips=[mcast_address_v4], port=port) as mcast_sock:
        pass


def test_rx_v4_ssm_can_be_opened():
    """
    Sanity check that a Rx IPv4 Source-Specific Multicast socket can be opened using the default gateway
    """

    with multicast_expert.McastRxSocket(socket.AF_INET, mcast_ips=[mcast_address_v4], source_ips=["192.168.1.1", "192.168.1.2"], port=port) as mcast_sock:
        pass


def test_rx_v6_can_be_opened():
    """
    Sanity check that a Rx IPv6 socket can be opened using the default gateway
    """

    with multicast_expert.McastRxSocket(socket.AF_INET6, mcast_ips=[mcast_address_v6], port=port) as mcast_sock:
        pass


def test_v4_loopback():
    """
    Check that a packet can be sent to the loopback address and received using IPv4 multicast.
    """

    # This test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip route add 239.2.2.2/32 dev lo


    with multicast_expert.McastRxSocket(socket.AF_INET,
                                        mcast_ips=[mcast_address_v4],
                                        port=port,
                                        iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_rx_sock:

        # Make sure the test doesn't get stuck forever if the packet isn't received
        mcast_rx_sock.settimeout(1.0)

        with multicast_expert.McastTxSocket(socket.AF_INET,
                                                mcast_ips=[mcast_address_v4],
                                                iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_tx_sock:

            mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))

            packet = mcast_rx_sock.recvfrom()

            print("\nRx: " + repr(packet))
            assert packet[0] == test_string
            assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])


def test_v4_ssm_loopback():
    """
    Check that a packet can be sent to the loopback address and received using IPv4 source-specific multicast.
    Note: With only one host we cannot actually test the source-specific features, but at least we can check
    that the socket options are set correctly and it receives regular multicasts OK.
    """

    with multicast_expert.McastRxSocket(socket.AF_INET,
                                        mcast_ips=[mcast_address_v4],
                                        port=port,
                                        iface_ip=multicast_expert.LOCALHOST_IPV4,
                                        source_ips=[multicast_expert.LOCALHOST_IPV4]) as mcast_rx_sock:

        # Make sure the test doesn't get stuck forever if the packet isn't received
        mcast_rx_sock.settimeout(1.0)

        with multicast_expert.McastTxSocket(socket.AF_INET,
                                            mcast_ips=[mcast_address_v4],
                                            iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_tx_sock:

            mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))

            packet = mcast_rx_sock.recvfrom()

            print("\nRx: " + repr(packet))
            assert packet[0] == test_string
            assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])


def test_v6_loopback():
    """
    Check that a packet can be sent to the loopback address and received using IPv6 multicast.
    """

    # This test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip -6 route add table local ff11::/16 dev lo


    with multicast_expert.McastRxSocket(socket.AF_INET6,
                                        mcast_ips=[mcast_address_v6],
                                        port=port,
                                        iface_ip=multicast_expert.LOCALHOST_IPV6) as mcast_rx_sock:

        # Make sure the test doesn't get stuck forever if the packet isn't received
        mcast_rx_sock.settimeout(1.0)

        with multicast_expert.McastTxSocket(socket.AF_INET6,
                                            mcast_ips=[mcast_address_v6],
                                            iface_ip=multicast_expert.LOCALHOST_IPV6) as mcast_tx_sock:

            mcast_tx_sock.sendto(test_string, (mcast_address_v6, port))

            packet = mcast_rx_sock.recvfrom()

            print("\nRx: " + repr(packet))
            assert packet[0] == test_string
            assert packet[1][0:2] == (multicast_expert.LOCALHOST_IPV6, mcast_tx_sock.getsockname()[1])