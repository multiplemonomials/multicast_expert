import multicast_expert
import socket
import pytest
import platform

# Test constants
mcast_address_v4 = '239.2.2.2'
mcast_address_v4_alternate = '239.2.2.3'
mcast_address_v6 = 'ff13::abcd'
mcast_address_v6_alternate = 'ff13::abcf'
test_string = b'Test of Multicast!'
test_string_alternate = b'Test of Multicast -- alternate address!'
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

    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip route add 239.2.2.0/24 dev lo


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

    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip -6 route add table local ff13::/16 dev lo


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


@pytest.mark.skipif(platform.system() == "Windows", reason="Does not pass on Windows")
def test_v4_unicast_blocked():
    """
    Check that unicast packets cannot be received by a multicast socket
    """

    with multicast_expert.McastRxSocket(socket.AF_INET,
                                        mcast_ips=[mcast_address_v4],
                                        port=port,
                                        iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_rx_sock:
        mcast_rx_sock.settimeout(0.25)

        tx_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        tx_socket.sendto(b'Ignore this plz', (multicast_expert.LOCALHOST_IPV4, port))

        assert mcast_rx_sock.recvfrom() is None

        tx_socket.close()


@pytest.mark.skipif(platform.system() == "Windows", reason="Does not pass on Windows")
def test_v6_unicast_blocked():
    """
    Check that unicast packets cannot be received by a multicast socket
    """

    with multicast_expert.McastRxSocket(socket.AF_INET6,
                                        mcast_ips=[mcast_address_v6],
                                        port=port,
                                        iface_ip=multicast_expert.LOCALHOST_IPV6) as mcast_rx_sock:
        mcast_rx_sock.settimeout(0.25)

        tx_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        tx_socket.sendto(b'Ignore this plz', (multicast_expert.LOCALHOST_IPV6, port))

        assert mcast_rx_sock.recvfrom() is None

        tx_socket.close()


def test_v4_loopback_multiple():
    """
    Check that we can open two different Rx sockets on the same port but different addresses, and use them
    with correct routing.
    """

    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip route add 239.2.2.0/24 dev lo

    with multicast_expert.McastRxSocket(socket.AF_INET,
                                        mcast_ips=[mcast_address_v4],
                                        port=port,
                                        iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_rx_sock:

        # Make sure the test doesn't get stuck forever if the packet isn't received
        mcast_rx_sock.settimeout(1.0)

        with multicast_expert.McastRxSocket(socket.AF_INET,
                                            mcast_ips=[mcast_address_v4_alternate],
                                            port=port,
                                            iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_rx_sock_alt:
            # Make sure the test doesn't get stuck forever if the packet isn't received
            mcast_rx_sock_alt.settimeout(1.0)

            with multicast_expert.McastTxSocket(socket.AF_INET,
                                                    mcast_ips=[mcast_address_v4],
                                                    iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_tx_sock:

                with multicast_expert.McastTxSocket(socket.AF_INET,
                                                    mcast_ips=[mcast_address_v4_alternate],
                                                    iface_ip=multicast_expert.LOCALHOST_IPV4) as mcast_tx_sock_alt:

                    mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))
                    mcast_tx_sock_alt.sendto(test_string_alternate, (mcast_address_v4_alternate, port))

                    packet = mcast_rx_sock.recvfrom()

                    print("\nRx: " + repr(packet))
                    assert packet[0] == test_string
                    assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])

                    packet_alt = mcast_rx_sock_alt.recvfrom()

                    print("\nRx: " + repr(packet_alt))
                    assert packet_alt[0] == test_string_alternate
                    assert packet_alt[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock_alt.getsockname()[1])


def test_v6_loopback_multiple():
    """
    Check that we can open two different Rx sockets on the same port but different addresses, and use them
    with correct routing.
    """

    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip -6 route add table local ff13::/16 dev lo

    with multicast_expert.McastRxSocket(socket.AF_INET6,
                                        mcast_ips=[mcast_address_v6],
                                        port=port,
                                        iface_ip=multicast_expert.LOCALHOST_IPV6) as mcast_rx_sock:

        # Make sure the test doesn't get stuck forever if the packet isn't received
        mcast_rx_sock.settimeout(1.0)

        with multicast_expert.McastRxSocket(socket.AF_INET6,
                                            mcast_ips=[mcast_address_v6_alternate],
                                            port=port,
                                            iface_ip=multicast_expert.LOCALHOST_IPV6) as mcast_rx_sock_alt:
            # Make sure the test doesn't get stuck forever if the packet isn't received
            mcast_rx_sock_alt.settimeout(1.0)

            with multicast_expert.McastTxSocket(socket.AF_INET6,
                                                    mcast_ips=[mcast_address_v6],
                                                    iface_ip=multicast_expert.LOCALHOST_IPV6) as mcast_tx_sock:

                with multicast_expert.McastTxSocket(socket.AF_INET6,
                                                    mcast_ips=[mcast_address_v6_alternate],
                                                    iface_ip=multicast_expert.LOCALHOST_IPV6) as mcast_tx_sock_alt:

                    mcast_tx_sock.sendto(test_string, (mcast_address_v6, port))
                    mcast_tx_sock_alt.sendto(test_string_alternate, (mcast_address_v6_alternate, port))

                    packet = mcast_rx_sock.recvfrom()

                    print("\nRx: " + repr(packet))
                    assert packet[0] == test_string
                    assert packet[1][0:2] == (multicast_expert.LOCALHOST_IPV6, mcast_tx_sock.getsockname()[1])

                    packet_alt = mcast_rx_sock_alt.recvfrom()

                    print("\nRx: " + repr(packet_alt))
                    assert packet_alt[0] == test_string_alternate
                    assert packet_alt[1][0:2] == (multicast_expert.LOCALHOST_IPV6, mcast_tx_sock_alt.getsockname()[1])