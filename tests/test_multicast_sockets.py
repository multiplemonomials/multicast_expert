import asyncio
import platform
import socket
import sys
import time
import warnings
from ipaddress import IPv4Address, IPv6Address

import multicast_expert
import netifaces
import pytest
from multicast_expert import IfaceInfo

# Test constants
mcast_address_v4 = "239.2.2.2"
mcast_address_v4_alternate = "239.2.2.3"
mcast_address_v6 = "ff11::abcd"
mcast_address_v6_alternate = "ff11::abcf"
test_string = b"Test of Multicast!"
test_string_alternate = b"Test of Multicast -- alternate address!"
port = 12345


@pytest.fixture
def nonloopback_iface_ipv6() -> multicast_expert.IfaceInfo:
    """Try to obtain a non-loopback IPv6 interface. If the default interface cannot be found, then use an arbitrary interface."""
    nonloopback_iface_ipv6 = multicast_expert.get_default_gateway_iface(netifaces.AF_INET6)
    if nonloopback_iface_ipv6 is None:
        for iface in multicast_expert.scan_interfaces():
            if not iface.is_localhost() and len(iface.ip6_addrs) > 0:
                nonloopback_iface_ipv6 = iface
                break

        if nonloopback_iface_ipv6 is None:
            raise RuntimeError("Couldn't find an ipv6 interface to use for the test!")

        warnings.warn(
            f"netifaces was not able to determine the default ipv6 gateway on this machine. Using arbitrarily selected interface {nonloopback_iface_ipv6!s} instead.",
            stacklevel=2,
        )
    return nonloopback_iface_ipv6


def test_get_iface_ips() -> None:
    """
    Simple test, just prints the interface IPs available on the current machine
    :return:
    """
    print("\nIPv4 Interface IPs: -----------------")
    print("\n".join(multicast_expert.get_interface_ips(include_ipv4=True, include_ipv6=False)))

    print("\nIPv6 Interface IPs: -----------------")
    print("\n".join(multicast_expert.get_interface_ips(include_ipv4=False, include_ipv6=True)))


def test_scan_ifaces() -> None:
    """
    Simple test, just prints the interfaces available on the current machine
    :return:
    """
    print("\nInterfaces: -----------------")
    print("\n".join(str(iface_info) for iface_info in multicast_expert.scan_interfaces()))


def test_get_default_gateway() -> None:
    """
    Simple test, just prints the default gateway ifaces on the current machine
    :return:
    """
    print("\nIPv4 Default Gateway Interface: " + str(multicast_expert.get_default_gateway_iface_ip_v4()))
    print("IPv6 Default Gateway Interface: " + str(multicast_expert.get_default_gateway_iface_ip_v6()))


def test_tx_v4_can_be_used() -> None:
    """
    Sanity check that a Tx IPv4 socket can be opened and used using the default gateway
    :return:
    """
    with multicast_expert.McastTxSocket(socket.AF_INET, mcast_ips=[mcast_address_v4]) as mcast_sock:
        mcast_sock.sendto(b"Hello IPv4", (mcast_address_v4, port))


def test_tx_v6_can_be_used(nonloopback_iface_ipv6: IfaceInfo) -> None:
    """
    Sanity check that a Tx IPv6 socket can be opened and used using the default gateway
    :return:
    """
    with multicast_expert.McastTxSocket(
        socket.AF_INET6, mcast_ips=[mcast_address_v6], iface=nonloopback_iface_ipv6
    ) as mcast_sock:
        mcast_sock.sendto(b"Hello IPv6", (mcast_address_v6, port))


def test_non_mcast_raises_error(nonloopback_iface_ipv6: IfaceInfo) -> None:
    """
    Check that trying to use a non-multicast address raises an error
    """
    with pytest.raises(multicast_expert.MulticastExpertError, match="not a multicast address"):
        multicast_expert.McastTxSocket(socket.AF_INET, mcast_ips=["239.2.2.2", "192.168.5.1"])

    with pytest.raises(multicast_expert.MulticastExpertError, match="not a multicast address"):
        multicast_expert.McastTxSocket(socket.AF_INET6, mcast_ips=["abcd::"], iface=nonloopback_iface_ipv6)


def test_rx_v4_can_be_opened() -> None:
    """
    Sanity check that a Rx IPv4 socket can be opened using the default gateway
    """
    with multicast_expert.McastRxSocket(socket.AF_INET, mcast_ips=[mcast_address_v4], port=port):
        pass


def test_rx_v4_ssm_can_be_opened() -> None:
    """
    Sanity check that a Rx IPv4 Source-Specific Multicast socket can be opened using the default gateway
    """
    with multicast_expert.McastRxSocket(
        socket.AF_INET, mcast_ips=[mcast_address_v4], source_ips=["192.168.1.1", "192.168.1.2"], port=port
    ):
        pass


def test_rx_v6_can_be_opened(nonloopback_iface_ipv6: IfaceInfo) -> None:
    """
    Sanity check that a Rx IPv6 socket can be opened using the default gateway
    """
    with multicast_expert.McastRxSocket(
        socket.AF_INET6, mcast_ips=[mcast_address_v6], port=port, ifaces=[nonloopback_iface_ipv6]
    ):
        pass


def test_v4_loopback() -> None:
    """
    Check that a packet can be sent to the loopback address and received using IPv4 multicast.
    """
    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip route add 239.2.2.0/24 dev lo

    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV4,
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET, mcast_ips=[mcast_address_v4], iface_ip=multicast_expert.LOCALHOST_IPV4
        ) as mcast_tx_sock,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))

        packet = mcast_rx_sock.recvfrom()

        print("\nRx: " + repr(packet))
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])


def test_v4_loopback_with_ipaddrs() -> None:
    """
    Same as above test, but uses IPv4Address objects.
    """

    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[IPv4Address(mcast_address_v4)],
            port=port,
            iface=IPv4Address(multicast_expert.LOCALHOST_IPV4),
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET,
            mcast_ips=[IPv4Address(mcast_address_v4)],
            iface_ip=IPv4Address(multicast_expert.LOCALHOST_IPV4),
        ) as mcast_tx_sock,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))

        packet = mcast_rx_sock.recvfrom()

        print("\nRx: " + repr(packet))
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])


def test_v4_ssm_loopback() -> None:
    """
    Check that a packet can be sent to the loopback address and received using IPv4 source-specific multicast.
    Note: With only one host we cannot actually test the source-specific features, but at least we can check
    that the socket options are set correctly and it receives regular multicasts OK.
    """
    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV4,
            source_ips=[multicast_expert.LOCALHOST_IPV4],
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET, mcast_ips=[mcast_address_v4], iface_ip=multicast_expert.LOCALHOST_IPV4
        ) as mcast_tx_sock,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))

        packet = mcast_rx_sock.recvfrom()

        print("\nRx: " + repr(packet))
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])


def test_v6_loopback() -> None:
    """
    Check that a packet can be sent to the loopback address and received using IPv6 multicast.
    """
    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip -6 route add table local ff11::/16 dev lo

    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET6,
            mcast_ips=[mcast_address_v6],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV6,
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET6, mcast_ips=[mcast_address_v6], iface_ip=multicast_expert.LOCALHOST_IPV6
        ) as mcast_tx_sock,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v6, port))

        packet = mcast_rx_sock.recvfrom()

        print("\nRx: " + repr(packet))
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1][0:2] == (multicast_expert.LOCALHOST_IPV6, mcast_tx_sock.getsockname()[1])


def test_v6_loopback_with_ipaddrs() -> None:
    """
    Same as above test, but uses IPv6Address objects
    """

    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET6,
            mcast_ips=[IPv6Address(mcast_address_v6)],
            port=port,
            iface=IPv6Address(multicast_expert.LOCALHOST_IPV6),
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET6,
            mcast_ips=[IPv6Address(mcast_address_v6)],
            iface_ip=IPv6Address(multicast_expert.LOCALHOST_IPV6),
        ) as mcast_tx_sock,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v6, port))

        packet = mcast_rx_sock.recvfrom()

        print("\nRx: " + repr(packet))
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1][0:2] == (multicast_expert.LOCALHOST_IPV6, mcast_tx_sock.getsockname()[1])


def test_blocking_false() -> None:
    """
    Check that the old style ``blocking`` argument still works.
    """
    with multicast_expert.McastRxSocket(
        socket.AF_INET,
        mcast_ips=[mcast_address_v4],
        port=port,
        iface_ip=multicast_expert.LOCALHOST_IPV4,
        blocking=False,
    ) as mcast_rx_sock:
        assert mcast_rx_sock.recvfrom() is None


@pytest.mark.skipif(platform.system() == "Windows", reason="Does not pass on Windows")
def test_v6_unicast_blocked() -> None:
    """
    Check that unicast packets cannot be received by a multicast socket
    """
    with multicast_expert.McastRxSocket(
        socket.AF_INET6, mcast_ips=[mcast_address_v6], port=port, iface_ip=multicast_expert.LOCALHOST_IPV6, timeout=0.25
    ) as mcast_rx_sock:
        tx_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        tx_socket.sendto(b"Ignore this plz", (multicast_expert.LOCALHOST_IPV6, port))

        assert mcast_rx_sock.recvfrom() is None

        tx_socket.close()


def test_v4_different_mcast_addr_blocked() -> None:
    """
    Check that multicast packets to the same interface and port but a different mcast address cannot be received by a multicast socket.
    To make it even more stringent, we do subscribe to that mcast address and that port on a *different* interface, and make sure we don't
    get anything there either.
    """
    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV4,
            timeout=0.25,
        ) as mcast_rx_sock,
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4_alternate],
            port=port,
            iface_ip=multicast_expert.get_default_gateway_iface_ip_v4(),
            timeout=0.25,
        ) as alternate_rx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET, mcast_ips=[mcast_address_v4_alternate], iface_ip=multicast_expert.LOCALHOST_IPV4
        ) as mcast_tx_sock,
    ):
        mcast_tx_sock.sendto(b"Ignore this plz", (mcast_address_v4_alternate, port))

        # Neither socket should receive anything: mcast_rx_sock is on the right interface but the wrong mcast address,
        # and alternate_rx_sock is on the right mcast address but the wrong interface
        assert mcast_rx_sock.recvfrom() is None
        assert alternate_rx_sock.recvfrom() is None


def test_v4_loopback_multiple() -> None:
    """
    Check that we can open two different Rx sockets on the same port but different addresses, and use them
    with correct routing.
    """
    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip route add 239.2.2.0/24 dev lo

    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV4,
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4_alternate],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV4,
            timeout=1.0,
        ) as mcast_rx_sock_alt,
        multicast_expert.McastTxSocket(
            socket.AF_INET, mcast_ips=[mcast_address_v4], iface_ip=multicast_expert.LOCALHOST_IPV4
        ) as mcast_tx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET, mcast_ips=[mcast_address_v4_alternate], iface_ip=multicast_expert.LOCALHOST_IPV4
        ) as mcast_tx_sock_alt,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))
        mcast_tx_sock_alt.sendto(test_string_alternate, (mcast_address_v4_alternate, port))

        packet = mcast_rx_sock.recvfrom()

        print("\nRx: " + repr(packet))
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])

        packet_alt = mcast_rx_sock_alt.recvfrom()

        print("\nRx: " + repr(packet_alt))
        assert packet_alt is not None
        assert packet_alt[0] == test_string_alternate
        assert packet_alt[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock_alt.getsockname()[1])


def test_v6_loopback_multiple() -> None:
    """
    Check that we can open two different Rx sockets on the same port but different addresses, and use them
    with correct routing.
    """
    # On Linux, this test requires a route to be set up to enable transmission of multicasts on loopback:
    # sudo ip -6 route add table local ff11::/16 dev lo

    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET6,
            mcast_ips=[mcast_address_v6],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV6,
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastRxSocket(
            socket.AF_INET6,
            mcast_ips=[mcast_address_v6_alternate],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV6,
            timeout=1.0,
        ) as mcast_rx_sock_alt,
        multicast_expert.McastTxSocket(
            socket.AF_INET6, mcast_ips=[mcast_address_v6], iface_ip=multicast_expert.LOCALHOST_IPV6
        ) as mcast_tx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET6, mcast_ips=[mcast_address_v6_alternate], iface_ip=multicast_expert.LOCALHOST_IPV6
        ) as mcast_tx_sock_alt,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v6, port))
        mcast_tx_sock_alt.sendto(test_string_alternate, (mcast_address_v6_alternate, port))

        packet = mcast_rx_sock.recvfrom()

        print("\nRx: " + repr(packet))
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1][0:2] == (multicast_expert.LOCALHOST_IPV6, mcast_tx_sock.getsockname()[1])

        packet_alt = mcast_rx_sock_alt.recvfrom()

        print("\nRx: " + repr(packet_alt))
        assert packet_alt is not None
        assert packet_alt[0] == test_string_alternate
        assert packet_alt[1][0:2] == (multicast_expert.LOCALHOST_IPV6, mcast_tx_sock_alt.getsockname()[1])


def test_external_loopback_v4() -> None:
    """
    Check that packets sent over external interface can be received when `enable_external_loopback` is set.
    """
    with multicast_expert.McastTxSocket(
        socket.AF_INET, mcast_ips=[mcast_address_v4], enable_external_loopback=True
    ) as tx_socket:
        assert not tx_socket.network_interface.is_localhost()

        with multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            iface=tx_socket.network_interface,
            port=port,
            timeout=1,
            enable_external_loopback=True,
        ) as rx_socket:
            tx_socket.sendto(test_string, (mcast_address_v4, port))
            data = rx_socket.recv()
            assert data == test_string


def test_external_loopback_v6(nonloopback_iface_ipv6: IfaceInfo) -> None:
    """
    Check that packets sent over external interface can be received when `enable_external_loopback` is set.
    """
    with (
        multicast_expert.McastTxSocket(
            socket.AF_INET6,
            mcast_ips=[mcast_address_v6],
            iface_ip=nonloopback_iface_ipv6,
            enable_external_loopback=True,
        ) as tx_socket,
        multicast_expert.McastRxSocket(
            socket.AF_INET6,
            mcast_ips=[mcast_address_v6],
            ifaces=[nonloopback_iface_ipv6],
            port=port,
            timeout=1,
            enable_external_loopback=True,
        ) as rx_socket,
    ):
        tx_socket.sendto(test_string, (mcast_address_v6, port))
        data = rx_socket.recv()
        assert data == test_string


def test_external_loopback_disabled_v4() -> None:
    """
    Check that packets sent over external interface are not received when `enable_external_loopback` is set to False.
    """
    with multicast_expert.McastTxSocket(
        socket.AF_INET, mcast_ips=[mcast_address_v4], enable_external_loopback=False
    ) as tx_socket:
        assert not tx_socket.network_interface.is_localhost()

        with multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            iface=tx_socket.network_interface,
            port=port,
            timeout=1,
            enable_external_loopback=False,
        ) as rx_socket:
            tx_socket.sendto(test_string, (mcast_address_v4, port))
            rx_socket.settimeout(0.1)
            data = rx_socket.recv()
            assert data == None


def test_external_loopback_disabled_v6(nonloopback_iface_ipv6: IfaceInfo) -> None:
    """
    Check that packets sent over external interface are not received when `enable_external_loopback` is set to False.
    """
    with (
        multicast_expert.McastTxSocket(
            socket.AF_INET6,
            mcast_ips=[mcast_address_v6],
            iface_ip=nonloopback_iface_ipv6,
            enable_external_loopback=False,
        ) as tx_socket,
        multicast_expert.McastRxSocket(
            socket.AF_INET6,
            mcast_ips=[mcast_address_v6],
            ifaces=[nonloopback_iface_ipv6],
            port=port,
            timeout=1,
            enable_external_loopback=False,
        ) as rx_socket,
    ):
        rx_socket.settimeout(0.1)
        tx_socket.sendto(test_string, (mcast_address_v6, port))
        data = rx_socket.recv()
        assert data == None


@pytest.mark.skipif(sys.version_info < (3, 11), reason="Async support requires python 3.11")
async def test_async_v4() -> None:
    """
    Check that we can receive packets correctly using an Rx socket in asynchronous mode.

    Note: we would like for this Rx socket to have at least two internal sockets, so that
    we can check that the select()-like operation works. On Windows, at least, we can guarantee that
    by opening it on two interfaces and using both of them.
    """

    # Open two Tx sockets, one on localhost and one on an external interface
    with (
        multicast_expert.McastTxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            enable_external_loopback=True,
            iface=multicast_expert.get_default_gateway_iface(netifaces.AF_INET),
        ) as external_iface_tx_socket,
        multicast_expert.McastTxSocket(
            socket.AF_INET, mcast_ips=[mcast_address_v4], iface=multicast_expert.LOCALHOST_IPV4
        ) as loopback_tx_socket,
    ):
        assert not external_iface_tx_socket.network_interface.is_localhost()

        # Open a receive socket on both interfaces
        with multicast_expert.AsyncMcastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4],
            ifaces=[external_iface_tx_socket.network_interface, loopback_tx_socket.network_interface],
            port=port,
            enable_external_loopback=True,
        ) as rx_socket:
            # First, check that trying to receive without sending anything never completes and triggers a timeout
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(rx_socket.recv(), 0.5)

            # Then check that setting a timeout does the same thing and raises a TimeoutError
            rx_socket.settimeout(0.1)
            with pytest.raises(asyncio.TimeoutError):
                await rx_socket.recv()

            # Let's also try a timeout of 0
            rx_socket.settimeout(0)
            with pytest.raises(asyncio.TimeoutError):
                await rx_socket.recv()

            # Make sure we can send a packet to just one of the interfaces and it gets received
            loopback_tx_socket.sendto(b"Test 1", (mcast_address_v4, port))
            assert await rx_socket.recv() == b"Test 1"

            # There should NOT be any packets left in the socket now
            with pytest.raises(asyncio.TimeoutError):
                await rx_socket.recv()

            # Now send one packet to each of the interfaces
            loopback_tx_socket.sendto(b"Test 2", (mcast_address_v4, port))
            external_iface_tx_socket.sendto(b"Test 3", (mcast_address_v4, port))

            # Expect to receive two packets (order undefined)
            results = set()
            results.add(await rx_socket.recvfrom())
            results.add(await rx_socket.recvfrom())
            assert results == {
                (b"Test 2", loopback_tx_socket.getsockname()),
                (b"Test 3", external_iface_tx_socket.getsockname()),
            }

            # There should NOT be any packets left in the socket now
            with pytest.raises(asyncio.TimeoutError):
                await rx_socket.recv()

            # Lastly, let's test receiving a packet while in a recv() call.
            # We will use very large timeouts as who knows how long context switch delays are on GitLab CI runners...
            rx_socket.settimeout(1)
            start_time = time.perf_counter()
            recv_task = asyncio.get_running_loop().create_task(rx_socket.recv())
            await asyncio.sleep(0.5)

            send_time = time.perf_counter()
            external_iface_tx_socket.sendto(b"Test 4", (mcast_address_v4, port))

            assert await recv_task == b"Test 4"
            recv_time = time.perf_counter()

            # Check times. The recv async task should have returned pretty soon after we sent the packet.
            send_duration = send_time - start_time

            # We should have sent the packet after about a 0.5 sec sleep (though sometimes it seems like
            # the sleep can sleep for a few ms short of the intended time)
            assert send_duration > 0.45

            # We should have received the packet after sending it, and pretty soon after sending it
            assert send_time <= recv_time < (send_time + 0.5)


def test_duplicate_mcast_address() -> None:
    """
    Check that nothing bad happens if we open a Tx or Rx socket with two duplicated multicast addresses
    """
    with (
        multicast_expert.McastRxSocket(
            socket.AF_INET,
            mcast_ips=[mcast_address_v4, mcast_address_v4],
            port=port,
            iface_ip=multicast_expert.LOCALHOST_IPV4,
            timeout=1.0,
        ) as mcast_rx_sock,
        multicast_expert.McastTxSocket(
            socket.AF_INET, mcast_ips=[mcast_address_v4, mcast_address_v4], iface_ip=multicast_expert.LOCALHOST_IPV4
        ) as mcast_tx_sock,
    ):
        mcast_tx_sock.sendto(test_string, (mcast_address_v4, port))

        packet = mcast_rx_sock.recvfrom()
        assert packet is not None
        assert packet[0] == test_string
        assert packet[1] == (multicast_expert.LOCALHOST_IPV4, mcast_tx_sock.getsockname()[1])
