from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface

import multicast_expert
import netifaces
import pytest
from multicast_expert import IfaceInfo
import pytest_mock

TEST_IFACES = [
    # eth0 has v4 and v6 addresses
    IfaceInfo(
        machine_name="eth0",
        index=20,
        link_layer_address="ad:b8:90:13:16:12",
        ip4_addrs=[IPv4Interface("192.168.1.10/24")],
        ip6_addrs=[IPv6Interface("fe80::2dc9%20/64")],
    ),
    # eth1 has two V4 addresses only (one of which duplicates eth0), and no detectable MAC address
    IfaceInfo(
        machine_name="eth1",
        index=21,
        link_layer_address=None,
        ip4_addrs=[IPv4Interface("192.168.1.11/17"), IPv4Interface("192.168.1.10/24")],
        ip6_addrs=[],
    ),
    # wlan0 has no addresses (down)
    IfaceInfo(machine_name="wlan0", index=22, link_layer_address="ac:b8:91:14:16:12", ip4_addrs=[], ip6_addrs=[]),
]


def test_scan_interfaces(mocker: pytest_mock.MockerFixture):
    """
    Test scanning interfaces to create IfaceInfo objects
    """
    mocker.patch("netifaces.interfaces").return_value = ["eth0", "eth1", "wlan0"]

    test_if_addrs = {
        "eth0": {
            netifaces.AF_LINK: [{"addr": "ad:b8:90:13:16:12"}],
            netifaces.AF_INET6: [
                {
                    "addr": "fe80::2dc9%20",
                    "netmask": "ffff:ffff:ffff:ffff::/64",
                    "broadcast": "fe80::ffff:ffff:ffff:ffff%20",
                }
            ],
            netifaces.AF_INET: [{"addr": "192.168.1.10", "netmask": "255.255.255.0", "broadcast": "192.168.1.255"}],
        },
        "eth1": {
            netifaces.AF_INET: [
                {"addr": "192.168.1.11", "netmask": "255.255.128.0", "broadcast": "192.168.127.255"},
                {"addr": "192.168.1.10", "netmask": "255.255.255.0", "broadcast": "192.168.1.255"},
            ],
        },
        "wlan0": {netifaces.AF_LINK: [{"addr": "ac:b8:91:14:16:12"}]},
    }
    test_if_indexes = {"eth0": 20, "eth1": 21, "wlan0": 22}
    mocker.patch("netifaces.ifaddresses").side_effect = lambda name: test_if_addrs[name]
    mocker.patch("multicast_expert.interfaces.iface_name_to_index").side_effect = lambda name: test_if_indexes[name]

    assert multicast_expert.scan_interfaces() == TEST_IFACES


def test_find_iface_by_name():
    """
    Test that finding an interface by name works
    """

    assert multicast_expert.find_interfaces(["wlan0"], ifaces=TEST_IFACES) == [TEST_IFACES[2]]
    assert multicast_expert.find_interfaces(["eth1"], ifaces=TEST_IFACES) == [TEST_IFACES[1]]

    with pytest.raises(
        multicast_expert.MulticastExpertError, match="does not appear to be a valid interface name or IP"
    ):
        multicast_expert.find_interfaces(["blargh"])


def test_find_iface_by_ip():
    """
    Test that finding an interface by IP address works
    """

    assert multicast_expert.find_interfaces(["192.168.1.11"], ifaces=TEST_IFACES) == [TEST_IFACES[1]]
    assert multicast_expert.find_interfaces([IPv4Address("192.168.1.10")], ifaces=TEST_IFACES) == [
        TEST_IFACES[0],
        TEST_IFACES[1],
    ]

    # Test with and without scope ID
    assert multicast_expert.find_interfaces([IPv6Address("fe80::2dc9%20")], ifaces=TEST_IFACES) == [TEST_IFACES[0]]
    assert multicast_expert.find_interfaces([IPv6Address("fe80::2dc9")], ifaces=TEST_IFACES) == [TEST_IFACES[0]]

    with pytest.raises(multicast_expert.MulticastExpertError, match="No matches found for interface IP address"):
        multicast_expert.find_interfaces([IPv4Address("192.168.1.12")])

    with pytest.raises(multicast_expert.MulticastExpertError, match="No matches found for interface IP address"):
        multicast_expert.find_interfaces(["1234::5678"])


def test_find_iface_deduplication():
    """
    Test that passing multiple IPs of the same interface only returns that interface once
    """
    assert multicast_expert.find_interfaces(["192.168.1.11", "192.168.1.10"], ifaces=TEST_IFACES) == [
        TEST_IFACES[1],
        TEST_IFACES[0],
    ]
