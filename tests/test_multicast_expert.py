import multicast_expert


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