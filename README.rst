###########################
Multicast Expert for Python
###########################

.. warning::
    Under construction as of 7-30-2022


Multicasting is one of the cooler features of Internet Protocol (IP).  It allows a single source to send out IP packets (usually UDP) which are then received by multiple other devices on the network.  No configuration in advance is needed -- the sender just sends packets, and other devices may subscribe to these packets at their leisure.  Using a protocol called IGMP, computers and network switches communicate to ensure that the multicasts are only sent where they are needed, and not anywhere else.  It's great for applications such as audio/video transmission or distributed systems where you need to send out data to many different machines on a network.

Of course, in practice, things are a bit more complicated -- chiefly because using multicast requires setting additional socket options whose values and formats often differ by OS.  To that end, this library was created, so that you can multicast networking without having to mess around with low level OS stuff.

*******************
Multicasting Basics
*******************

Before I can explain how to use this library, I first need to explain the basics of multicasting itself.  There's not a lot of info out there on the net about how to do multicasting right, and much of what there is is buried deep in OS documentation.  So let's go over some of the basic concepts first.

First and foremost, there is one principle that I need to make clear, or you will not have a good time trying to use multicast.  **Multicasting happens at the network interface level, not the machine level**.  Almost every machine has at least two network interfaces: the loopback interface to itself and the Ethernet/WiFi connection it uses to access the the Internet.  Many machines also have additional interfaces such as bridges to Docker containers/virtual machines, VPNs, or additional private LANs.  With normal (unicast) networking, you simply tell the OS what IP address you want to send a packet to, and it will select the appropriate interface automatically (using a structure called the routing table).  This is not so with multicast!  Every multicast socket needs to be bound to one specific network interface that it will use.  There is no such thing as "bind to 0.0.0.0" or "listen on all addresses"!

Now that we've gotten that out of the way, we can cover the four essential topics for multicast: multicast addresses, understanding network routing, creating a transmitter, and creating a receiver.

Multicast Addresses
===================
A multicast IPv4 address is defined as any IPv4 address whose most significant four bits are "1110".  In decimal, this means any IP address whose first number is in the range of 224 through 239 (0xE0-0xEF) is a multicast address.  Similarly, for IPv6, any address whose first byte is 0xFF is a multicast address.

When a network interface (e.g. your Ethernet card) sees a packet going to a multicast IP address, it processes it differently.  The exact specifics are outside of the scope of this document and depend on the specific medium, but often it will mark that packet as multicast at the link layer too, e.g. by giving it a special destination MAC address.  This ensures that the packet is delivered correctly by the link layer.

If you are simply trying to receive existing multicast packets, all you need to do is open a multicast_expert socket with the multicast address of the protocol you're using.  But if you're trying to build your own application that communicates via multicast, you'll need to select an IPv4 or IPv6 multicast address to use for it.  Many of these addresses have to be officially assigned by IANA (the `wikipedia page on multicast addresses <https://en.wikipedia.org/wiki/Multicast_address#IPv4>`_ has the full details), though it's worth knowing that IP addresses in the 239.x.x.x range are "administratively scoped" and available for private use on LANs.

Multicast Routing in Networks
=============================
Compared to regular IP packets, multicast packets are handled differently by networking devices such as Ethernet switches and routers.  It's all too easy to forget to take this into account, and then find yourself asking "wait, why am I not receiving any multicast traffic", or even "wait, why am I receiving *all of the multicasts* that I didn't ask for?"  This section will go over some basics of how multicast packets move through Ethernet networks.  Other networks may differ in the specifics, but the basic concepts should be similar.

For a simple ("unmanaged") Ethernet switch, its handling of multicast packets is very simple.  It simply treats them like broadcasts, and passes them along to every port of the switch.

As you might imagine, if you have a large network full of multicast users, and switches are broadcasting every message everywhere, you could get some pretty awful network congestion.  To combat this, more complex ("managed") Ethernet switches often have a feature called "IGMP snooping".  When a switch has this setting enabled, it listens for what's called an "IGMP join message" to be sent by a host.  This message is automatically sent by your OS whenever you open a multicast receive socket, and indicates that host X wants to receive traffic going to multicast address Y.  When the switch sees one of these messages, it automatically begins routing traffic to that multicast address over the corresponding network link.  No IGMP join message?  No multicasts for you.

Last but not least, routers.  In contrast to Ethernet switches, which connect individual hosts together, routers connect entire networks together.  They have quite a bit more logic and generally require at least some manual configuration of what packets are routed where.  Generally, most multicasts are used within one network and as such multicast packets are usually not passed by routers (you can guarantee this by setting the Time To Live to 1, forcing them to be dropped by all routers).  However, the specifics depend on the router configuration, and often individual multicast addresses are treated differently.  If you really do need to pass multicasts through a router, you should contact your ISP or your network admin to verify the router settings.

In conclusion, here's a table of how different boxes handle multicasts:

========================================= ============================================
Box                                       What does it do with them?
========================================= ============================================
Ethernet Switch (No IGMP Snooping)        Forwards to all hosts
Ethernet Switch (IGMP Snooping Enabled)   Forwards to any hosts that have subscribed
Router                                    Depends on configuration, often drops.
========================================= ============================================

.. warning::
    Be careful of boxes with unexpected behavior!  Multicast is one of the more rarely used features of IP and often does not seem to be well tested.  In my time working with multicast, I've seen a number of devices that do not implement the standard as I've written it here.  For instance, some switches can individually have IGMP snooping enabled/disabled on each port, which can produce unexpected behavior.  But I think the worst was a desktop switch which worked fine initially but started dropping most multicast traffic when IGMP snooping was enabled!

    Since lots of devices come with weird multicast settings out of the box, prepare to have to check and fix the configuration on each switch/device when you start using multicast on your network.

Sending Multicasts
===================

Receiving Multicasts
====================

**********************
Using Multicast Expert
**********************

Now let's get into some actual code examples.  Now first, before we can create any sockets, we need to find the interface address we want to use (see above).  Luckily, Multicast Expert comes with a convenient function to list all available network interfaces:

>>> import multicast_expert
>>> multicast_expert.get_interface_ips(include_ipv4=True, include_ipv6=False)
['192.168.0.248', '192.168.153.1', '127.0.0.1']

(note that this functionality is a wrapper around the netifaces library, which provides quite a bit more functionality if you need it)

But which of those is the interface we actually want to use?  Well, that depends on your specific nework setup, but to make an educated guess, we also have a function to get the interface your machine uses to contact the internet.  This is not always correct but will work for many network setups.

>>> multicast_expert.get_default_gateway_iface_ip_v4()
'192.168.0.248'

Transmitting Multicasts
=======================

To send some data to a multicast, use the McastTxSocket class.  This wraps a socket internally, and does all the hard work of configuring it correctly for multicast.  For now we will use '239.1.2.3' as our multicast address since it's in the administratively scoped block.

The following block shows how to create a socket which sends multicasts.

>>> import socket
>>> with multicast_expert.McastTxSocket(socket.AF_INET, mcast_ips=['239.1.2.3'], iface_ip='192.168.0.248') as mcast_sock:
...     mcast_sock.sendto(b'Hello World', ('239.1.2.3', 12345))

Note: when you construct the socket, you have to pass in all of the multicast IPs that you will want to use the socket to send to.  These must be known in advance in order to configure socket options correctly.

Note 2: If you omitted the iface_ip= argument, the get_default_gateway_iface_ip_v4() function would have been called to guess the iface ip.