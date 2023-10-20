###########################
Multicast Expert for Python
###########################

Multicasting is one of the cooler features of Internet Protocol (IP).  It allows a single source to send out IP packets (usually UDP) which are then received by multiple other devices on the network.  No configuration in advance is needed -- the sender just sends packets, and other devices may subscribe to these packets at their leisure.  Using a protocol called IGMP, computers and network switches communicate to ensure that the multicasts are only sent where they are needed, and not anywhere else.  It's great for applications such as audio/video transmission or distributed systems where you need to send out data to many different machines on a network.

Ideally, multicasting is as simple as sending a packet to a specific multicast address, and then having certain other machines receive it.  It looks a bit like this:

.. image:: https://app.box.com/shared/static/ftsh3tq2gvrzibhqwr26n1nvwqazcmlu.png
    :alt: Diagram of a multicast packet being sent on a network

Of course, in practice, things are a bit more complicated -- chiefly because using multicast requires setting additional socket options whose values and formats often differ by OS.  To that end, this library was created, so that you can use multicast networking without having to mess around with low level OS stuff.  Multicast Expert includes all the required pieces to create and use IPv4 and IPv6 multicast sockets on Windows, Mac, and Linux.

*******************
Multicasting Basics
*******************

Before I can explain how to use this library, I first need to explain the basics of multicasting itself.  There's not a lot of info out there on the net about how to do multicasting right, and much of what there is is buried deep in OS documentation.  So let's go over some of the basic concepts first.

First and foremost, there is one principle that I need to make clear, or you will not have a good time trying to use multicast.  **Sending multicasts happens at the network interface level, not the machine level**.  Almost every machine has at least two network interfaces: the loopback interface to itself and the Ethernet/WiFi connection it uses to access the the Internet.  Many machines also have additional interfaces such as bridges to Docker containers/virtual machines, VPNs, or additional private LANs.  With normal (unicast) networking, you simply tell the OS what IP address you want to send a packet to, and it will select the appropriate interface automatically (using a structure called the routing table).  This is not so with multicast!  Every multicast socket needs to be bound to a specific network interface that it will use.  At the OS level, there is no such thing as "bind to 0.0.0.0" or "listen on all interface"!

However, multicast_expert does allow an "multi-interface" mode which combines together multiple OS sockets to allow listening for incoming multicasts on several or all network interfaces.  This allows "bind to 0.0.0.0"-like behavior for Rx sockets only!

Now that we've gotten that out of the way, we can cover the four essential topics for multicast: multicast addresses, understanding network routing, creating a transmitter, and creating a receiver.

Multicast Addresses
===================
A multicast IPv4 address is defined as any IPv4 address whose most significant four bits are "1110".  This means any IP address whose first number is in the range of 224 through 239 (0xE0-0xEF) is a multicast address.  Similarly, for IPv6, any address whose first byte is 0xFF is a multicast address.

When a network interface (e.g. your Ethernet card) sees a packet going to a multicast IP address, it processes it differently.  The exact specifics are outside of the scope of this document and depend on the specific medium, but often it will mark that packet as multicast at the link layer too, e.g. by giving it a special destination MAC address.  This ensures that the packet is delivered correctly by the link layer.

If you are simply trying to receive existing multicast packets, all you need to know is the group address that the multicasts are being sent on.  But if you're trying to build your own application that communicates via multicast, you'll need to select an IPv4 or IPv6 multicast address to use for it.  Many of these addresses have to be officially assigned by IANA (the `wikipedia page on multicast addresses <https://en.wikipedia.org/wiki/Multicast_address#IPv4>`_ has the full details), though IP addresses in the 239.x.x.x range are "administratively scoped" and available for private use on LANs.

Multicast Routing in Networks
=============================
Compared to regular IP packets, multicast packets are handled differently by networking devices such as Ethernet switches and routers.  It's all too easy to forget to take this into account, and then find yourself asking "wait, why am I not receiving any multicast traffic", or even "wait, why am I receiving *all of the multicasts* that I didn't ask for?"  This section will go over some basics of how multicast packets move through Ethernet networks.  Other networks may differ in the specifics, but the basic concepts should be similar.

For a simple ("unmanaged") Ethernet switch, its handling of multicast packets is very simple.  It simply treats them like broadcasts, and forwards them to every other port of the switch.

As you might imagine, if you have a large network full of multicast users, and switches are broadcasting every message everywhere, you could get some pretty awful network congestion.  To combat this, more complex ("managed") Ethernet switches often have a feature called "IGMP snooping".  When a switch has this setting enabled, it listens for what's called an "IGMP join message" to be sent by a host.  This message is automatically sent by your OS whenever you open a multicast receive socket, and indicates that host X wants to receive traffic going to multicast address Y.  When the switch sees one of these messages, it automatically begins routing traffic going to multicast address Y into host X's network link.  No IGMP join message?  No multicasts for you.

Note: for IPv6, MLD messages are used instead of IGMP, but they do pretty much the same thing.

Last but not least, routers.  In contrast to Ethernet switches, which connect individual hosts together, routers connect entire networks together.  They have quite a bit more logic and generally require at least some manual configuration of what packets are routed where.  Often, multicasts are just used within the local network and are dropped by routers (you can guarantee this by setting the Time To Live to 1, forcing them to be dropped by any router).  However, the specifics depend on the router configuration, and often individual multicast addresses are treated differently.  If you really do need to pass multicasts through a router, you should contact your ISP or your network admin to verify the router settings.

In conclusion, here's a table of how different boxes handle multicasts:

========================================= ============================================
Box                                       What does it do with multicast packets?
========================================= ============================================
Ethernet Switch (No IGMP Snooping)        Forwards to all hosts
Ethernet Switch (IGMP Snooping Enabled)   Forwards to any hosts that have subscribed
Router                                    Depends on configuration.
========================================= ============================================

**NOTE:** Be careful of boxes with unexpected behavior!  Multicast is one of the more rarely used features of IP and often does not seem to be well tested.  In my time working with multicast, I've seen a number of devices that do not implement the standard as I've written it here.  For instance, some switches can individually have IGMP snooping enabled/disabled on each port, producing unexpected behavior.  I think the worst was a desktop switch which seemed to work fine initially but started dropping most multicast traffic when IGMP snooping was enabled!

Since lots of devices come with weird multicast settings out of the box, prepare to have to check and fix the configuration on each switch/device when you start using multicast on your network.

Sending Multicasts
===================

To send multicasts, an application can pretty much just create a normal UDP socket and have it send packets to a multicast IP address.  However, there is one additional piece needed, which is that the OS needs to be told which interface to send the multicasts on.  This is always done using the IP_MULTICAST_IF setsockopt() option, but the exact syntax and procedure for using this option differs by OS.  Luckily, Multicast Expert takes care of that for you!

Receiving Multicasts
====================

To receive multicasts, essentially two things need to happen.  First, your OS needs to be told to send out an IGMP join message, telling other devices on the network to send multicast packets your way.  This generally happens as a side effect of enabling the IP_ADD_MEMBERSHIP socket option (or one of its variants) on a socket.  Then, the OS network stack needs to be configured to forward multicast packets which arrive on the given interface to your application.  This process is pretty different on Windows and Unix.

On Windows, multicast sockets are bound to a given port and interface (using bind()) when they are initially created.  Then, IP_ADD_MEMBERSHIP commands are used to further associate them with individual multicast addresses, so that when a packet is received to that multicast addr, it goes to the correct socket.  This is convenient as it means one socket can use multiple multicast groups and still not receive unwanted traffic from other groups that use the same port.  However, there's no way to block unicast traffic going to that interface and port from also being received by the multicast socket.

But on Unix, the situation is a bit different.  The IP_ADD_MEMBERSHIP command does not directly set up filtering by multicast address, it pretty much just sends the IGMP join message and opens the interface to receive packets going to the multicast address.  It does not directly associate the socket with the multicast address, it's still a "regular" UDP socket.  So, if you were to take a multicast socket and bind it to 0.0.0.0, it would end up receiving all UDP traffic on the port number, even traffic to other multicast addresses or to the unicast address.  The only way to fix this is to bind the socket to the specific multicast address instead, causing any traffic with a different destination address to not be accepted by the socket.  Unfortunately, a socket can only be bound to one destination address at a time, so this means multicast expert needs to create a different socket under the hood for each multicast address you want to listen on.

**********************
Using Multicast Expert
**********************

Now let's get into some actual code examples.  Now first, before we can create any sockets, we need to find the interface address we want to use (see above).  Luckily, Multicast Expert comes with a convenient function to list all available network interfaces:

>>> import multicast_expert
>>> multicast_expert.get_interface_ips(include_ipv4=True, include_ipv6=False)
['192.168.0.248', '192.168.153.1', '127.0.0.1']

(note that this function is a wrapper around the netifaces library, which provides quite a bit more functionality if you need it)

But which of those is the interface we actually want to use?  Well, that depends on your specific nework setup, but to make an educated guess, we also have a function to get the interface your machine uses to contact the internet.  This is not always correct but will work for many network setups.

>>> multicast_expert.get_default_gateway_iface_ip_v4()
'192.168.0.248'

Transmitting Multicasts
=======================

To send some data to a multicast, use the McastTxSocket class.  This wraps a socket internally, and does all the hard work of configuring it correctly for multicast.  For now we will use '239.1.2.3' as our multicast address since it's in the administratively scoped block.

The following block shows how to create a Tx socket and send some data:

>>> import socket
>>> with multicast_expert.McastTxSocket(socket.AF_INET, mcast_ips=['239.1.2.3'], iface_ip='192.168.0.248') as mcast_tx_sock:
...     mcast_tx_sock.sendto(b'Hello World', ('239.1.2.3', 12345))

Note: when you construct the socket, you have to pass in all of the multicast IPs that you will want to use the socket to send to.  These must be known in advance in order to configure socket options correctly.

Note 2: If you omitted the iface_ip= argument, the get_default_gateway_iface_ip_v4() function would have been called to guess the iface ip.  So, we could have omitted this argument for the same result.

Receiving Multicasts
====================

To receive from one or more multicast addresses, use the McastRxSocket class.  For example:

>>> with multicast_expert.McastRxSocket(socket.AF_INET, mcast_ips=['239.1.2.3'], port=12345, iface_ip='192.168.0.248') as mcast_rx_sock:
...     bytes, src_address = mcast_rx_sock.recvfrom()

The above code will listen on the 239.1.2.3 multicast address, and will block until a packet is received.  To change the blocking behavior, use the settimeout() function.

Full Example
============
For a complete example of how to use this library, see the system test script `here <https://github.com/multiplemonomials/multicast_expert/blob/main/examples/mcast_communicator.py>`_.

FAQ
===
Q: What happens if an interface changes IP address (e.g. due to the user modifying a static IP) after I create a multicast socket on that interface?
    A: On all machines tested so far, multicast sockets will stick with their assigned interface once created, even if the IP of that interface changes or it is brought down.

Q: Do McastRxSockets receive regular (unicast) UDP packets going to the same interface and port?
    A: On Windows, yes.  On Unix, no.  Unfortunately, this is a platform difference that I haven't found an easy way to work around.

Q: Can I create multiple McastRxSockets on the same port and interface?
    A: As long as they have different mcast addresses, then yes, this works how you'd expect.

Q: Is it possible to receive multicasts on all interfaces with a single socket?
    A: Yes!  As of multicast_expert 1.2.0, the default behavior of McastRxSocket, when you do not pass any interface IP addresses explicitly, is to listen on all non-loopback interfaces of the machine.

Q: Why are my multicasts to the loopback device not going through in Linux?
    A: Linux seems to be very picky about what it allows through loopback.  First of all, you need to use ``ip route`` to add a route directing your multicast address to the ``lo`` interface.  For example, the command ``sudo ip route add 239.2.2.0/24 dev lo`` would allow any multicasts in the 239.2.2.x range through loopback.

    Additionally, for IPv6, I have found that multicasts to addresses that don't start with ``ffx1`` for any value of x (i.e. non-interface-local addresses) do not seem to be sent on loopback.  Still trying to find any document explaining this behavior...

Q: My multicasts aren't being received in Linux, even though I see them coming in in packet dumps.
    A: On Linux, you must also be careful of a kernel feature called Reverse Path Filtering (RPF).  You see, in most cases, multicast doesn't care about unicast IPs or subnets -- you can quite easily have a machine with IP 10.0.0.1 send multicasts to 192.168.1.2, even though those are on different subnets so they can't normally communicate.  However, RPF throws a wrench in this.  In its default "loose" mode (setting 2), it blocks reception of IP packets if they come from an IP address not reachable by any interface.  So, for example, if you receive a multicast from 10.0.0.1 but you only have routes in your routing table for 192.168.x.x IP addresses, the kernel will summarily drop the packet.  The easiest fix is to label one of your network interfaces as a default route.  This makes all IP addresses reachable from an interface, so all packets will be able to get by the check.

    RPF's "strict" mode (setting 1) is even worse.  It applies the same check, but on a per-interface level.  So, in order to receive packets from multicast address X, each individual interface must have a routing rule permitting it to send packets to X.  If this is too much of a pain to set up, you can turn RPF off using sysctl (`this seems like a decent guide <https://access.redhat.com/solutions/53031#:~:text=rp_filter%20parameter%20only%20has%20two,default%20is%201%20(loose).>`_).  Just remember to change it both for the "all" interface and for whichever interfaces you want to affect -- the kernel takes the stricter of the two values.

    If RPF isn't the problem, you may also want to check any firewalls (firewalld/iptables) and see if those are blocking multicast packets.

Q: If I have a socket that receives from multiple mcast addresses, say A and B, and I receive a packet, how do I tell whether the packet was sent to multicast address A or B?
    A: You can't, or at least I haven't found a way to do this from Python.  You'll need to create multiple sockets if you need this information.

Q: What if, rather than using a Multicast Expert socket inside a single ``with`` block, I want to create it, store it, and then close it later in a separate function?
    A: This is a not-uncommon problem for Python users, and a lot of people will try to work around it by calling ``__enter__`` and ``__exit__`` directly.  However, this is not a very good way as it is likely to leave the sockets un-cleaned-up if an exception occurs.  The best solution I know of is to use `contextlib.ExitStack`, which allows you to "transfer" ownership of the socket into a standalone object which can be closed manually later.  Here's an example:

.. code-block:: python

    import multicast_expert
    import contextlib

    class McastUser():

        def init():
            self.mcast_socket = multicast_expert.McastTxSocket(...)
            with contextlib.ExitStack as temp_exit_stack: # Creates a temporary ExitStack
                temp_exit_stack.enter_context(self.mcast_socket) # Enter the mcast socket using the temporary stack
                self.exit_stack = temp_exit_stack.pop_all() # Creates a new exit stack with ownership of mcast_socket "moved" into it
        
        def deinit():
            if self.exit_stack is not None:
                self.exit_stack.close() # This exits each object saved in the stack
            self.exit_stack = None

With this setup, the socket will be opened when you call ``init()``, and will stay open until someone calls ``deinit()``.  Note however that this transfers the responsibility for closing the socket onto you: if you forget to call ``deinit()`` before you're done using the class, the socket could stay open longer than intended.

Q: When I try to send a packet to the loopback address on Windows, I get "[WinError 10051] A socket operation was attempted to an unreachable network"!
    A: On Windows, to send multicasts through the loopback interface, you must open a listening socket before trying to send packets, or an error will be generated. So, make sure there's an application listing to the loopback interface on the correct port before you send your multicast packet.

Changelog
=========

v1.3.0 - Oct 20, 2023
*********************
* Replace ``blocking`` arg to McastRxSocket with ``timeout``, which allows you to set an integer timeout in the constructor. The old argument is still supported but is marked as legacy.
* Fix the type annotation for McastRxSocket.settimeout() parameter.


v1.2.2 - Jun 30, 2023
*********************
* Fix some mypy errors that were visible for users of the library.

v1.2.1 - Jun 29, 2023
*********************
* Fix IPv6 McastRxSocket being broken on Linux when multiple interfaces were used (need to open an OS socket for each interface ip-mcast ip permutation)

v1.2.0 - Jun 29, 2023
*********************
* An McastRxSocket can now listen on multiple interface IPs at once via passing a list of interface addresses to the new ``iface_ips`` parameter.  The old ``iface_ip`` parameter is retained for compatibility.
* If no interface IPs are specified, McastRxSocket now listens on all non-loopback interfaces instead of just the default gateway.  This should provide more intuitive default behavior for applications where the interface for receiving isn't known.
* Type annotations now applied to everything, library passes mypy in strict mode.
* py.typed file now provided so that mypy can see type annotations provided by multicast_expert in your own projects.

v1.1.2 - May 16, 2023
*********************
* Another hotfix for a typo in v1.1.0

v1.1.1 - May 16, 2023
*********************
* Hotfix for a missing import in v1.1.0.  Forgot to run unit tests one last time before uploading to pypi 🤦‍♂️

v1.1.0 - May 15, 2023
*********************
* Add mac compatibility (now that I finally have someone to help test who possesses a mac).  Previously only Windows and Linux were properly supported.

v1.0.1 - Aug 13, 2022
*********************
* Documentation updates

v1.0.0 - Aug 13, 2022
*********************
* Initial release!
