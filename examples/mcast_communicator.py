#!/usr/bin/env python3
"""
Multicast communication example with multicast_expert.
This program sends and receives multicasts on a local network to test the functionality of the library.

You may run up to 3 instances of the script on different machines.  When run, it performs the following actions:

- Sends a packet to mcast address 0 once every second
- Sends a packet to mcast address [machine number] once every second
- Listens to mcast address 0 and prints packets
- Listens to mcast address [machine number + 1] % 3 and prints packets

When the script runs, you should see packets from mcast addresses 0 and ([machine number + 1] % 3), but not
any other addresses.
"""
import multicast_expert

MULTICAST_ADDRESSES = {
    'IPv4': [
        '239.2.2.0',
        '239.2.2.1',
        '239.2.2.2',
        '239.2.2.3'
    ],
    'IPv6': [
        '239.2.2.0',
        '239.2.2.1',
        '239.2.2.2',
        '239.2.2.3'
    ],
}