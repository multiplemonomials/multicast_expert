#!/usr/bin/env python3

"""
Multicast communication example with multicast_expert.

This program sends and receives multicasts on a local network to test the functionality of the library.

You may run up to 3 instances of the script on different machines.  When run, it performs the following actions:

- Sends a packet to mcast address 0 once every second
- Sends a packet to mcast address [machine number] once every second
- Listens to mcast address 0 and prints packets
- Listens to mcast address of the next highest machine and prints packets

When the script runs, you should see packets from mcast addresses 0 and ([machine number % 3] + 1), but not
any other addresses.
"""

from __future__ import annotations

import socket
import sys
import threading
import time

import multicast_expert

MULTICAST_ADDRESSES: dict[int, list[str]] = {
    socket.AF_INET: ["239.2.2.0", "239.2.2.1", "239.2.2.2", "239.2.2.3"],
    socket.AF_INET6: ["ffa5::2220", "ffa5::2221", "ffa5::2222", "ffa5::2223"],
}

# Note: We make all multicast groups use the same port in order to ensure that address filtering
# is working properly.
PORT = 34348


def listener_thread(machine_index: int, addr_family: int, iface_ip: str) -> None:
    mcast_ips_to_listen = [
        MULTICAST_ADDRESSES[addr_family][0],
        MULTICAST_ADDRESSES[addr_family][(machine_index % 3) + 1],
    ]
    with multicast_expert.McastRxSocket(
        addr_family, mcast_ips=mcast_ips_to_listen, port=PORT, blocking=True, iface_ips=[iface_ip]
    ) as rx_socket:
        while True:
            recv_result = rx_socket.recvfrom()
            if recv_result is not None:
                packet, sender_addr = recv_result

                print(f"Rx from {sender_addr[0]}:{sender_addr[1]}: {packet.decode('UTF-8')}")


# Read and check arguments
if len(sys.argv) not in (3, 4):
    print(f"Error: Usage: {sys.argv[0]} <IPv4 | IPv6> <1|2|3> [Interface to bind to]")
    sys.exit(1)

if sys.argv[1] == "IPv4":
    addr_family = socket.AF_INET
elif sys.argv[1] == "IPv6":
    addr_family = socket.AF_INET6
else:
    print("Invalid IP version!")
    sys.exit(1)

machine_number = int(sys.argv[2])
if machine_number < 1 or machine_number > 3:
    print("Invalid machine number!")
    sys.exit(1)

if len(sys.argv) > 3:
    iface = sys.argv[3]
else:
    iface = multicast_expert.get_default_gateway_iface_ip(addr_family)
    if iface is None:
        print("Unable to determine default gateway.  Please specify interface in arguments.")
        sys.exit(1)

# Start listener thread
listener_thread_obj = threading.Thread(
    target=listener_thread, name="Multicast Listener Thread", args=(machine_number, addr_family, iface), daemon=True
)
listener_thread_obj.start()

# Start transmitting
print(f"Communicator starting on interface {iface}.  Press Ctrl-C to exit")
with multicast_expert.McastTxSocket(
    addr_family=addr_family,
    mcast_ips=[MULTICAST_ADDRESSES[addr_family][0], MULTICAST_ADDRESSES[addr_family][machine_number]],
    iface=iface,
) as tx_socket:
    while True:
        time.sleep(1.0)

        tx_socket.sendto(
            f"Hello from machine {machine_number} via group 0".encode(),
            (MULTICAST_ADDRESSES[addr_family][0], PORT),
        )
        tx_socket.sendto(
            f"Hello from machine {machine_number} via group {machine_number}".encode(),
            (MULTICAST_ADDRESSES[addr_family][machine_number], PORT),
        )
