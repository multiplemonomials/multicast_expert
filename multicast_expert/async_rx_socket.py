from __future__ import annotations

import asyncio
import socket
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Self

from multicast_expert.rx_socket import DEFAULT_RX_BUFSIZE, BaseMcastRxSocket, PacketAndSenderAddress


class AsyncMcastRxSocket(BaseMcastRxSocket):
    """
    Class to wrap a socket that receives from one or more multicast groups using asynchronous operations.
    """

    @staticmethod
    async def _recvfrom_wrapper(sock: socket.socket) -> tuple[socket.socket, PacketAndSenderAddress]:
        """
        Wrapper around the EventLoop.sock_recvfrom() function.

        This is used to associate the packet data with the socket that received it. This seems to be needed
        as I wasn't able to find a way to attach "metadata" to a future in a way that passes through ``asyncio.wait()``.
        """
        packet_and_addr: PacketAndSenderAddress = await asyncio.get_running_loop().sock_recvfrom(
            sock, DEFAULT_RX_BUFSIZE
        )
        return sock, packet_and_addr

    def __enter__(self) -> Self:
        super().__enter__()

        # For asyncio socket functions, we need to set the timeout on the actual sockets to 0 (nonblocking).
        # Then we pass self.timeout to asyncio.wait() later.
        for sock in self.sockets:
            sock.settimeout(0)

        # Start a receive operation on each of the sockets.
        # We do this now so that we can have a known future for each socket that is active at all times.
        self._recvfrom_tasks: dict[socket.socket, asyncio.Task[tuple[socket.socket, PacketAndSenderAddress]]] = {
            sock: asyncio.create_task(self._recvfrom_wrapper(sock)) for sock in self.sockets
        }

        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        # Cancel all tasks
        for recvfrom_task in self._recvfrom_tasks.values():
            recvfrom_task.cancel()

        super().__exit__(exc_type, exc, traceback)

    async def recvfrom(self) -> PacketAndSenderAddress:
        """
        Asynchronously receive a UDP packet from the socket.

        Note that multicast_expert uses multiple sockets under the hood in some cases, and if multiple sockets
        are in use, this will dequeue and return a packet from one of those sockets (which socket is not defined).

        This respects the current blocking and timeout settings.

        :return: List of tuples of (bytes, address).  For IPv4, address is a tuple of sender IP address (str) and
            port number.
            For IPv6, address is a tuple of IP address (str), port number, flow info (int), and scope ID (int).
        :raises asyncio.TimeoutError: If no packets were received within the timeout. If the timeout is 0, this is
            raised if there were no packets available to be returned immediately.
        """
        # Do a "select" from all the current recvfrom futures to find one that is done.
        done, pending = await asyncio.wait(
            self._recvfrom_tasks.values(), timeout=self.timeout, return_when=asyncio.FIRST_COMPLETED
        )

        if len(done) == 0:
            # No sockets can be read
            raise asyncio.TimeoutError

        # Pick some arbitrary one from the done list and get its result. Others in the done list will be gotten on
        # the next call to this function.
        sock, result_packet = await next(iter(done))

        # Reschedule another receive for this socket
        self._recvfrom_tasks[sock] = asyncio.create_task(self._recvfrom_wrapper(sock))

        return result_packet

    async def recv(self) -> bytes:
        """
        Asynchronously receive a UDP packet from the socket, returning the bytes.

        Note that multicast_expert uses multiple sockets under the hood in some cases, and if multiple sockets
        are in use, this will dequeue and return a packet from one of those sockets (which socket is not defined).

        This respects the current blocking and timeout settings.

        :return: Bytes received.
        :raises asyncio.TimeoutError: If no packets were received within the timeout. If the timeout is 0, this is
            raised if there were no packets available to be returned immediately.
        """
        packet_and_addr = await self.recvfrom()
        return packet_and_addr[0]
