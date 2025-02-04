from typing import Final, Literal

AF_INET: Final[int]
AF_INET6: Final[int]
AF_LINK: Final[int]
AF_PACKET: Final[int]
AF_UNSPEC: Final[int]

address_families: Final[dict[int, str]]
version: Final[str]

def gateways() -> dict[
    int | Literal["default"], list[tuple[str, str, bool] | tuple[str, str]] | dict[int, tuple[str, str]]
]: ...
def ifaddresses(ifname: str, /) -> dict[int, list[dict[str, str]]]: ...
def interfaces() -> list[str]: ...
