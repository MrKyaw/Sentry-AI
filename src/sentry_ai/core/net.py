"""Network address helpers."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from functools import lru_cache

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_INTERNAL_NETWORKS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
)


@lru_cache(maxsize=16)
def _networks(cidrs: tuple[str, ...]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)


@lru_cache(maxsize=65536)
def parse_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_ip(value: str) -> bool:
    return parse_ip(value) is not None


@lru_cache(maxsize=262144)
def _is_internal(value: str, networks: tuple[str, ...]) -> bool:
    ip = parse_ip(value)
    if ip is None:
        return False
    return any(ip in net for net in _networks(networks))


def is_internal(value: str, networks: Iterable[str] = DEFAULT_INTERNAL_NETWORKS) -> bool:
    """True if ``value`` is an IP inside one of the configured internal networks."""
    return _is_internal(value, networks if isinstance(networks, tuple) else tuple(networks))


def is_protected(dst: str, networks: Iterable[str] = DEFAULT_INTERNAL_NETWORKS) -> bool:
    """True if ``dst`` is a service you defend: an internal IP, or a non-IP server name.

    Access-log events name the server they were logged on rather than its
    address, and a server's own log is only collected for servers you run.
    """
    return parse_ip(dst) is None or is_internal(dst, networks)


def entity_type(value: str, networks: Iterable[str] = DEFAULT_INTERNAL_NETWORKS) -> str:
    """Classify an entity as ``internal_ip``, ``external_ip``, or ``user``."""
    if parse_ip(value) is None:
        return "user"
    return "internal_ip" if is_internal(value, networks) else "external_ip"


def peer_group(value: str, prefix: int = 24) -> str:
    """Peer group key: the IPv4 /``prefix`` network, or ``default`` otherwise."""
    ip = parse_ip(value)
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    return "default"
