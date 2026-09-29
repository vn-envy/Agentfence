"""The harness's own calls: named hosts only, and each key only where it belongs.

The box has no network at all. When a tool truly needs the internet, the
harness makes the call, and first asks ``check_url``:

  - the scheme is http or https, and the URL carries no user or password;
  - the host is in [net] allow (a leading dot also allows subdomains);
  - the name does not lead to a cloud metadata or link-local address, or to a
    private or loopback one unless the rules name that address or localhost.

``key_for`` hands out a key only for a URL on a host [keys] lists for it, over
https (plain http only to localhost), the way OpenShell's supervisor adds
credentials only to requests bound for approved endpoints.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit

from .errors import EgressDenied, KeyDenied
from .policy import host_allowed

# Cloud metadata services: never, whatever the rules say.
_METADATA = (ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("fe80::/10"),
             ipaddress.ip_network("fd00:ec2::254/128"), ipaddress.ip_network("100.100.100.200/32"))

Resolver = Callable[[str], list[str]]


def _resolve(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_url(url: str, allow: tuple[str, ...] | list[str], *, resolve: Resolver = _resolve) -> str:
    """The URL's host if the harness may call it; otherwise EgressDenied."""
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise EgressDenied(f"Only http and https URLs are called, not '{parts.scheme or url}'.")
    if parts.username or parts.password:
        raise EgressDenied("A URL with a user name or password in it is not called.")
    host = (parts.hostname or "").lower()
    if not host:
        raise EgressDenied(f"{url} has no host.")
    if not host_allowed(host, allow):
        raise EgressDenied(f"{host} is not in [net] allow.")
    names_itself = host == "localhost" or _is_ip(host)
    try:
        addresses = [host] if _is_ip(host) else resolve(host)
    except OSError as exc:
        raise EgressDenied(f"{host} does not resolve: {exc}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if any(ip in net for net in _METADATA):
            raise EgressDenied(f"{host} leads to {ip}, a link-local or cloud metadata address.")
        if (ip.is_private or ip.is_loopback) and not names_itself:
            raise EgressDenied(f"{host} leads to the private address {ip}; list that address itself to allow it.")
    return host


def key_for(name: str, url: str, keys: Mapping[str, tuple[str, ...]], allow: tuple[str, ...] | list[str], *,
            environ: Mapping[str, str] | None = None, resolve: Resolver = _resolve) -> str:
    """The value of key `name`, only for a URL on a host the rules send that key to."""
    hosts = keys.get(name)
    if hosts is None:
        raise KeyDenied(f"{name} is not in [keys], so it goes nowhere.")
    host = check_url(url, allow, resolve=resolve)
    if not host_allowed(host, hosts):
        raise KeyDenied(f"{name} goes only to {', '.join(hosts)}, not {host}.")
    loopback = host == "localhost" or (_is_ip(host) and ipaddress.ip_address(host).is_loopback)
    if urlsplit(url).scheme != "https" and not loopback:
        raise KeyDenied(f"{name} is sent only over https.")
    value = (os.environ if environ is None else environ).get(name)
    if not value:
        raise KeyDenied(f"{name} is not set in the harness's environment.")
    return value
