"""Rule 2: keys stay out of the box.

Code in the box gets a short allowlist of environment variables, never the
harness's whole environment, and never a name that looks like a secret, even
when someone lists it by mistake.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Mapping

PASSTHROUGH = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ")
SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "COOKIE", "SESSION")


def looks_secret(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in SECRET_MARKERS)


def scrubbed(extra: Iterable[str] = (), source: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for code in the box: a few harmless names, never one that looks like a secret."""
    source = os.environ if source is None else source
    env: dict[str, str] = {}
    for name in (*PASSTHROUGH, *extra):
        if not looks_secret(name) and name in source:
            env[name] = source[name]
    env.setdefault("PATH", "/usr/bin:/bin")
    return env
