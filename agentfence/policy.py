"""Rule 5: keep the rules in one file the agent can't edit, and review every change.

The rules live in a small TOML file (``agentfence.toml``). Loading it refuses
rules that would undo themselves: the file inside the box's writable folders,
a path the startup check must prove unreadable that the box is allowed to
read, or a key sent to a host the harness may not call.

``widening(old, new)`` answers the one question to ask of every change: does
it add a host, a folder or a write verb? It is the home-sized version of
OpenShell's policy prover: plain set differences, no solver.
"""
from __future__ import annotations

import hashlib
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import PolicyError

DEFAULT_VERBS = ("send", "pay", "delete", "remove", "post", "publish", "submit", "buy", "purchase", "book",
                 "transfer")

STARTER = '''\
# agentfence.toml: the rules your agent runs under.
# Keep this file out of the agent's reach, and review every change with
#   agentfence diff OLD NEW

[box]
# The one folder code in the box may write. It gets no network, no keys and
# no view of your home folder.
workdir = "./agent-work"
also_write = []
also_read = []
# Paths the startup check proves the box cannot read (missing ones are skipped).
must_not_read = ["~/.ssh", "./.env"]
timeout_seconds = 60

[net]
# Hosts the harness itself may call. A leading dot also allows subdomains.
allow = ["api.anthropic.com"]

[keys]
# Each key goes only to the hosts listed here, and never into the box.
ANTHROPIC_API_KEY = ["api.anthropic.com"]

[approve]
# Actions whose name contains one of these words wait for your yes.
verbs = ["send", "pay", "delete", "remove", "post", "publish", "submit", "buy", "purchase", "book", "transfer"]
ttl_minutes = 15
'''

_SECTIONS = {
    "box": {"workdir", "also_write", "also_read", "must_not_read", "timeout_seconds"},
    "net": {"allow"},
    "keys": None,
    "approve": {"verbs", "ttl_minutes"},
}
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HOST = re.compile(r"^\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$|^\[?[0-9a-f:.]+\]?$")


@dataclass(frozen=True)
class Policy:
    workdir: Path
    also_write: tuple[Path, ...] = ()
    also_read: tuple[Path, ...] = ()
    must_not_read: tuple[Path, ...] = ()
    timeout_s: float = 60.0
    net_allow: tuple[str, ...] = ()
    keys: dict[str, tuple[str, ...]] = field(default_factory=dict)
    verbs: tuple[str, ...] = DEFAULT_VERBS
    ttl_s: int = 900
    path: Path | None = None
    fingerprint: str = ""

    @property
    def write_roots(self) -> tuple[Path, ...]:
        return (self.workdir, *self.also_write)

    @property
    def base(self) -> Path:
        return self.path.parent if self.path else Path.cwd()

    @classmethod
    def default(cls, workdir: str | Path = "./agent-work") -> Policy:
        """Rules for trying agentfence without a file: one folder, no hosts, no keys."""
        return cls(workdir=_resolve(workdir, Path.cwd()),
                   must_not_read=tuple(_resolve(p, Path.cwd()) for p in ("~/.ssh", "./.env")))

    @classmethod
    def load(cls, path: str | Path = "agentfence.toml", *, base: str | Path | None = None,
             validate: bool = True) -> Policy:
        """Read the rules. Relative paths resolve against `base` (default: the file's folder)."""
        path = Path(path).expanduser().resolve()
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PolicyError(f"Cannot read {path}: {exc.strerror}. Create one with `agentfence init`.") from exc
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise PolicyError(f"{path} is not valid TOML: {exc}") from exc
        policy = cls._from_dict(data, Path(base).resolve() if base else path.parent, path,
                                hashlib.sha256(raw).hexdigest())
        if validate:
            policy.validate()
        return policy

    @classmethod
    def _from_dict(cls, data: dict, base: Path, path: Path | None, fingerprint: str) -> Policy:
        for section, value in data.items():
            if section not in _SECTIONS:
                raise PolicyError(f"Unknown section [{section}]. Known: {', '.join(_SECTIONS)}.")
            if not isinstance(value, dict):
                raise PolicyError(f"[{section}] must be a table.")
            allowed = _SECTIONS[section]
            unknown = set(value) - allowed if allowed is not None else set()
            if unknown:
                raise PolicyError(f"Unknown key in [{section}]: {', '.join(sorted(unknown))}.")
        box, net, keys, approve = (data.get(name, {}) for name in ("box", "net", "keys", "approve"))
        if "workdir" not in box:
            raise PolicyError("[box] needs a workdir: the one folder the box may write.")
        key_hosts: dict[str, tuple[str, ...]] = {}
        for name, hosts in keys.items():
            if not _ENV_NAME.match(name):
                raise PolicyError(f"[keys] {name} is not an environment variable name.")
            key_hosts[name] = tuple(_host(h, f"[keys] {name}") for h in _strings(hosts, f"[keys] {name}"))
        timeout = box.get("timeout_seconds", 60)
        ttl = approve.get("ttl_minutes", 15)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise PolicyError("[box] timeout_seconds must be a positive number.")
        if not isinstance(ttl, (int, float)) or ttl <= 0:
            raise PolicyError("[approve] ttl_minutes must be a positive number.")
        return cls(
            workdir=_resolve(_string(box["workdir"], "[box] workdir"), base),
            also_write=tuple(_resolve(p, base) for p in _strings(box.get("also_write", []), "[box] also_write")),
            also_read=tuple(_resolve(p, base) for p in _strings(box.get("also_read", []), "[box] also_read")),
            must_not_read=tuple(_resolve(p, base)
                                for p in _strings(box.get("must_not_read", []), "[box] must_not_read")),
            timeout_s=float(timeout),
            net_allow=tuple(_host(h, "[net] allow") for h in _strings(net.get("allow", []), "[net] allow")),
            keys=key_hosts,
            verbs=tuple(v.lower() for v in _strings(approve.get("verbs", list(DEFAULT_VERBS)), "[approve] verbs")),
            ttl_s=int(ttl * 60),
            path=path,
            fingerprint=fingerprint,
        )

    def validate(self) -> None:
        """Refuse rules that would undo themselves."""
        for root in self.write_roots:
            if self.path and _inside(self.path, root):
                raise PolicyError(f"The rules file {self.path} is inside {root}, which the box may write: "
                                  "it could rewrite its own rules. Move one of them.")
        for secret in self.must_not_read:
            for root in (*self.write_roots, *self.also_read):
                if _inside(secret, root):
                    raise PolicyError(f"{secret} is in must_not_read, but the box may read {root}, which holds it.")
        for name, hosts in self.keys.items():
            for host in hosts:
                if not host_allowed(host.lstrip("."), self.net_allow):
                    raise PolicyError(f"[keys] {name} goes to {host}, which [net] allow does not list.")

    def current_fingerprint(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest() if self.path else ""


# ── Is this change wider? ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class Finding:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


def widening(old: Policy, new: Policy) -> list[Finding]:
    """What `new` lets the agent reach or do that `old` did not. Empty: the change is not wider."""
    found: list[Finding] = []
    for path in sorted(set(new.write_roots) - set(old.write_roots)):
        found.append(Finding("write_added", f"the box may now write {path}"))
    for path in sorted(set(new.also_read) - set(old.also_read)):
        found.append(Finding("read_added", f"the box may now read {path}"))
    for path in sorted(set(old.must_not_read) - set(new.must_not_read)):
        found.append(Finding("check_removed", f"the startup check no longer proves {path} unreadable"))
    keyed = {host for hosts in new.keys.values() for host in hosts}
    for host in sorted(set(new.net_allow) - set(old.net_allow)):
        if host in keyed:
            found.append(Finding("credentialed_host_added", f"the harness may now call {host} and send it a key"))
        else:
            found.append(Finding("host_added", f"the harness may now call {host}"))
    for name in sorted(new.keys):
        added = set(new.keys[name]) - set(old.keys.get(name, ()))
        if name not in old.keys:
            found.append(Finding("key_added", f"{name} may now be sent to {', '.join(sorted(added))}"))
        elif added:
            found.append(Finding("key_reach_expanded", f"{name} may now also go to {', '.join(sorted(added))}"))
    for verb in sorted(set(old.verbs) - set(new.verbs)):
        found.append(Finding("approval_removed", f"actions named '{verb}' no longer wait for your yes"))
    if new.ttl_s > old.ttl_s:
        found.append(Finding("approval_window_longer",
                             f"an approval now stays valid {new.ttl_s // 60} minutes, not {old.ttl_s // 60}"))
    return found


# ── Helpers ───────────────────────────────────────────────────────────────────

def host_allowed(host: str, allow: tuple[str, ...] | list[str]) -> bool:
    """`host` is listed, or sits under a listed ".domain"."""
    host = host.lower().strip("[]")
    for entry in allow:
        entry = entry.lower().strip("[]")
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def _resolve(value: str | Path, base: Path) -> Path:
    path = Path(os.path.expanduser(str(value)))
    return Path(os.path.realpath(path if path.is_absolute() else base / path))


def _inside(path: Path, root: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
        return True
    except ValueError:
        return False


def _string(value, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{where} must be a non-empty string.")
    return value


def _strings(value, where: str) -> list[str]:
    if not isinstance(value, list):
        raise PolicyError(f"{where} must be a list of strings.")
    return [_string(item, where) for item in value]


def _host(value: str, where: str) -> str:
    host = value.strip().lower()
    if not _HOST.match(host):
        raise PolicyError(f"{where}: '{value}' is not a host name (no scheme, port or path).")
    return host
