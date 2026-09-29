"""Rule 3: prove the box before you trust it.

Before the first run, a small script runs inside the box and tries what a
leaking box would allow:

  write_own_folder      write a file in the box's folder        must be allowed
  read_secret           read a file only the harness can see    must be denied
  read_through_symlink  read that file through a symlink        must be denied
  hard_link_secret      hard-link that file into the box        must be denied
  list_home             list the real home folder               must be denied
  network               connect to a listener on 127.0.0.1      must be denied
  write_outside         write next to the box's folder          must be denied
  must_not_read:<path>  read each path the rules name           must be denied

The check runs through the same plumbing as a real run. If any line comes out
wrong, or the script cannot start, the box is not proven and nothing runs.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .box import NO_BACKEND_HELP

if TYPE_CHECKING:
    from .box import Box

PROBE_SCRIPT = r'''
import errno, json, os, socket, sys
# Not readable, not there, not reachable: all mean the box held.
DENIED = {errno.EPERM, errno.EACCES, errno.ENOENT, errno.ENOTDIR, errno.ECONNREFUSED,
          errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EXDEV, errno.EROFS}
secret, home, port, outside = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
out = {}

def attempt(name, action):
    try:
        value = action()
        out[name] = "allowed" if value is None else "allowed " + json.dumps(value)
    except OSError as exc:
        out[name] = "denied" if exc.errno in DENIED else "unclear: %s (errno %s)" % (type(exc).__name__, exc.errno)
    except Exception as exc:
        out[name] = "unclear: " + type(exc).__name__

def read(path):
    if os.path.isdir(path):
        os.listdir(path)
    else:
        with open(path, "rb") as handle:
            handle.read(1)

def write_own():
    with open("probe-own.txt", "w") as handle:
        handle.write("ok")

def through_symlink():
    os.symlink(secret, "probe-symlink")
    read("probe-symlink")

def connect():
    socket.create_connection(("127.0.0.1", port), timeout=2).close()

def write_outside():
    with open(outside, "w") as handle:
        handle.write("x")

attempt("write_own_folder", write_own)
attempt("read_secret", lambda: read(secret))
attempt("read_through_symlink", through_symlink)
attempt("hard_link_secret", lambda: os.link(secret, "probe-hardlink"))
attempt("list_home", lambda: sorted(os.listdir(home)))
attempt("network", connect)
attempt("write_outside", write_outside)
for path in sys.argv[5:]:
    attempt("must_not_read:" + path, lambda path=path: read(path))
print(json.dumps(out))
'''

MUST_BE_DENIED = ("read_secret", "read_through_symlink", "hard_link_secret", "list_home", "network",
                  "write_outside")


@dataclass
class Proof:
    ok: bool                 # True: code may run (proven, or the owner chose backend="none")
    confined: bool           # True: it runs inside a box the check proved
    backend: str
    reason: str
    checks: dict[str, str] = field(default_factory=dict)


def _skeleton(box: Box, home: Path) -> set[str]:
    """Names a box shows in the home folder only because its own folders are mounted below it."""
    from .box import interpreter_roots

    names = set()
    for root in [*box.write_roots, *box.read_roots, *map(Path, interpreter_roots())]:
        try:
            names.add(Path(root).relative_to(home).parts[0])
        except (ValueError, IndexError):
            pass
    return names


def run_probe(box: Box) -> Proof:
    backend = box.backend
    if backend == "unavailable":
        return Proof(False, False, "none", "No sandbox on this system. " + NO_BACKEND_HELP)
    if backend == "none":
        return Proof(True, False, "none", "Running without a box: the owner chose backend='none'.")

    box.workdir.mkdir(parents=True, exist_ok=True)
    home = Path(os.path.realpath(Path.home()))
    secret_dir = Path(tempfile.mkdtemp(prefix="agentfence-probe-"))
    secret = secret_dir / "secret.txt"
    secret.write_text("agentfence probe secret")
    secret.chmod(0o600)
    outside = box.workdir.parent / f".agentfence-probe-{uuid.uuid4().hex[:8]}"
    script = box.workdir / f".agentfence-probe-{uuid.uuid4().hex[:8]}.py"
    targets = [str(p) for p in box.must_not_read if p.exists()]
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        script.write_text(PROBE_SCRIPT, encoding="utf-8")
        command = [sys.executable, str(script), str(secret), str(home), str(listener.getsockname()[1]),
                   str(outside), *targets]
        result = None
        try:
            result = box._spawn(box.wrap(command), timeout_s=60)
            checks = json.loads(result.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError, OSError) as exc:
            said = (result.stderr or result.stdout) if result else f"{type(exc).__name__}: {exc}"
            return Proof(False, False, backend, f"The box could not start: {said.strip()[:400] or 'no output'}")
        # The harness's own view: a write outside counts only if it landed on this machine.
        checks["write_outside"] = "allowed" if outside.exists() else "denied"
        # A box may show empty mount points for its own folders; only real names are a leak.
        listing = checks.get("list_home", "")
        if listing.startswith("allowed "):
            seen = set(json.loads(listing[len("allowed "):]))
            real = set(os.listdir(home)) - _skeleton(box, home)
            if not real:
                checks["list_home"] = "skipped (the home folder holds nothing but the box's own folders)"
            elif not (seen & real):
                checks["list_home"] = "denied"
            else:
                checks["list_home"] = "allowed"
        for path in box.must_not_read:
            if not path.exists():
                checks[f"must_not_read:{path}"] = "skipped (not on this machine)"
    finally:
        listener.close()
        shutil.rmtree(secret_dir, ignore_errors=True)
        if outside.exists() or outside.is_symlink():
            outside.unlink()
        script.unlink(missing_ok=True)
        for name in ("probe-own.txt", "probe-symlink", "probe-hardlink"):
            path = box.workdir / name
            if path.exists() or path.is_symlink():
                path.unlink()

    writable = checks.get("write_own_folder") == "allowed"
    required = [*MUST_BE_DENIED, *(name for name in checks if name.startswith("must_not_read:"))]
    leaks = [name for name in required
             if not (checks.get(name, "missing") == "denied" or checks.get(name, "").startswith("skipped"))]
    if not writable:
        reason = f"Code in the box cannot write its own folder ({checks.get('write_own_folder')})."
    elif leaks:
        reason = "The box did not hold: " + ", ".join(f"{name} {checks.get(name, 'missing')}" for name in leaks) + "."
    else:
        reason = (f"{backend}: no home folder, no secrets, no network; writes only "
                  + ", ".join(str(p) for p in box.write_roots) + ".")
    ok = writable and not leaks
    return Proof(ok, ok, backend, reason, checks)
