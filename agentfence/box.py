"""Rule 1: run what the model writes in a box with no network and one writable folder.

Backends:
  seatbelt    macOS. ``sandbox-exec`` with a deny-by-default profile.
  bubblewrap  Linux. ``bwrap`` with every namespace unshared (so no network)
              and only system folders, the interpreter and the box's own
              folders mounted.
  none        No box. Only when you choose it: ``backend="none"``.

The profile is an allowlist. Reads: system files, the Python interpreter and
its packages, and the box's folders. Writes: the box's folders. Network:
none, not even 127.0.0.1, which many local tools trust.

A box also protects the harness from what the code leaves behind. Output is
read through pipes the harness opened, never by a name the code could swap
for a link. When a run ends, its process group is killed and any symbolic
or hard link left in a writable folder is removed before anything serves it.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .env import scrubbed
from .errors import FenceNotProven

if TYPE_CHECKING:
    from .audit import AuditLog
    from .probe import Proof

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
BACKENDS = ("auto", "seatbelt", "bubblewrap", "none")

# What a Python process and the tools it starts read on macOS. User data lives
# under /Users, /Volumes and /private/var/folders, none of which are here.
SEATBELT_SYSTEM_READS = (
    "/System", "/usr", "/bin", "/sbin", "/Library", "/opt",
    "/private/etc", "/private/var/db/timezone", "/private/var/db/dyld", "/dev",
    "/private/var/select", "/private/var/db/xcode_select_link",
)
SEATBELT_MACH_SERVICES = (
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.system.logger",
    "com.apple.logd",
    "com.apple.system.notification_center",
)

# What a Python process reads from /etc on Linux. Not the whole folder: as
# root, the box could otherwise read /etc/shadow.
BWRAP_ETC = (
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime", "/etc/timezone",
    "/etc/alternatives", "/etc/fonts", "/etc/ssl", "/etc/ca-certificates", "/etc/passwd", "/etc/group",
    "/etc/nsswitch.conf", "/etc/hosts", "/etc/mime.types",
)
BWRAP_SYSTEM = ("/usr",)
BWRAP_MAYBE_LINKS = ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")


def _real(path: str | Path) -> str:
    return os.path.realpath(os.path.expanduser(str(path)))


def detect_backend() -> str:
    """The box this system can offer, or "unavailable"."""
    if sys.platform == "darwin" and os.access(SANDBOX_EXEC, os.X_OK):
        return "seatbelt"
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        return "bubblewrap"
    return "unavailable"


def interpreter_roots() -> list[str]:
    """Where the interpreter and its packages live (a venv or pyenv may sit under the home folder)."""
    roots = {sys.prefix, sys.base_prefix, sys.exec_prefix, str(Path(_real(sys.executable)).parent.parent)}
    paths = sysconfig.get_paths()
    for name in ("stdlib", "platstdlib", "purelib", "platlib"):
        if paths.get(name):
            roots.add(paths[name])
    # Only package folders from PYTHONPATH, never a source tree.
    for entry in os.environ.get("PYTHONPATH", "").split(os.pathsep):
        if entry and ("site-packages" in entry or "dist-packages" in entry):
            roots.add(entry)
    return sorted({_real(root) for root in roots if root})


# ── Seatbelt (macOS) ──────────────────────────────────────────────────────────

def _sbpl(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def seatbelt_profile(read_roots: Iterable[str], write_roots: Iterable[str]) -> str:
    """A deny-by-default Seatbelt profile: exactly these reads and writes, no network."""
    reads = " ".join(f"(subpath {_sbpl(_real(p))})" for p in [*SEATBELT_SYSTEM_READS, *read_roots])
    writes = " ".join(f"(subpath {_sbpl(_real(p))})" for p in write_roots)
    mach = " ".join(f"(global-name {_sbpl(name)})" for name in SEATBELT_MACH_SERVICES)
    return "\n".join([
        "(version 1)",
        "(deny default)",
        ";; The interpreter and the tools it starts; each inherits this profile.",
        "(allow process-fork)",
        "(allow process-exec)",
        "(allow signal (target same-sandbox))",
        "(allow process-info* (target same-sandbox))",
        "(allow sysctl-read)",
        ";; Names and sizes along a path, never contents or listings.",
        "(allow file-read-metadata)",
        ";; The root folder itself (only its top-level names): the loader reads it as every process starts.",
        '(allow file-read* (literal "/"))',
        ";; System and interpreter files may be read and loaded as code (dyld maps libraries).",
        f"(allow file-read* file-map-executable {reads})",
        f"(allow file-read* file-write* {writes})",
        '(allow file-write-data (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper"))',
        '(allow file-ioctl (literal "/dev/dtracehelper"))',
        f"(allow mach-lookup {mach})",
        "(allow ipc-posix-sem)",
        "(allow ipc-posix-shm)",
        ";; No network rule: every socket is denied, 127.0.0.1 included.",
    ]) + "\n"


# ── bubblewrap (Linux) ────────────────────────────────────────────────────────

def bwrap_argv(command: Sequence[str], read_roots: Iterable[str], write_roots: Iterable[str],
               cwd: str | Path) -> list[str]:
    """A bwrap command line: new namespaces (no network), system files read-only, the box's folders."""
    argv = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"]
    for path in BWRAP_SYSTEM:
        if os.path.isdir(path):
            argv += ["--ro-bind", path, path]
    for path in BWRAP_MAYBE_LINKS:
        if os.path.islink(path):
            argv += ["--symlink", os.readlink(path), path]
        elif os.path.isdir(path):
            argv += ["--ro-bind", path, path]
    for path in BWRAP_ETC:
        if os.path.lexists(path):
            argv += ["--ro-bind", path, path]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in read_roots:
        real = _real(path)
        if os.path.exists(real):
            argv += ["--ro-bind", real, real]
    for path in write_roots:
        real = _real(path)
        argv += ["--bind", real, real]
    argv += ["--chdir", _real(cwd), "--", *command]
    return argv


# ── Links the code leaves behind ──────────────────────────────────────────────

def drop_links(folder: str | Path) -> list[str]:
    """Remove symbolic and hard links under `folder`; return what was removed.

    The box stops the code reading through a link, but the harness reads these
    folders unboxed. A symlink to a secret, or a hard link to one, would let it
    hand the secret over."""
    removed: list[str] = []
    folder = Path(folder)
    if not folder.is_dir():
        return removed
    for root, dirs, files in os.walk(folder):
        for name in [*dirs, *files]:
            path = Path(root, name)
            try:
                if path.is_symlink() or (not path.is_dir() and path.lstat().st_nlink > 1):
                    path.unlink()
                    removed.append(str(path.relative_to(folder)))
            except OSError:
                pass
    return removed


def _kill_group(pgid: int) -> None:
    if hasattr(os, "killpg"):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


class _Drain(threading.Thread):
    """Read a pipe to the end, keeping the first `cap` bytes and dropping the rest.

    A pipe, not a file: Seatbelt can refuse writes to a spool file outside the
    box even through a descriptor the harness handed in. A pipe has no path at
    all, so the code can neither write to it by name nor swap it for a link."""

    def __init__(self, pipe, cap: int) -> None:
        super().__init__(daemon=True)
        self.pipe, self.cap, self.data = pipe, cap, bytearray()

    def run(self) -> None:
        try:
            while chunk := self.pipe.read(65536):
                if len(self.data) < self.cap:
                    self.data += chunk[: self.cap - len(self.data)]
        except (OSError, ValueError):
            pass

    def text(self) -> str:
        self.join(timeout=2)
        try:
            self.pipe.close()
        except OSError:
            pass
        return bytes(self.data).decode("utf-8", errors="replace")


# ── The box ───────────────────────────────────────────────────────────────────

@dataclass
class RunResult:
    returncode: int | None          # None when the run timed out
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float
    backend: str                    # seatbelt | bubblewrap | none
    removed_links: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Box:
    """A folder that model-written code can write, and nothing else it can reach.

    >>> box = Box("./agent-work")
    >>> box.run_python("open('hello.txt', 'w').write('hi')").ok
    True
    """

    def __init__(self, workdir: str | Path, *, also_write: Iterable[str | Path] = (),
                 also_read: Iterable[str | Path] = (), must_not_read: Iterable[str | Path] = (),
                 backend: str = "auto", env_passthrough: Iterable[str] = (), timeout_s: float = 60.0,
                 output_cap: int = 64_000, audit: AuditLog | None = None) -> None:
        if backend not in BACKENDS:
            raise ValueError(f"backend must be one of {', '.join(BACKENDS)}")
        self.workdir = Path(_real(workdir))
        self.write_roots = [self.workdir, *(Path(_real(p)) for p in also_write)]
        self.read_roots = [Path(_real(p)) for p in also_read]
        self.must_not_read = [Path(os.path.abspath(os.path.expanduser(str(p)))) for p in must_not_read]
        self.requested_backend = backend
        self.env_passthrough = tuple(env_passthrough)
        self.timeout_s = timeout_s
        self.output_cap = output_cap
        self.audit = audit
        self._proof: Proof | None = None
        self._lock = threading.Lock()

    @property
    def backend(self) -> str:
        return detect_backend() if self.requested_backend == "auto" else self.requested_backend

    def environment(self) -> dict[str, str]:
        """Home, temp and caches point inside the box, so libraries never reach for the real home."""
        cache = self.workdir / ".cache"
        for folder in (self.workdir / ".tmp", cache):
            folder.mkdir(parents=True, exist_ok=True)
        return {**scrubbed(self.env_passthrough), "HOME": str(self.workdir), "TMPDIR": str(self.workdir / ".tmp"),
                "XDG_CACHE_HOME": str(cache), "XDG_CONFIG_HOME": str(cache),
                "MPLCONFIGDIR": str(cache / "matplotlib"), "MPLBACKEND": "Agg"}

    def wrap(self, command: Sequence[str]) -> list[str]:
        """`command` as it runs in this box."""
        backend = self.backend
        reads = [*interpreter_roots(), *map(str, self.read_roots)]
        writes = [str(p) for p in self.write_roots]
        if backend == "seatbelt":
            return [SANDBOX_EXEC, "-p", seatbelt_profile(reads, writes), *command]
        if backend == "bubblewrap":
            return bwrap_argv(command, reads, writes, self.workdir)
        if backend == "none":
            return list(command)
        raise FenceNotProven("No sandbox on this system. " + NO_BACKEND_HELP)

    def prove(self, refresh: bool = False) -> Proof:
        """Run the startup check once (or again with refresh=True). See probe.py."""
        from .probe import run_probe

        with self._lock:
            if self._proof is None or refresh:
                self._proof = run_probe(self)
                if self.audit:
                    self.audit.record("probe", backend=self._proof.backend, ok=self._proof.ok,
                                      confined=self._proof.confined, checks=self._proof.checks)
            return self._proof

    def run(self, command: Sequence[str], *, timeout_s: float | None = None) -> RunResult:
        """Run `command` in the box. Refuses unless the startup check proved the box holds."""
        proof = self.prove()
        if not proof.ok:
            raise FenceNotProven(proof.reason)
        result = self._spawn(self.wrap(command), timeout_s=timeout_s or self.timeout_s)
        if self.audit:
            self.audit.record("run", program=Path(command[0]).name, backend=result.backend,
                              returncode=result.returncode, timed_out=result.timed_out,
                              duration_s=result.duration_s, removed_links=result.removed_links)
        return result

    def run_python(self, code: str, *, timeout_s: float | None = None) -> RunResult:
        """Run Python source in the box, with the box's folder as the working directory."""
        self.workdir.mkdir(parents=True, exist_ok=True)
        script = self.workdir / f".agentfence-{uuid.uuid4().hex[:8]}.py"
        script.write_text(code, encoding="utf-8")
        try:
            return self.run([sys.executable, str(script)], timeout_s=timeout_s)
        finally:
            script.unlink(missing_ok=True)

    def _spawn(self, argv: list[str], *, timeout_s: float) -> RunResult:
        self.workdir.mkdir(parents=True, exist_ok=True)
        env = self.environment()
        started = time.monotonic()
        proc: subprocess.Popen | None = None
        timed_out = False
        returncode: int | None = None
        drains: list[_Drain] = []
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    cwd=str(self.workdir), env=env, start_new_session=True)
            drains = [_Drain(proc.stdout, self.output_cap), _Drain(proc.stderr, self.output_cap)]
            for drain in drains:
                drain.start()
            try:
                returncode = proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            if proc is not None:
                # Nothing the code started outlives the run (it would also hold the pipes open).
                _kill_group(proc.pid)
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
            removed = [link for root in self.write_roots for link in drop_links(root)]
        stdout, stderr = (drain.text() for drain in drains) if drains else ("", "")
        return RunResult(returncode=None if timed_out else returncode, stdout=stdout, stderr=stderr,
                         timed_out=timed_out, duration_s=round(time.monotonic() - started, 3),
                         backend=self.backend, removed_links=removed)


NO_BACKEND_HELP = ("On Linux, install bubblewrap (apt install bubblewrap, dnf install bubblewrap). "
                   "On macOS, sandbox-exec ships with the system. To run without a box anyway, "
                   "pass backend='none' (or --backend none).")
