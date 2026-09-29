"""Rules 1 to 3: the box, the keys kept out of it, and the startup check."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from agentfence import Box, FenceNotProven
from agentfence.box import bwrap_argv, interpreter_roots, seatbelt_profile
from agentfence.env import scrubbed

# ── The profiles, on any platform ─────────────────────────────────────────────


def test_the_seatbelt_profile_is_an_allowlist_without_network(tmp_path):
    work = tmp_path / "work"
    profile = seatbelt_profile(interpreter_roots(), [str(work)])
    assert profile.startswith("(version 1)\n(deny default)\n")
    assert "network" not in profile.replace(";; No network rule", "")
    assert "(allow default)" not in profile
    assert '(allow file-read* (literal "/"))' in profile      # the root folder alone, never (subpath "/")
    assert '(subpath "/")' not in profile
    write_rule = next(line for line in profile.splitlines() if "file-write*" in line)
    assert write_rule == f'(allow file-read* file-write* (subpath "{os.path.realpath(work)}"))'
    read_rule = next(line for line in profile.splitlines() if line.startswith("(allow file-read* file-map-executable"))
    assert f'(subpath "{os.path.realpath(Path.home())}")' not in read_rule
    assert '(subpath "/System")' in read_rule
    # Code may be loaded from system and interpreter folders, never from the box's own folder.
    assert f'(subpath "{os.path.realpath(work)}")' not in read_rule


def test_seatbelt_paths_are_quoted():
    assert '(subpath "/tmp/a \\"b\\"\\\\c")' in seatbelt_profile([], ['/tmp/a "b"\\c'])


def test_bubblewrap_unshares_everything_and_mounts_no_home(tmp_path):
    argv = bwrap_argv(["python3", "x.py"], interpreter_roots(), [str(tmp_path)], tmp_path)
    assert argv[:2] == ["bwrap", "--unshare-all"]
    assert "--share-net" not in argv
    assert argv[-3:] == ["--", "python3", "x.py"]
    mounted = {argv[i + 1] for i, arg in enumerate(argv) if arg in ("--bind", "--ro-bind")}
    assert os.path.realpath(Path.home()) not in mounted
    assert "/etc" not in mounted and "/etc/shadow" not in mounted
    assert argv[argv.index("--bind") + 1] == os.path.realpath(tmp_path)


def test_pythonpath_adds_package_folders_only(tmp_path):
    with patch.dict(os.environ, {"PYTHONPATH": os.pathsep.join([str(tmp_path), "/opt/x/site-packages"])}):
        roots = interpreter_roots()
    assert os.path.realpath("/opt/x/site-packages") in roots
    assert str(tmp_path) not in roots


def test_secret_looking_names_never_pass():
    env = scrubbed(["MY_API_KEY", "GITHUB_TOKEN", "EDITOR"], {"PATH": "/bin", "MY_API_KEY": "k",
                                                              "GITHUB_TOKEN": "t", "EDITOR": "vi", "HOME": "/h"})
    assert env == {"PATH": "/bin", "EDITOR": "vi"}


# ── The startup check ─────────────────────────────────────────────────────────


def test_the_check_catches_an_unboxed_run(tmp_path, secret):
    """With the box taken away, every leak must show up."""
    box = Box(tmp_path / "work", must_not_read=[secret], backend="bubblewrap")
    with patch.object(Box, "wrap", lambda self, command: list(command)):
        proof = box.prove()
    assert not proof.ok and not proof.confined
    for name in ("read_secret", "read_through_symlink", "hard_link_secret", "network", "write_outside",
                 f"must_not_read:{secret}"):
        assert proof.checks[name] == "allowed", (name, proof.checks)
    assert proof.checks["list_home"] == "allowed" or proof.checks["list_home"].startswith("skipped")
    assert "did not hold" in proof.reason
    leftovers = [p.name for p in (tmp_path / "work").iterdir() if not p.name.startswith(".")]
    assert leftovers == []
    assert not list(tmp_path.glob(".agentfence-probe-*"))


def test_a_box_that_cannot_start_is_not_proven(tmp_path):
    box = Box(tmp_path / "work", backend="bubblewrap")
    with patch.object(Box, "wrap", lambda self, command: [sys.executable, "-c", "import sys; sys.exit(3)"]):
        proof = box.prove()
    assert not proof.ok
    assert "could not start" in proof.reason
    with pytest.raises(FenceNotProven):
        box.run(["true"])


def test_no_sandbox_refuses_unless_you_choose_none(tmp_path):
    with patch("agentfence.box.detect_backend", return_value="unavailable"):
        box = Box(tmp_path / "work")
        assert not box.prove().ok
        with pytest.raises(FenceNotProven, match="bubblewrap"):
            box.run(["true"])
    none = Box(tmp_path / "work", backend="none")
    proof = none.prove()
    assert proof.ok and not proof.confined


# ── What the harness does around every run (backend none: plumbing only) ────


def test_output_is_read_by_handle_not_by_a_name_in_the_box(tmp_path):
    box = Box(tmp_path / "work", backend="none")
    code = "import json, os, sys\nprint(json.dumps(os.listdir('.')))\nprint('to stderr', file=sys.stderr)"
    result = box.run_python(code)
    assert result.ok, result.stderr
    names = json.loads(result.stdout)
    assert not [n for n in names if "stdout" in n or "stderr" in n or n.startswith("tmp")], names
    assert result.stderr.strip() == "to stderr"


def test_a_flood_of_output_is_capped_and_does_not_hang(tmp_path):
    box = Box(tmp_path / "work", backend="none", output_cap=1000)
    result = box.run_python("import sys\nsys.stdout.write('x' * 5_000_000)\nsys.stderr.write('y' * 5_000_000)")
    assert result.ok
    assert result.stdout == "x" * 1000 and result.stderr == "y" * 1000


def test_links_left_behind_are_removed(tmp_path, secret):
    box = Box(tmp_path / "work", backend="none")
    code = (f"import os\nos.symlink({str(secret)!r}, 'leak.html')\nos.link({str(secret)!r}, 'hard.png')\n"
            f"os.makedirs('sub')\nos.symlink({str(secret)!r}, 'sub/deep.txt')\nopen('page.html', 'w').write('mine')\n")
    result = box.run_python(code)
    assert result.ok, result.stderr
    assert sorted(result.removed_links) == ["hard.png", "leak.html", os.path.join("sub", "deep.txt")]
    work = tmp_path / "work"
    assert (work / "page.html").read_text() == "mine"
    assert not os.path.lexists(work / "leak.html") and not os.path.lexists(work / "sub" / "deep.txt")
    assert secret.read_text() == "family data"


def test_a_timeout_stops_the_whole_process_group(tmp_path):
    box = Box(tmp_path / "work", backend="none")
    marker = tmp_path / "work" / "late.txt"
    code = ("import os, time\n"
            "if os.fork() == 0:\n    time.sleep(2)\n    open('late.txt', 'w').write('x')\n    os._exit(0)\n"
            "time.sleep(30)\n")
    started = time.monotonic()
    result = box.run_python(code, timeout_s=1)
    assert result.timed_out and result.returncode is None
    assert time.monotonic() - started < 10
    time.sleep(2.5)
    assert not marker.exists()


def test_nothing_outlives_a_normal_run(tmp_path):
    box = Box(tmp_path / "work", backend="none")
    code = ("import os, time\n"
            "if os.fork() == 0:\n    time.sleep(1.5)\n    open('late.txt', 'w').write('x')\n    os._exit(0)\n")
    assert box.run_python(code).ok
    time.sleep(2.5)
    assert not (tmp_path / "work" / "late.txt").exists()


def test_home_and_temp_point_inside_the_box(tmp_path):
    box = Box(tmp_path / "work", backend="none")
    result = box.run_python("import os; print(os.environ['HOME']); print(os.environ['TMPDIR'])")
    home, tmp = result.stdout.split()
    assert home == os.path.realpath(tmp_path / "work")
    assert tmp == os.path.join(home, ".tmp")


# ── The real box on this machine ──────────────────────────────────────────────


def test_the_real_box_holds(real_box):
    proof = real_box.prove()
    assert proof.confined
    assert all(v in ("denied", "allowed") or v.startswith("skipped") for v in proof.checks.values())


def test_code_in_the_real_box_reaches_nothing(real_box, secret, tmp_path):
    code = (
        "import os, socket\n"
        "def tryit(name, fn):\n"
        "    try:\n        fn(); print(name, 'OPEN')\n"
        "    except OSError:\n        print(name, 'blocked')\n"
        f"tryit('secret', lambda: open({str(secret)!r}).read())\n"
        f"tryit('home', lambda: os.listdir({str(Path.home())!r}))\n"
        "tryit('net', lambda: socket.create_connection(('1.1.1.1', 443), timeout=2))\n"
        "open('made-here.txt', 'w').write('ok')\n"
    )
    result = real_box.run_python(code)
    assert result.ok, result.stderr
    lines = dict(line.split() for line in result.stdout.splitlines())
    assert lines == {"secret": "blocked", "home": "blocked", "net": "blocked"}, result.stdout
    assert (tmp_path / "work" / "made-here.txt").read_text() == "ok"


def test_keys_never_enter_the_real_box(real_box):
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test", "SESSION_COOKIE": "c"}):
        result = real_box.run_python("import os; print(sorted(os.environ))")
    assert "ANTHROPIC_API_KEY" not in result.stdout and "SESSION_COOKIE" not in result.stdout
