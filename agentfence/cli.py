"""agentfence on the command line.

  agentfence init                 write a starter agentfence.toml
  agentfence check                prove the box on this machine (exit 1 if it does not hold)
  agentfence run -- CMD ...       run a command in the box
  agentfence diff OLD NEW         what a rules change widens (exit 1 if anything)
  agentfence verify-log PATH      check the audit log's chain
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from . import __version__
from .audit import AuditLog
from .box import BACKENDS, Box
from .errors import AgentfenceError
from .policy import STARTER, Policy, widening


def _policy(path: str | None) -> Policy:
    if path:
        return Policy.load(path)
    if Path("agentfence.toml").exists():
        return Policy.load("agentfence.toml")
    return Policy.default(Path(tempfile.mkdtemp(prefix="agentfence-check-")) / "work")


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite).", file=sys.stderr)
        return 1
    path.write_text(STARTER, encoding="utf-8")
    print(f"Wrote {path}. Next: agentfence check")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    policy = _policy(args.policy)
    box = Box(policy.workdir, also_write=policy.also_write, also_read=policy.also_read,
              must_not_read=policy.must_not_read, backend=args.backend)
    proof = box.prove()
    print(f"agentfence check · backend {proof.backend}")
    width = max((len(name) for name in proof.checks), default=0)
    for name, result in proof.checks.items():
        expected = "allowed" if name == "write_own_folder" else "denied"
        good = result == expected or result.startswith("skipped")
        print(f"  {'ok  ' if good else 'LEAK'}  {name.ljust(width)}  {result}")
    print(proof.reason)
    return 0 if proof.ok and proof.confined else 1


def cmd_run(args: argparse.Namespace) -> int:
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        print("Nothing to run: agentfence run -- CMD ...", file=sys.stderr)
        return 2
    policy = _policy(args.policy)
    box = Box(policy.workdir, also_write=policy.also_write, also_read=policy.also_read,
              must_not_read=policy.must_not_read, backend=args.backend, timeout_s=args.timeout or policy.timeout_s)
    result = box.run(command)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    for link in result.removed_links:
        print(f"agentfence: removed a link the code left behind: {link}", file=sys.stderr)
    if result.timed_out:
        print(f"agentfence: stopped after {box.timeout_s:g}s", file=sys.stderr)
        return 124
    return result.returncode if result.returncode is not None else 1


def cmd_diff(args: argparse.Namespace) -> int:
    base = args.base or str(Path(args.new).resolve().parent)
    old = Policy.load(args.old, base=base, validate=False)
    new = Policy.load(args.new, base=base)
    findings = widening(old, new)
    if not findings:
        print("Not wider: this change adds no host, folder, key reach or approval gap.")
        return 0
    print(f"This change widens what the agent can reach ({len(findings)}):")
    for finding in findings:
        print(f"  {finding.code}: {finding.detail}")
    return 1


def cmd_verify_log(args: argparse.Namespace) -> int:
    intact, count, problem = AuditLog.verify(args.path)
    print(f"{count} lines intact." if intact else f"Broken after {count} lines: {problem}")
    return 0 if intact else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentfence", description="Six small rules for personal AI agents.")
    parser.add_argument("--version", action="version", version=f"agentfence {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="write a starter agentfence.toml")
    p.add_argument("--path", default="agentfence.toml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    for name, func, text in (("check", cmd_check, "prove the box on this machine"),
                             ("run", cmd_run, "run a command in the box")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--policy", help="rules file (default: ./agentfence.toml, else a temporary box)")
        p.add_argument("--backend", choices=BACKENDS, default="auto")
        if name == "run":
            p.add_argument("--timeout", type=float, help="seconds (default: the rules' timeout_seconds)")
            p.add_argument("command", nargs=argparse.REMAINDER)
        p.set_defaults(func=func)

    p = sub.add_parser("diff", help="what a rules change widens")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--base", help="resolve relative paths in both files from here (default: NEW's folder)")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("verify-log", help="check the audit log's chain")
    p.add_argument("path")
    p.set_defaults(func=cmd_verify_log)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AgentfenceError as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
