"""The six rules behind one object.

    from agentfence import Fence

    fence = Fence.from_file("agentfence.toml")
    fence.prove()                                   # rule 3: or FenceNotProven
    result = fence.run_python(model_written_code)   # rules 1 and 2
    if fence.gate("send_email", target=to, args=email):   # rule 4
        send(email)
    fence.check_url(url)                            # rule 1, for the harness's own calls
    headers = {"x-api-key": fence.key_for("ANTHROPIC_API_KEY", url)}   # rule 2
    # rule 5: every call refuses once agentfence.toml changes under it
    # rule 6: everything above lands in the audit log
"""
from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from .approvals import Approvals, Proposal, terminal_prompt
from .audit import AuditLog
from .box import Box, RunResult
from .errors import EgressDenied, FenceNotProven, KeyDenied, PolicyError, RulesChanged
from .net import check_url as _check_url
from .net import key_for as _key_for
from .policy import Policy, _inside
from .probe import Proof

_ASK_DEFAULT = object()


class Fence:
    def __init__(self, policy: Policy, *, backend: str = "auto",
                 ask: Callable[[Proposal], bool] | None | object = _ASK_DEFAULT,
                 audit_path: str | Path | None = None, env_passthrough: Sequence[str] = ()) -> None:
        self.policy = policy
        audit_path = Path(audit_path) if audit_path else policy.base / ".agentfence" / "audit.jsonl"
        for root in policy.write_roots:
            if _inside(audit_path, root):
                raise PolicyError(f"The audit log {audit_path} is inside {root}, which the box may write.")
        self.audit = AuditLog(audit_path)
        self.box = Box(policy.workdir, also_write=policy.also_write, also_read=policy.also_read,
                       must_not_read=policy.must_not_read, backend=backend, env_passthrough=env_passthrough,
                       timeout_s=policy.timeout_s, audit=self.audit)
        if ask is _ASK_DEFAULT:
            ask = terminal_prompt if sys.stdin is not None and sys.stdin.isatty() else None
        self.approvals = Approvals(policy.verbs, policy.ttl_s, ask=ask, audit=self.audit)

    @classmethod
    def from_file(cls, path: str | Path = "agentfence.toml", **kwargs) -> Fence:
        return cls(Policy.load(path), **kwargs)

    # Rule 5: the rules in force are the rules that were reviewed.
    def _same_rules(self) -> None:
        if self.policy.path and self.policy.current_fingerprint() != self.policy.fingerprint:
            self.audit.record("rules_changed", path=str(self.policy.path))
            raise RulesChanged(f"{self.policy.path} changed after it was loaded. Review it with "
                               "`agentfence diff`, then load it again.")

    def prove(self, refresh: bool = False) -> Proof:
        self._same_rules()
        proof = self.box.prove(refresh=refresh)
        if not proof.ok:
            raise FenceNotProven(proof.reason)
        return proof

    def run(self, command: Sequence[str], *, timeout_s: float | None = None) -> RunResult:
        self._same_rules()
        return self.box.run(command, timeout_s=timeout_s)

    def run_python(self, code: str, *, timeout_s: float | None = None) -> RunResult:
        self._same_rules()
        return self.box.run_python(code, timeout_s=timeout_s)

    def gate(self, action: str, target: str = "", args: dict | None = None) -> bool:
        self._same_rules()
        return self.approvals.gate(action, target, args)

    def check_url(self, url: str) -> str:
        self._same_rules()
        try:
            host = _check_url(url, self.policy.net_allow)
        except EgressDenied as exc:
            self.audit.record("egress_denied", reason=str(exc))
            raise
        self.audit.record("egress", host=host)
        return host

    def key_for(self, name: str, url: str) -> str:
        self._same_rules()
        try:
            value = _key_for(name, url, self.policy.keys, self.policy.net_allow)
        except (KeyDenied, EgressDenied) as exc:
            self.audit.record("key_denied", key=name, reason=str(exc))
            raise
        self.audit.record("key_released", key=name, host=_host_of(url))
        return value


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(url).hostname or "").lower()
