"""Rule 4: ask before anything outward or irreversible, and approve that exact thing once.

An action whose name carries a commit verb (send, pay, delete, post, submit…)
waits for a yes. The yes is bound to a hash of the action, its target and its
arguments: change one word of the email and it is a new request. An approval
is used once and expires (15 minutes by default). Everything else runs, so a
yes still means something when it is asked for.

Two ways to use it:

    if approvals.gate("send_email", target=to, args={"subject": s, "body": b}):
        send(...)                        # asks in the terminal, or through `ask`

    p = approvals.propose(...)           # a phone or web UI shows p.summary, p.args
    approvals.decide(p.id, True)         # when the person taps Approve
    if approvals.consume(...):           # the same action, target and args
        send(...)
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .policy import DEFAULT_VERBS

if TYPE_CHECKING:
    from .audit import AuditLog

_SUFFIXES = ("", "s", "es", "ed", "ing", "ment", "ments")


def digest(action: str, target: str, args: dict | None) -> str:
    canonical = json.dumps({"action": action, "target": target, "args": args or {}}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Proposal:
    id: str
    action: str
    target: str
    args: dict[str, Any]
    digest: str
    created: float
    expires: float
    state: str = "pending"            # pending | approved | rejected | used
    decided_by: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        return f"{self.action} → {self.target}" if self.target else self.action


def terminal_prompt(proposal: Proposal) -> bool:
    """Show the exact action on the terminal and read a yes or no."""
    body = json.dumps(proposal.args, indent=2, ensure_ascii=False, default=str)
    if len(body) > 4000:
        body = body[:4000] + "\n  … (cut; the approval still covers all of it)"
    print("\nagentfence: approval needed", file=sys.stderr)
    print(f"  action: {proposal.action}", file=sys.stderr)
    if proposal.target:
        print(f"  target: {proposal.target}", file=sys.stderr)
    print("  args:\n" + "\n".join("    " + line for line in body.splitlines()), file=sys.stderr)
    try:
        answer = input("Approve this exact action, once? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


class Approvals:
    def __init__(self, verbs: tuple[str, ...] | list[str] = DEFAULT_VERBS, ttl_s: float = 900, *,
                 ask: Callable[[Proposal], bool] | None = None, audit: AuditLog | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.verbs = tuple(v.lower() for v in verbs)
        self.ttl_s = ttl_s
        self.ask = ask
        self.audit = audit
        self.clock = clock
        self._proposals: dict[str, Proposal] = {}
        self._lock = threading.Lock()

    def needs_approval(self, action: str) -> bool:
        """Does the action's name carry a commit verb? send_email, delete-file, "Post update", payment…"""
        words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", action)      # submitForm → submit_Form
        tokens = [t for t in re.split(r"[^a-z0-9]+", words.lower()) if t]
        return any(token == verb + suffix for token in tokens for verb in self.verbs for suffix in _SUFFIXES)

    def propose(self, action: str, target: str = "", args: dict | None = None) -> Proposal:
        """A pending request for this exact action. The same request again reuses it."""
        key = digest(action, target, args)
        now = self.clock()
        with self._lock:
            for proposal in self._proposals.values():
                if proposal.digest == key and proposal.state == "pending" and proposal.expires > now:
                    return proposal
            proposal = Proposal(id=uuid.uuid4().hex[:12], action=action, target=target, args=dict(args or {}),
                                digest=key, created=now, expires=now + self.ttl_s)
            self._proposals[proposal.id] = proposal
        self._record("approval_requested", proposal)
        return proposal

    def get(self, proposal_id: str) -> Proposal | None:
        return self._proposals.get(proposal_id)

    def pending(self) -> list[Proposal]:
        now = self.clock()
        return [p for p in self._proposals.values() if p.state == "pending" and p.expires > now]

    def decide(self, proposal_id: str, approved: bool, by: str = "you") -> Proposal:
        with self._lock:
            proposal = self._proposals.get(proposal_id)
            if proposal is None:
                raise KeyError(proposal_id)
            if proposal.state != "pending":
                return proposal
            proposal.state = "approved" if approved else "rejected"
            proposal.decided_by = by
        self._record("approval_" + proposal.state, proposal)
        return proposal

    def consume(self, action: str, target: str = "", args: dict | None = None) -> bool:
        """True once for an approved, unexpired approval of exactly this action; then never again."""
        key = digest(action, target, args)
        now = self.clock()
        with self._lock:
            for proposal in self._proposals.values():
                if proposal.digest == key and proposal.state == "approved" and proposal.expires > now:
                    proposal.state = "used"
                    break
            else:
                return False
        self._record("approval_used", proposal)
        return True

    def gate(self, action: str, target: str = "", args: dict | None = None) -> bool:
        """True if the action may run now. Commit actions ask first (through `ask`)."""
        if not self.needs_approval(action):
            if self.audit:
                self.audit.record("action", action=action, target=target, approval="not needed")
            return True
        proposal = self.propose(action, target, args)
        if self.ask is None:
            return False            # pending: decide it elsewhere, then consume
        self.decide(proposal.id, bool(self.ask(proposal)))
        return self.consume(action, target, args)

    def _record(self, event: str, proposal: Proposal) -> None:
        if self.audit:
            # The digest, not the arguments: the log should not become a copy of every message.
            self.audit.record(event, id=proposal.id, action=proposal.action, target=proposal.target,
                              digest=proposal.digest, by=proposal.decided_by or None)
