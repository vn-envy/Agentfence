"""agentfence: six small rules that keep a personal AI agent inside the lines.

1. Run what the model writes in a box with no network and one writable folder.  Box
2. Keep keys out of the box.                                                      env, key_for
3. Prove the box before you trust it.                                             Box.prove
4. Ask before anything outward or irreversible, and approve the exact thing once. Approvals
5. Keep the rules in one file the agent can't edit, and review every change.     Policy, widening
6. Log what happened in one append-only file.                                     AuditLog

Fence puts all six behind one object. Inspired by NVIDIA OpenShell; not affiliated with NVIDIA.
"""
from .approvals import Approvals, Proposal, terminal_prompt
from .audit import AuditLog
from .box import Box, RunResult, detect_backend
from .errors import (
    AgentfenceError,
    EgressDenied,
    FenceNotProven,
    KeyDenied,
    PolicyError,
    RulesChanged,
)
from .fence import Fence
from .net import check_url, key_for
from .policy import Finding, Policy, widening
from .probe import Proof

__version__ = "0.1.0"

__all__ = [
    "AgentfenceError", "Approvals", "AuditLog", "Box", "EgressDenied", "Fence", "FenceNotProven", "Finding",
    "KeyDenied", "Policy", "PolicyError", "Proof", "Proposal", "RulesChanged", "RunResult", "check_url",
    "detect_backend", "key_for", "terminal_prompt", "widening", "__version__",
]
