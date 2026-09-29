"""Every refusal agentfence makes is one of these, so a harness can catch them by kind."""
from __future__ import annotations


class AgentfenceError(Exception):
    """Base class for everything agentfence refuses."""


class PolicyError(AgentfenceError):
    """The rules file is malformed, or would let the box reach something it must not."""


class RulesChanged(AgentfenceError):
    """The rules file changed after it was loaded. Review the change, then load it again."""


class FenceNotProven(AgentfenceError):
    """The startup check did not show that the box holds, so nothing runs in it."""


class EgressDenied(AgentfenceError):
    """A URL the harness was about to call is not allowed by the rules."""


class KeyDenied(AgentfenceError):
    """A key was requested for a host the rules do not send it to."""
