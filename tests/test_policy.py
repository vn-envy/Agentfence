"""Rule 5: the rules file, what it refuses, and what a change widens."""
from __future__ import annotations

import pytest

from agentfence import Policy, PolicyError, widening
from agentfence.policy import STARTER, host_allowed


def write(tmp_path, text, name="agentfence.toml"):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_the_starter_file_loads_with_paths_beside_it(tmp_path):
    policy = Policy.load(write(tmp_path, STARTER))
    assert policy.workdir == (tmp_path / "agent-work").resolve()
    assert policy.net_allow == ("api.anthropic.com",)
    assert policy.keys == {"ANTHROPIC_API_KEY": ("api.anthropic.com",)}
    assert policy.ttl_s == 900 and "send" in policy.verbs
    assert len(policy.fingerprint) == 64


@pytest.mark.parametrize("text, message", [
    ('[box]\nworkdir = "w"\n[boxes]\n', "Unknown section"),
    ('[box]\nworkdir = "w"\nnetwork = true\n', "Unknown key"),
    ("[box]\n", "needs a workdir"),
    ('[box]\nworkdir = "w"\n[net]\nallow = ["https://x.com/"]\n', "not a host name"),
    ('[box]\nworkdir = "w"\n[keys]\nK = ["api.x.com"]\n', "does not list"),
    ('[box]\nworkdir = "w"\n[approve]\nttl_minutes = 0\n', "positive"),
    ('[box]\nworkdir = "."\n', "rewrite its own rules"),
    ('[box]\nworkdir = "w"\nalso_read = ["~"]\nmust_not_read = ["~/.ssh"]\n', "must_not_read"),
    ("not toml at all [", "not valid TOML"),
])
def test_rules_that_would_undo_themselves_are_refused(tmp_path, text, message):
    with pytest.raises(PolicyError, match=message):
        Policy.load(write(tmp_path, text))


def test_a_narrower_change_has_no_findings(tmp_path):
    old = Policy.load(write(tmp_path, STARTER, "old.toml"))
    new = Policy.load(write(tmp_path, STARTER.replace('"./.env"]', '"./.env", "~/.aws"]'), "new.toml"))
    assert widening(old, new) == []


def test_every_way_to_widen_is_named(tmp_path):
    old = Policy.load(write(tmp_path, STARTER, "old.toml"))
    wider = (STARTER
             .replace('also_write = []', 'also_write = ["./downloads"]')
             .replace('also_read = []', 'also_read = ["./docs"]')
             .replace('must_not_read = ["~/.ssh", "./.env"]', 'must_not_read = ["~/.ssh"]')
             .replace('allow = ["api.anthropic.com"]',
                      'allow = ["api.anthropic.com", "pastebin.com", "api.openai.com"]')
             .replace('ANTHROPIC_API_KEY = ["api.anthropic.com"]',
                      'ANTHROPIC_API_KEY = ["api.anthropic.com", "pastebin.com"]\nOPENAI_API_KEY = ["api.openai.com"]')
             .replace('"book", "transfer"]', '"book"]')
             .replace("ttl_minutes = 15", "ttl_minutes = 120"))
    new = Policy.load(write(tmp_path, wider, "new.toml"))
    codes = sorted(f.code for f in widening(old, new))
    assert codes == sorted(["write_added", "read_added", "check_removed", "credentialed_host_added",
                            "credentialed_host_added", "key_added", "key_reach_expanded", "approval_removed",
                            "approval_window_longer"])


def test_a_plain_host_is_named_without_a_key(tmp_path):
    old = Policy.load(write(tmp_path, STARTER, "old.toml"))
    new = Policy.load(write(tmp_path, STARTER.replace('allow = ["api.anthropic.com"]',
                                                      'allow = ["api.anthropic.com", "en.wikipedia.org"]'), "new.toml"))
    assert [f.code for f in widening(old, new)] == ["host_added"]


def test_host_matching():
    assert host_allowed("api.x.com", ["api.x.com"])
    assert not host_allowed("evil-api.x.com", ["api.x.com"])
    assert host_allowed("a.b.x.com", [".x.com"]) and host_allowed("x.com", [".x.com"])
    assert not host_allowed("notx.com", [".x.com"])
