"""Fence (all six rules behind one object) and the command line."""
from __future__ import annotations

import json

import pytest

from agentfence import EgressDenied, Fence, Policy, PolicyError, RulesChanged
from agentfence.cli import main
from agentfence.policy import STARTER


@pytest.fixture
def rules(tmp_path):
    path = tmp_path / "agentfence.toml"
    path.write_text(STARTER)
    return path


def events(fence):
    return [json.loads(line)["event"] for line in fence.audit.path.read_text().splitlines()]


def test_a_fence_runs_gates_and_logs(rules):
    fence = Fence.from_file(rules, backend="none", ask=lambda p: True)
    assert fence.prove().ok
    assert fence.run_python("print('hi')").stdout.strip() == "hi"
    assert fence.gate("send_email", "a@example.com", {"body": "x"})
    with pytest.raises(EgressDenied):
        fence.check_url("https://pastebin.com/")
    assert events(fence) == ["probe", "run", "approval_requested", "approval_approved", "approval_used",
                             "egress_denied"]


def test_a_changed_rules_file_stops_everything(rules):
    fence = Fence.from_file(rules, backend="none", ask=lambda p: True)
    rules.write_text(STARTER.replace('allow = ["api.anthropic.com"]', 'allow = ["api.anthropic.com", "x.com"]'))
    for call in (lambda: fence.run_python("print(1)"), lambda: fence.gate("send_email"),
                 lambda: fence.check_url("https://api.anthropic.com/")):
        with pytest.raises(RulesChanged):
            call()


def test_the_log_may_not_live_inside_the_box(rules, tmp_path):
    with pytest.raises(PolicyError, match="audit log"):
        Fence(Policy.load(rules), backend="none", audit_path=tmp_path / "agent-work" / "log.jsonl")


def test_init_then_check_then_run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert main(["init"]) == 1                     # never overwrites without --force
    assert main(["check", "--backend", "none"]) == 1   # no box is not a pass
    assert main(["run", "--backend", "none", "--", "python3", "-c", "print('boxed')"]) == 0
    assert "boxed" in capsys.readouterr().out


def test_diff_names_what_widens(tmp_path, capsys):
    old = tmp_path / "old.toml"
    new = tmp_path / "new.toml"
    old.write_text(STARTER)
    new.write_text(STARTER)
    assert main(["diff", str(old), str(new)]) == 0
    new.write_text(STARTER.replace('allow = ["api.anthropic.com"]', 'allow = ["api.anthropic.com", "x.com"]'))
    assert main(["diff", str(old), str(new)]) == 1
    assert "host_added: the harness may now call x.com" in capsys.readouterr().out


def test_verify_log(tmp_path, rules, capsys):
    fence = Fence.from_file(rules, backend="none", ask=None)
    fence.gate("search_web")
    assert main(["verify-log", str(fence.audit.path)]) == 0
    assert "1 lines intact" in capsys.readouterr().out
