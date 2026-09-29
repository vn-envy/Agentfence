"""Rules 4 and 6: approvals bound to the exact action, and a log that shows tampering."""
from __future__ import annotations

import json
import os
import stat

import pytest

from agentfence import Approvals, AuditLog


def test_commit_verbs_are_found_in_action_names():
    approvals = Approvals()
    for action in ("send_email", "delete-file", "Post update", "payment", "submitForm", "sendMessage", "book_table",
                   "transfer_funds", "publishing"):
        assert approvals.needs_approval(action), action
    for action in ("read_file", "search_web", "summarise", "list_events", "reorder_list", "payload_size"):
        assert not approvals.needs_approval(action), action


def test_other_actions_run_without_asking():
    asked = []
    approvals = Approvals(ask=lambda p: asked.append(p) or True)
    assert approvals.gate("search_web", args={"q": "weather"})
    assert asked == []


def test_a_yes_covers_that_exact_action_once():
    asked = []
    approvals = Approvals(ask=lambda p: asked.append(p.args) or True)
    email = {"subject": "Dinner", "body": "7pm?"}
    assert approvals.gate("send_email", "mom@example.com", email)
    assert not approvals.consume("send_email", "mom@example.com", email)       # used once
    assert approvals.gate("send_email", "mom@example.com", {**email, "body": "8pm?"})  # asked again
    assert asked == [email, {**email, "body": "8pm?"}]


def test_no_means_no_and_no_ask_means_pending():
    approvals = Approvals(ask=lambda p: False)
    assert not approvals.gate("delete_file", "notes.txt")
    pending = Approvals(ask=None)
    assert not pending.gate("pay_bill", "electricity", {"amount": 1200})
    [proposal] = pending.pending()
    pending.decide(proposal.id, True, by="phone")
    assert not pending.consume("pay_bill", "electricity", {"amount": 12000})   # not what was approved
    assert pending.consume("pay_bill", "electricity", {"amount": 1200})


def test_approvals_expire():
    now = [1000.0]
    approvals = Approvals(ttl_s=60, clock=lambda: now[0])
    proposal = approvals.propose("send_email", "a@example.com", {"body": "hi"})
    approvals.decide(proposal.id, True)
    now[0] += 61
    assert not approvals.consume("send_email", "a@example.com", {"body": "hi"})


def test_the_log_chains_and_shows_an_edit(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.record("run", n=i)
    assert AuditLog.verify(path) == (True, 3, "")
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # A second writer (a new process) continues the same chain.
    AuditLog(path).record("run", n=3)
    assert AuditLog.verify(path)[:2] == (True, 4)
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["n"] = 99
    lines[1] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    intact, count, problem = AuditLog.verify(path)
    assert not intact and "line 3" in problem


def test_approval_events_log_the_digest_not_the_message(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    approvals = Approvals(ask=lambda p: True, audit=log)
    approvals.gate("send_email", "mom@example.com", {"body": "a private note"})
    text = (tmp_path / "a.jsonl").read_text()
    assert "a private note" not in text
    assert [json.loads(line)["event"] for line in text.splitlines()] == [
        "approval_requested", "approval_approved", "approval_used"]


@pytest.mark.parametrize("answer, expected", [("y\n", True), ("yes\n", True), ("\n", False), ("n\n", False)])
def test_the_terminal_prompt_shows_the_action(monkeypatch, capsys, answer, expected):
    from agentfence import terminal_prompt

    monkeypatch.setattr("builtins.input", lambda prompt="": answer.strip())
    approvals = Approvals()
    proposal = approvals.propose("send_email", "mom@example.com", {"subject": "Dinner"})
    assert terminal_prompt(proposal) is expected
    shown = capsys.readouterr().err
    assert "send_email" in shown and "mom@example.com" in shown and "Dinner" in shown
