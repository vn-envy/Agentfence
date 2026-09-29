"""The harness's own calls: named hosts only, and keys only where they belong."""
from __future__ import annotations

import pytest

from agentfence import EgressDenied, KeyDenied, check_url, key_for

ALLOW = ("api.anthropic.com", ".example.com", "localhost", "10.0.0.5")


def public(host):
    return ["93.184.216.34"]


@pytest.mark.parametrize("url, message", [
    ("ftp://api.anthropic.com/x", "Only http and https"),
    ("https://user:pw@api.anthropic.com/", "user name or password"),
    ("https://pastebin.com/raw", "not in \\[net\\] allow"),
    ("https://api.anthropic.com.evil.net/", "not in \\[net\\] allow"),
])
def test_urls_the_rules_do_not_name_are_refused(url, message):
    with pytest.raises(EgressDenied, match=message):
        check_url(url, ALLOW, resolve=public)


def test_a_named_host_that_leads_somewhere_private_is_refused():
    with pytest.raises(EgressDenied, match="private address"):
        check_url("https://docs.example.com/", ALLOW, resolve=lambda h: ["192.168.1.10"])
    with pytest.raises(EgressDenied, match="metadata"):
        check_url("https://docs.example.com/", ALLOW, resolve=lambda h: ["169.254.169.254"])


def test_listed_hosts_pass_and_local_ones_only_by_name():
    assert check_url("https://api.anthropic.com/v1/messages", ALLOW, resolve=public) == "api.anthropic.com"
    assert check_url("https://a.b.example.com/", ALLOW, resolve=public) == "a.b.example.com"
    assert check_url("http://localhost:11434/api", ALLOW, resolve=lambda h: ["127.0.0.1"]) == "localhost"
    assert check_url("http://10.0.0.5/", ALLOW) == "10.0.0.5"


def test_a_key_goes_only_to_its_hosts_over_https():
    keys = {"ANTHROPIC_API_KEY": ("api.anthropic.com",), "LOCAL_KEY": ("localhost",)}
    env = {"ANTHROPIC_API_KEY": "sk-1", "LOCAL_KEY": "l"}
    url = "https://api.anthropic.com/v1"
    assert key_for("ANTHROPIC_API_KEY", url, keys, ALLOW, environ=env, resolve=public) == "sk-1"
    with pytest.raises(KeyDenied, match="goes only to"):
        key_for("ANTHROPIC_API_KEY", "https://docs.example.com/", keys, ALLOW, environ=env, resolve=public)
    with pytest.raises(KeyDenied, match="only over https"):
        key_for("ANTHROPIC_API_KEY", "http://api.anthropic.com/v1", keys, ALLOW, environ=env, resolve=public)
    with pytest.raises(KeyDenied, match="not in \\[keys\\]"):
        key_for("OTHER", "https://api.anthropic.com/", keys, ALLOW, environ=env, resolve=public)
    with pytest.raises(KeyDenied, match="not set"):
        key_for("ANTHROPIC_API_KEY", "https://api.anthropic.com/", keys, ALLOW, environ={}, resolve=public)
    assert key_for("LOCAL_KEY", "http://localhost:8080/", keys, ALLOW, environ=env,
                   resolve=lambda h: ["127.0.0.1"]) == "l"
