# agentfence

Six small rules that keep a personal AI agent from reading, leaking or doing more than you meant. One Python package, no dependencies, macOS and Linux.

Inspired by [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell). Not affiliated with NVIDIA. Status: beta (v0.1).

## Why

Agents write code and call tools on your machine, with your keys. OpenShell shows how to fence a fleet of them. It gives you:

- kernel-enforced sandboxes that deny by default;
- credentials added only at approved endpoints;
- policy changes checked before they widen reach;
- nothing starts until the fence is confirmed.

agentfence is the home-sized version of the same ideas for one person's agent on a laptop: no daemon, no VM, no gateway.

## The six rules

| Rule | In agentfence |
| --- | --- |
| 1. Run what the model writes in a box with no network and one writable folder | `Box`: Seatbelt on macOS, bubblewrap on Linux |
| 2. Keep keys out of the box | A scrubbed environment for the box; `key_for` hands a key only to the hosts it belongs to |
| 3. Prove the box before you trust it | `Box.prove()` and `agentfence check`: if any leak test passes, nothing runs |
| 4. Ask before anything outward or irreversible, and approve the exact thing once | `Approvals.gate`: bound to a hash of the action and its arguments, used once, expires |
| 5. Keep the rules in one file the agent can't edit, and review every change | `agentfence.toml`, `agentfence diff`, and a refusal when the file changes under a running harness |
| 6. Log what happened in one append-only file | `AuditLog`: hash-chained JSON lines, readable by you only |

## Install

Requires Python 3.11 or newer.

```sh
pip install git+https://github.com/vn-envy/agentfence
```

On Linux, also install bubblewrap: `sudo apt install bubblewrap` or `sudo dnf install bubblewrap`. On macOS, the sandbox ships with the system.

## Quick start

```sh
agentfence init                        # writes agentfence.toml
agentfence check                       # proves the box on this machine
agentfence run -- python3 script.py    # runs a command in the box
```

`agentfence check` runs a small script inside the box that tries to leak, and prints what it could and couldn't do:

```
agentfence check · backend bubblewrap
  ok    write_own_folder                         allowed
  ok    read_secret                              denied
  ok    read_through_symlink                     denied
  ok    hard_link_secret                         denied
  ok    list_home                                denied
  ok    network                                  denied
  ok    write_outside                            denied
  ok    must_not_read:/home/you/.ssh             denied
  ok    must_not_read:/home/you/project/.env     skipped (not on this machine)
bubblewrap: no home folder, no secrets, no network; writes only /home/you/project/agent-work.
```

## In your harness

```python
from agentfence import Fence, EgressDenied

fence = Fence.from_file("agentfence.toml")
fence.prove()                                    # rule 3: raises FenceNotProven if the box leaks

result = fence.run_python(code_the_model_wrote)  # rules 1 and 2
print(result.stdout, result.removed_links)

email = {"to": "friend@example.com", "subject": "Lunch", "body": "Thursday at 1?"}
if fence.gate("send_email", target=email["to"], args=email):   # rule 4: asks you first
    send(email)

fence.check_url(url)                             # the harness's own calls: named hosts only
headers = {"x-api-key": fence.key_for("ANTHROPIC_API_KEY", url)}
```

Every call above refuses with `RulesChanged` if `agentfence.toml` changes after it was loaded (rule 5). Every call lands in `.agentfence/audit.jsonl` (rule 6).

On a terminal, `gate` asks there. Anywhere else, pass your own `ask=` function (a phone notification, a chat button). Or use `propose`, `decide` and `consume` to approve from another process. See `examples/harness.py` for a runnable walk-through.

## The rules file

```toml
[box]
workdir = "./agent-work"          # the one folder the box may write
also_write = []
also_read = []
must_not_read = ["~/.ssh", "./.env"]   # the check proves these unreadable
timeout_seconds = 60

[net]
allow = ["api.anthropic.com"]     # hosts the harness may call; ".example.com" allows subdomains

[keys]
ANTHROPIC_API_KEY = ["api.anthropic.com"]   # each key goes only here, never into the box

[approve]
verbs = ["send", "pay", "delete", "remove", "post", "publish", "submit", "buy", "purchase", "book", "transfer"]
ttl_minutes = 15
```

Loading refuses rules that would undo themselves:

- the rules file inside a folder the box may write;
- a `must_not_read` path the box is allowed to read;
- a key sent to a host `[net]` doesn't list;
- unknown sections or keys, so a typo can't quietly change anything.

## Reviewing a change

Ask one question of every change: does it add a host, a folder or a write verb?

```sh
git show HEAD:agentfence.toml > /tmp/old.toml
agentfence diff /tmp/old.toml agentfence.toml --base .
```

It exits 1 and names each widening, so you can run it in CI or a pre-commit hook:

| Finding | Meaning |
| --- | --- |
| `write_added` | The box may write a new folder |
| `read_added` | The box may read a new folder |
| `check_removed` | The startup check no longer proves a path unreadable |
| `host_added` | The harness may call a new host |
| `credentialed_host_added` | A new host that also receives a key |
| `key_added` | A new key |
| `key_reach_expanded` | An existing key goes to more hosts |
| `approval_removed` | Actions with a given verb no longer ask |
| `approval_window_longer` | Approvals stay valid longer |

## What the box allows

| | macOS (Seatbelt) | Linux (bubblewrap) |
| --- | --- | --- |
| Read | System folders, the Python interpreter and its packages, the box's folders | `/usr`, a short list of `/etc` files, the interpreter, the box's folders |
| Write | The box's folders | The box's folders |
| Network | None, including 127.0.0.1 | None: a new network namespace |
| Home | `HOME` and `TMPDIR` point inside the box | Same; the real home is not mounted |

The harness side matters as much as the box. Output is read through pipes the harness opened, never through a file the code could swap for a link. When a run ends, its whole process group is killed. Any symbolic or hard link the code left in a writable folder is removed before anything reads or serves that folder.

## What it does not do

- It is not a defence against kernel exploits or a hostile local user. It fences code a model wrote and gives your harness a checklist.
- The harness is trusted. If you later open a path the model handed you, check it yourself.
- Tools that need the internet don't run in the box. The harness makes those calls through `check_url`.
- Approvals live in memory in v0.1. Persist proposals yourself if several processes share them.
- The log's hash chain shows edits and deletions in the middle, not lines cut off the end.
- Windows is not supported.
- Apple marks `sandbox-exec` deprecated in its man page, but it still ships with macOS. The startup check is what tells you it still holds on your machine.

## Credits and license

The ideas come from NVIDIA OpenShell's architecture and security docs: supervisor and sandbox, deny-by-default egress, credentials only at approved endpoints, the policy prover, and a fail-closed launch. Any mistakes in the small version are ours.

Apache License 2.0. See [LICENSE](LICENSE).
