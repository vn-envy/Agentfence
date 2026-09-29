# Changelog

All notable changes to agentfence are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Until 1.0, a minor version may change the API.

## [Unreleased]

## [0.1.0] - 2026-09-29

The first release: six rules for personal AI agents, as one dependency-free Python package. [Release notes](docs/releases/v0.1.0.md).

### Added

- **Box.** Model-written code runs with no network and one writable folder: Seatbelt on macOS, bubblewrap on Linux. `backend="none"` runs without a box, and only when asked for.
- **Startup check.** `Box.prove()` and `agentfence check` try seven leaks inside the box before its first run:
  - reading a secret, directly, through a symlink or by hard link;
  - listing the home folder;
  - connecting to 127.0.0.1;
  - writing outside the box;
  - reading each `must_not_read` path.

  Any success, or any unclear result, stops the box.
- **Keys and outbound calls.** The box gets a scrubbed environment. `check_url` limits the harness's own calls to named hosts and always refuses link-local and cloud metadata addresses. `key_for` hands a key only to its hosts, over https.
- **Approvals.** Actions named with a commit verb (send, pay, delete, post, submit…) wait for a yes. A yes is bound to a digest of the exact action and its arguments, used once, and expires after 15 minutes by default.
- **Rules file.** `agentfence.toml` is validated on load and refuses rules that would undo themselves. `Fence` stops when the file changes under it. `agentfence diff` names every widening and exits 1.
- **Audit log.** Hash-chained, append-only JSON lines (mode 0600), checked with `agentfence verify-log`.
- **`Fence`**, one object for all six rules, and the `agentfence` command: `init`, `check`, `run`, `diff`, `verify-log`.
- `examples/harness.py`, a runnable walk-through of every rule.
- CI on macOS and Linux (Python 3.11 and 3.13) that runs the real sandboxes. On a macOS failure it prints the kernel's Sandbox deny log.

### Security

- Output is read through pipes the harness opened, never through a named file the code could swap for a link to a secret.
- When a run ends, its process group is killed, and symbolic and hard links left in writable folders are removed before anything reads them.
- The Seatbelt profile allows exactly the root folder `/`, and loads code only from system and interpreter folders, never from the box's own folder.

[Unreleased]: https://github.com/vn-envy/agentfence/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vn-envy/agentfence/releases/tag/v0.1.0
