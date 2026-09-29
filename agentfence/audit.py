"""Rule 6: log what happened in one append-only file.

One JSON object per line: what ran, what the startup check found, what was
refused and what you approved. Each line carries the SHA-256 of the line
before it, so an edit or a deleted line in the middle shows up in
``AuditLog.verify``. (Cutting lines off the end does not; keep a copy
elsewhere if that matters to you.) The file is created readable by you only.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path


def _hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()
        self._last: str | None = None

    def _tail_hash(self) -> str:
        if self._last is None:
            last = ""
            if self.path.exists():
                with self.path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if line.strip():
                            last = line.rstrip("\n")
            self._last = _hash(last) if last else ""
        return self._last

    def record(self, event: str, **fields) -> dict:
        with self._lock:
            entry = {"ts": datetime.now(UTC).isoformat(timespec="milliseconds"), "event": event,
                     **{k: v for k, v in fields.items() if v is not None}, "prev": self._tail_hash()}
            line = json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            self._last = _hash(line)
        return entry

    @staticmethod
    def verify(path: str | Path) -> tuple[bool, int, str]:
        """(intact, lines checked, what is wrong). Checks that each line names the one before it."""
        previous = ""
        count = 0
        with Path(path).expanduser().open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, count, f"line {number} is not JSON"
                if entry.get("prev") != previous:
                    return False, count, f"line {number} does not follow the line before it (edited or removed)"
                previous = _hash(line)
                count += 1
        return True, count, ""
