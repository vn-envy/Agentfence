from __future__ import annotations

import pytest

from agentfence import Box, detect_backend


@pytest.fixture
def secret(tmp_path):
    """A file outside the box that only the harness should be able to read."""
    path = tmp_path / "private" / "secret.txt"
    path.parent.mkdir()
    path.write_text("family data")
    return path


@pytest.fixture
def real_box(tmp_path, secret):
    """A box on this machine's real backend (Seatbelt on macOS, bubblewrap on Linux), or skip."""
    if detect_backend() == "unavailable":
        pytest.skip("no sandbox on this machine (install bubblewrap on Linux)")
    box = Box(tmp_path / "work", must_not_read=[secret])
    proof = box.prove()
    assert proof.ok, proof.reason
    return box
