"""A tiny agent harness with agentfence around it.

There is no model here: the "agent" is a list of things a model might ask
for, so you can see what each rule does. Run it from this folder:

    python harness.py
"""
from __future__ import annotations

from agentfence import EgressDenied, Fence, FenceNotProven, KeyDenied

fence = Fence.from_file("agentfence.toml")

# Rule 3: prove the box before anything runs in it.
try:
    print("check:", fence.prove().reason)
except FenceNotProven as exc:
    raise SystemExit(f"Not running model code: {exc}") from None

# Rules 1 and 2: code the model wrote runs in the box. It sees its own folder
# as home, no keys, no network.
code = """
import os, socket
print("home is", os.path.expanduser("~"))
print("keys I can see:", [k for k in os.environ if "KEY" in k])
try:
    socket.create_connection(("example.com", 443), timeout=2)
    print("network: open")
except OSError as exc:
    print("network: blocked,", exc.strerror)
open("report.txt", "w").write("made in the box")
"""
result = fence.run_python(code)
print(result.stdout, end="")

# Rule 4: sending waits for your yes; reading does not.
email = {"to": "friend@example.com", "subject": "Lunch", "body": "Thursday at 1?"}
if fence.gate("send_email", target=email["to"], args=email):
    print("email: sent (pretend)")
else:
    print("email: not sent")
print("search allowed without asking:", fence.gate("search_web", args={"q": "lunch places"}))

# The harness's own calls: named hosts only, keys only where they belong.
for url in ("https://api.anthropic.com/v1/messages", "https://pastebin.com/raw/abc"):
    try:
        print("may call", fence.check_url(url))
    except EgressDenied as exc:
        print("refused:", exc)
try:
    fence.key_for("ANTHROPIC_API_KEY", "https://pastebin.com/raw/abc")
except (KeyDenied, EgressDenied) as exc:
    print("key refused:", exc)

# Rule 6: all of the above is in the log.
print("log:", fence.audit.path)
