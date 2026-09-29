# Security

agentfence is beta software for fencing code a model wrote on your own machine. Please report a way around it privately: open a private security advisory on this repository (Security, then "Report a vulnerability"). Don't use a public issue.

Useful in a report:

- your OS and version, Python version, and `agentfence check` output;
- the smallest code that escapes (reads a `must_not_read` path, reaches the network, writes outside the box, or makes the harness read a file for it);
- whether the startup check still passed when it happened. A check that passes while the box leaks is the most important kind of bug here.

Out of scope: kernel exploits, a hostile local user, and running with `backend="none"`.
