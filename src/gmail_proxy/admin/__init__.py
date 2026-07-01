"""Admin web UI: configuration + debugging, served on the trusted host side.

Runs on a SEPARATE port from the MCP endpoint, is admin-authenticated, and is
never exposed to the VM.  Provides config editing, the audit-log viewer, a
policy-explain view, a dry-run tool tester, credential management, and the
kill-switch.
"""
