# Security Policy

cap is a security tool; reports about cap itself are taken seriously.

## Supported versions

Only the latest `main` (and the newest tagged release) receives fixes.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting
(Security → Report a vulnerability) rather than a public issue. Include the
affected file/line, an exploit scenario, and — if possible — a probe that
demonstrates the issue against the current main branch.

You can also self-check any capability folder at any time:

    python3 scripts/capability_registry.py audit <path> --recursive --strict --check-deps

## Scope notes

- The offline regex firewall never performs network calls unless you opt in
  via `--check-deps` or `--llm-scan` (and, for the latter, export provider
  credentials).
- Signed receipts attest report integrity only; use `--verify-files` to also
  re-check scanned contents on disk.
