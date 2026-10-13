# Security Scanning Allowlist

This document records justifications for security scanner suppressions and allowlisted packages.

## Bandit Suppressions

| ID | Issue | Location | Justification |
|---|---|---|---|
| B101 | Test assert statements | `tests/`, `*/tests/*` | Pytest relies on standard assert statements for test verifications. |
| B404 | Import of subprocess | `agent/collectors/` | Hardware evidence collection invokes system tools with allowlisted argument lists and `shell=False`. |
| B603 | Subprocess without shell | `agent/collectors/` | All subprocess executions use explicit list arguments and prohibit `shell=True`. |

## Dependency Audit Allowlist

No vulnerabilities are currently allowlisted.
All dependencies must resolve to secure release versions without known CVEs.
