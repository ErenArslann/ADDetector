# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.0.x  | ✅ Yes    |

## Reporting a Vulnerability

If you discover a security vulnerability in ADDetector, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Contact: github.com/ErenArslann

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours.

## Security Notes

- ADDetector is **read-only** — it does not modify, disable, or delete any AD objects
- Only performs `Get-ADUser` and `Get-ADGroup` LDAP queries
- No credentials are stored or transmitted
- All data stays local — no telemetry, no external connections
- Log files (`logs\ADDetector.log`) contain only operational data, no user credentials
