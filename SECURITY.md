# Security Policy

Opaque handles secrets and approval-gated operations. We take security seriously.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | Yes                |
| < latest | No                |

Only the latest release receives security updates.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities by emailing **security@anthropic.com**.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: within 72 hours
- **Initial assessment**: within 1 week
- **Fix timeline**: depends on severity, targeting 30 days for critical issues

## Coordinated Disclosure

We follow a 90-day coordinated disclosure policy. We will work with you to understand and address the issue before any public disclosure.

## Scope

In scope:
- Secret value disclosure through CLI output, MCP responses, or audit logs
- Policy bypass (operations executing without required approval)
- Daemon authentication bypass
- Sandbox escape or secret leakage from sandboxed processes
- Client identity spoofing

Out of scope:
- Denial of service against the local daemon
- Issues requiring physical access to an unlocked machine
- Social engineering
