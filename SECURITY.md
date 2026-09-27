# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 (2.x internal builds) | ❌ — upgrade to 1.0.0 |

## Reporting a vulnerability

If you believe you've found a security vulnerability in JSCoup, please report it privately rather than opening a public GitHub issue:

- Open a [GitHub Security Advisory](https://github.com/zaidonaljbaae/JSCOUP/security/advisories/new) (preferred — private by default), or
- Contact the maintainer, Zaidon Aljbaae, directly through GitHub.

Please include:
- JSCoup version and Python version
- A minimal reproduction, if possible
- The potential impact as you understand it (e.g. credential exposure, authentication bypass, denial of service)

You should expect an initial response acknowledging the report, followed by an assessment and, if confirmed, a fix released as a patch version with the vulnerability disclosed in `CHANGELOG.md` after users have had a reasonable window to upgrade.

## Scope and honest limits

JSCoup documents its own security posture directly in [SECURITY_UPGRADE.md](SECURITY_UPGRADE.md) and the [Technical White Paper](docs/JSCOUP_Whitepaper.pdf) — including what it does **not** claim to do:

- It is a single-process/single-machine library. Background delivery is best-effort, not durable messaging.
- Gateway rate limiting and quotas are local to one process/filesystem, not a distributed rate limiter.
- Windows ACLs on local state files are an explicit operator responsibility; the library does not enforce them.
- The dashboard's own frontend currently retains `unsafe-inline` in its Content-Security-Policy to preserve its existing inline-script UI.
- No independent third-party security audit has been performed; the security documentation reflects the maintainer's own review and testing.

If your deployment needs guarantees beyond what's documented, please treat that as a real gap to design around (e.g. an edge/API-gateway product in front of JSCoup's own gateway for distributed rate limiting), not as an oversight to report.
