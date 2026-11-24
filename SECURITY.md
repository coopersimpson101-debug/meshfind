# Security policy

## Supported versions

Only the latest commit on `main` is supported. This is a research/portfolio project
that has **not been deployed on hardware yet**; do not rely on it for anything critical.

## Scope

meshfind is a privacy protocol, so protocol-level weaknesses matter as much as code bugs.
Please report privately, for example:

- ways to **link a tag's rotating identities** (address/key) beyond the inherent timing/RSSI stitching
  described in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md);
- ways for relays, gateways, the server or a network observer to **learn report contents or the owner's identity**;
- **cryptographic flaws**: key-schedule or ratchet mistakes, nonce reuse, missing low-order point checks,
  AEAD misuse, Python/C disagreement on any vector;
- memory-safety bugs in the C core (`firmware/common/`) reachable from radio input (advertisements, mesh frames);
- ways to **defeat the anti-stalking detector** with standard meshfind firmware;
- server issues: unauthenticated uploads when a token is set, query/DB injection, denial of service.

Known, documented limitations (no need to report, but improvements are welcome): anyone who hears an
advertisement can submit false positions for that epoch; beacon time is unauthenticated; the server sees
which hashes are queried together.

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting**: open the repository's **Security** tab and click
**Report a vulnerability** (https://github.com/coopersimpson101-debug/meshfind/security/advisories/new).
Do not open a public issue, pull request or discussion for an unfixed vulnerability.

Please include:

- a description of the issue and its impact;
- steps to reproduce, ideally a failing test, script or vector;
- the commit hash you tested.

## What to expect

- an acknowledgement within **7 days**;
- an assessment and, if confirmed, a fix plan within **30 days**;
- coordinated disclosure: we agree a publication date with you, normally once a fix is on `main`
  (and, for protocol changes, once the spec and test vectors are updated);
- credit in the advisory and release notes, if you want it.

Thank you for helping keep the project and its users safe.
