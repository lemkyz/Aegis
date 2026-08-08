# Security Policy

Aegis handles source code, vulnerability evidence, local validation plans, and security-related execution results. Security reports are taken seriously.

## Reporting a vulnerability

Please do not open a public GitHub issue for a vulnerability that could put users, repositories, credentials, or local systems at risk.

Report security issues privately through GitHub's private vulnerability reporting feature when it is available for this repository.

A useful report should include:

- the affected component
- the observed behavior
- the expected security boundary
- clear reproduction steps
- the potential impact
- relevant logs or screenshots
- a proposed mitigation, when available

Do not include real secrets, production credentials, private source code, or data belonging to another person or organization.

## Scope

Security reports may include issues involving:

- authorization enforcement
- validation scope bypass
- path traversal
- unsafe container configuration
- sandbox escape conditions
- unintended network access
- command or argument injection
- unsafe filesystem access
- secret exposure
- evidence or report tampering
- incorrect verification verdicts
- extension-to-backend trust boundaries
- dependency vulnerabilities with practical impact

A finding that causes Aegis to incorrectly report a vulnerable patch as `VERIFIED` is considered security-relevant.

## Validation safety

Aegis validation features are intended only for repositories and systems that the operator owns or is explicitly authorized to test.

The validation pipeline is designed around the following boundaries:

- explicit authorization before execution
- declared validation scope
- normalized repository-relative entrypoints
- read-only repository mounts
- read-only container filesystems
- disabled networking by default
- dropped Linux capabilities
- no-new-privileges
- unprivileged container execution
- bounded CPU, memory, process count, runtime, and output
- deterministic before-and-after evidence comparison

A blocked, failed, or timed-out execution must not be interpreted as proof that a vulnerability has been fixed.

## Supported versions

Aegis is currently under active development and has not reached a stable release.

Security fixes are applied to the latest revision of the default branch. Older commits and experimental interfaces may not receive separate patches.

## Disclosure process

After receiving a valid report, the project will aim to:

1. reproduce and assess the issue
2. determine the affected security boundary
3. prepare and verify a fix
4. add regression coverage
5. publish the fix
6. credit the reporter when requested and appropriate

Response times may vary while the project is maintained by a small team.

## Safe research

Good-faith security research is welcome when it:

- stays within systems and repositories you control
- avoids accessing other people's data
- avoids persistence or destructive actions
- avoids service disruption
- stops when an unexpected boundary is crossed
- gives the project reasonable time to investigate before disclosure

Testing against third-party systems without authorization is not permitted.

## Secrets

Never submit API keys, access tokens, private keys, passwords, session cookies, production configuration, or proprietary source code in an issue or report.

Revoke and rotate any secret that may have been exposed.

## Security contact

Please do not disclose vulnerabilities in public GitHub issues. Report them privately to **security@aegistrustlayer.com** with the affected version or commit, reproduction steps, impact, and safe supporting evidence.
