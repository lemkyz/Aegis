<div align="center">

<img src="https://raw.githubusercontent.com/lemkyz/Aegis/main/extension/images/icon.png" alt="Aegis" width="112">

# Aegis Security

**Evidence-backed security analysis and fix verification inside VS Code.**

</div>

Aegis keeps the whole security run visible: the scanner evidence, model routes, consensus, threat model, authorization boundary, patch, replay result, policy decision, and integrity hashes.

## Before you start

The extension uses the local Aegis backend. It does not start a hidden service or send product telemetry.

1. Install and start the backend by following the [local setup guide](https://github.com/lemkyz/Aegis#get-started).
2. Keep it bound to `127.0.0.1`; the default extension address is `http://127.0.0.1:8000`.
3. Open a trusted local workspace.
4. Run **Aegis: Run Trusted Analysis** from the Command Palette.

Change the address with the `aegis.backendUrl` setting if your local service uses another port.

## Trusted Analysis

Trusted Analysis runs the production security-task graph and opens one report containing:

- deterministic scanner coverage
- primary and verifier model provenance
- consensus-backed findings
- a repository-aware threat model
- the final `ALLOW`, `REVIEW`, or `BLOCK` decision
- project security-memory changes
- append-only audit events
- verified source, plan, audit, and artifact-manifest hashes

Aegis checks that the returned source digest still matches the saved file before it displays the result. Incomplete scanner coverage, missing verification, repository drift, cancellation, and timeout remain visible and cannot become a clean baseline.

## Main commands

| Command | Use it for |
|---|---|
| **Aegis: Run Trusted Analysis** | Full evidence, model, threat, memory, and policy workflow |
| **Aegis: Fast Scan Current File** | Deterministic checks on the active file |
| **Aegis: Scan Entire Workspace** | Repository-wide static coverage |
| **Aegis: Deep Analysis Selected Code** | Model-backed review with provenance |
| **Aegis: Preview Security Task Plan** | Inspect the task graph without executing it |
| **Aegis: Run Authorized Dynamic Baseline** | Confirm behavior inside the local sandbox |
| **Aegis: Apply Secure Fix** | Review, apply, rescan, and replay a proposed fix |
| **Aegis: Scan Dependencies** | Check supported lockfiles against OSV |

Commands that read or validate repository code are disabled in untrusted and virtual workspaces.

## What a verdict means

- `VERIFIED`: the configured checks passed and the authorized baseline no longer reproduces.
- `PARTIAL`: available checks passed, but complete proof is missing.
- `FAILED`: the issue remains, a check failed, or the run could not support a trustworthy conclusion.

Aegis never treats a blocked, failed, cancelled, or timed-out validation as proof that code is safe.

## Support and security

- [Documentation and source](https://github.com/lemkyz/Aegis)
- [Report a bug](https://github.com/lemkyz/Aegis/issues)
- [Security policy](https://github.com/lemkyz/Aegis/security/policy)
- [Release history](https://github.com/lemkyz/Aegis/releases)

Use dynamic validation only on code and systems you own or are explicitly authorized to test.
