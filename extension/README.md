![Aegis — Security claims need proof](https://aegistrustlayer.com/og/aegis-og.png)

# Aegis Security

### Evidence-backed security for AI-generated software — inside VS Code.

[Website](https://aegistrustlayer.com) ·
[Source](https://github.com/lemkyz/Aegis) ·
[Security](https://aegistrustlayer.com/security) ·
[Research](https://aegistrustlayer.com/research) ·
[Releases](https://github.com/lemkyz/Aegis/releases)

**Security claims need proof.**

Aegis treats a security finding as a claim, not a conclusion. It connects deterministic evidence, model provenance, independent verification, threat context, controlled remediation, policy decisions, and persistent project memory in one reviewable workflow.

A finding is not proof.
A generated patch is not verification.
A model does not certify its own security-sensitive work.

---

## From alert to security decision

| Stage | What Aegis preserves |
| --- | --- |
| **Find** | Deterministic scanner evidence and exact source locations |
| **Explain** | Claim context, repository-aware threat model, impact, and provenance |
| **Verify** | Primary and independent verifier routes with visible consensus |
| **Authorize** | Explicit boundaries before any controlled dynamic validation |
| **Remediate** | Reviewable patch bound to the source and patch digest |
| **Re-verify** | Project checks, static rescan, and authorized baseline replay |
| **Decide** | `ALLOW`, `REVIEW`, or `BLOCK` from explicit policy |
| **Remember** | Audit records, integrity hashes, and project security memory |

The result is not “AI says secure.” It is a chain of evidence that can be inspected after the run.

---

## Trusted Analysis

**Aegis: Run Trusted Analysis** executes the production security-task graph and opens one report containing:

- deterministic scanner coverage
- primary and verifier model provenance
- consensus-backed findings
- repository-aware threat context
- final `ALLOW`, `REVIEW`, or `BLOCK` policy decision
- project security-memory changes
- append-only audit events
- source, plan, audit, and artifact-manifest integrity checks

Aegis checks that the analyzed source digest still matches the saved file before presenting the result. Repository drift, incomplete coverage, missing verification, cancellation, and timeout remain visible instead of becoming a clean baseline.

### Observed `0.2.0` fixture run

The checked-in vulnerable SQL fixture was exercised with the packaged public-preview workflow.

| Result | Observed value |
| --- | --- |
| Deterministic evidence | Semgrep + Bandit |
| Primary review | `openai/gpt-oss-20b` |
| Independent verifier | `mistralai/mistral-medium-3.5-128b` |
| Consensus | Confirmed · 99% confidence |
| Policy | `REVIEW` · risk 75/100 |
| Task graph | 8 completed · 0 failed · 0 blocked |
| Integrity | Source, plan, audit, and artifact manifest verified |
| Memory | New confirmed claim stored in the local project snapshot |

This is a reproducible fixture result, **not** a general accuracy or performance claim. `REVIEW` is the expected outcome because the fixture contains an active high-severity SQL injection claim.

---

## Fix & Prove

Aegis does not stop when a patch is generated.

A secure-fix workflow can:

1. bind the proposed change to the reviewed source selection
2. show the patch before writing
3. revalidate source and patch identity
4. apply the change transactionally
5. run project checks
6. rescan the target finding
7. replay an explicitly authorized baseline when available
8. classify the result as `VERIFIED`, `PARTIAL`, or `FAILED`

`VERIFIED` requires the configured proof conditions to pass. A blocked, failed, cancelled, or timed-out validation never becomes evidence that code is safe.

---

## What you can do from VS Code

| Command | Purpose |
| --- | --- |
| **Aegis: Run Trusted Analysis** | Full evidence, model, threat, memory, integrity, and policy workflow |
| **Aegis: Fast Scan Selected Code** | Deterministic checks on the current selection |
| **Aegis: Fast Scan Current File** | Deterministic checks on the active file |
| **Aegis: Scan Entire Workspace** | Repository-wide static coverage |
| **Aegis: Scan Uncommitted Changes** | Inspect current Git working-tree changes |
| **Aegis: Scan Staged Changes** | Inspect staged changes before commit |
| **Aegis: Deep Analysis Selected Code** | Model-backed review with provenance |
| **Aegis: Map Attack Surface** | Repository-aware attack-surface analysis |
| **Aegis: Generate Threat Model** | Build threat context from the repository |
| **Aegis: Preview Security Task Plan** | Inspect the task graph without executing it |
| **Aegis: Run Authorized Dynamic Baseline** | Confirm behavior inside the controlled local sandbox |
| **Aegis: Apply Secure Fix** | Review, apply, rescan, and verify a proposed fix |
| **Aegis: Scan Dependencies** | Check supported lockfiles against OSV |

Repository-reading and validation commands are disabled in untrusted and virtual workspaces.

---

## Install

Install from the Visual Studio Marketplace or from the command line:

```bash
code --install-extension aegis-security.aegis-security
```

Aegis uses a **local backend**. The extension does not silently start a hidden service.

### Local backend

Requirements:

- Python 3.14
- Semgrep
- Podman or Docker only for explicitly authorized dynamic validation

```bash
git clone https://github.com/lemkyz/Aegis.git
cd Aegis/backend

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

export AEGIS_FINGERPRINT_KEY="$(
  python -c 'import secrets; print(secrets.token_urlsafe(48))'
)"

uvicorn aegis.main:app --host 127.0.0.1 --port 8000
```

Then open a trusted local workspace and run:

**Aegis: Run Trusted Analysis**

The default backend address is `http://127.0.0.1:8000`. Change it with `aegis.backendUrl` if needed.

[Full setup and architecture](https://github.com/lemkyz/Aegis#local-setup)

---

## Local-first trust boundaries

Aegis is deliberately explicit about what happens to source code.

**No product telemetry.**
The VS Code workflow does not include Aegis product telemetry.

**Local deterministic path.**
Static analysis, policy evaluation, project security memory, and audit records can remain local.

**Model routes are deliberate.**
When model-backed review is enabled, Aegis sends the configured provider only the source context and evidence required for that request after the secret-redaction boundary. The report records which provider and model handled each role.

**Dynamic validation is never implicit.**
Controlled validation requires explicit authorization and uses a local container boundary with read-only repository/root mounts, networking disabled by default, dropped Linux capabilities, `no-new-privileges`, an unprivileged user, and bounded resources.

**Fixes are bound to evidence.**
Aegis binds a secure fix to the reviewed source and patch digest, revalidates both before writing, and avoids overwriting newer user work during rollback.

Use dynamic validation only on code and systems you own or are explicitly authorized to test.

---

## Verification and policy are different

### Verification

- `VERIFIED` — required checks passed, the target finding disappeared, no configured regression appeared, and an authorized baseline no longer reproduces when required.
- `PARTIAL` — available checks passed, but the evidence is insufficient for a verified claim.
- `FAILED` — the issue remains, a required check failed, a regression appeared, or the workflow could not support a trustworthy conclusion.

### Policy

- `ALLOW` — configured policy accepts the current evidence and risk.
- `REVIEW` — a person must resolve an active claim, incomplete evidence, or policy threshold.
- `BLOCK` — a blocking condition exists or a required trust boundary could not be preserved.

Aegis keeps these states separate on purpose.

---

## Built for the path from AI code to autonomous software

The current public preview applies the Aegis trust model to software security through VS Code, GitHub Actions, CLI, and a local orchestration backend.

The broader direction is **trust infrastructure for software agents**: permissioned actions, least privilege, evidence, independent verification, recoverability, policy, and memory.

The public extension is the developer surface of that system.

---

## Open source

Aegis is open source under **Apache-2.0**.

- [Website](https://aegistrustlayer.com)
- [GitHub](https://github.com/lemkyz/Aegis)
- [Security policy](https://github.com/lemkyz/Aegis/security/policy)
- [Report a bug](https://github.com/lemkyz/Aegis/issues)
- [Release history](https://github.com/lemkyz/Aegis/releases)
- [Contact](mailto:hello@aegistrustlayer.com)
- [Security contact](mailto:security@aegistrustlayer.com)

---

`0.2.x` is a public preview. Interfaces may change before `1.0`; evaluate the current release on local or non-production repositories first.
