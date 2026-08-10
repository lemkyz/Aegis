# AEGIS

**Trust infrastructure for software agents.**

**Security claims need proof.**

[Website](https://aegistrustlayer.com) · [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=aegis-security.aegis-security) · [Runtime releases](https://github.com/lemkyz/Aegis/releases) · [Security](SECURITY.md)

---

Software agents can write code, modify repositories, call tools, and propose production changes faster than human review can safely absorb.

Aegis is the trust layer between an agent action and the decision to accept it.

It turns a security-sensitive change into a durable trust record:

**claim → evidence → authorization → remediation → independent verification → policy → memory**

A scanner can tell you that something looks dangerous. Aegis is built to answer the harder question:

> **Can this action be trusted — and can the system show why?**

## Trust model

| Boundary | What Aegis preserves |
|---|---|
| **Claim** | What is being asserted, where, and against which exact source |
| **Evidence** | Deterministic findings, provenance, code locations, and supporting context |
| **Authorization** | What execution or mutation was explicitly permitted |
| **Remediation** | The exact reviewed change and its identity |
| **Verification** | Independent checks that do not let the proposing model certify itself |
| **Policy** | Explicit `ALLOW`, `REVIEW`, or `BLOCK` outcomes |
| **Memory** | Durable security state that survives the current model call or editor session |

Missing proof stays missing. A failed check does not become a clean result. A generated patch does not certify itself.

## Product surfaces

### VS Code

Aegis brings the trust record next to the code: findings, evidence, threat context, authorized validation, Fix & Prove, policy decisions, and project security memory.

[Install Aegis Security](https://marketplace.visualstudio.com/items?itemName=aegis-security.aegis-security)

### Local Aegis Runtime

The Aegis security engine is distributed as a **proprietary local runtime**.

The runtime binds to loopback only. Deterministic analysis, evidence, policy, and project security state can remain local by default.

The current runtime developer preview supports **Linux x64**.

See [Runtime](docs/RUNTIME.md).

### GitHub Action

The public Action is a thin integration surface. It downloads the versioned proprietary runtime, verifies its SHA-256 checksum, and invokes the public PR gate wrapper.

It does **not** install or publish the private Aegis engine source.

See [GitHub Action](docs/GITHUB_ACTION.md).

## Why Aegis is different

### Independent verification

The system that proposes a security-sensitive conclusion or remediation does not get to become the sole authority that certifies it.

### Exact identity

Trust is bound to concrete source, claim, authorization, patch, verification, and outcome identities rather than vague session context.

### Authorization before execution

Reading code is not permission to execute it. Analysis, controlled validation, repository mutation, and external access are different capabilities.

### Fail-closed semantics

Drift, missing evidence, blocked validation, failed verification, cancellation, timeout, and incomplete workflows remain visible.

### Security memory

Aegis is designed to remember what was proven, what changed, what reopened, and what still requires review.

## Fix & Prove

Aegis treats remediation as a security-sensitive transaction:

```text
claim
  ↓
evidence
  ↓
explicit authorization
  ↓
exact remediation identity
  ↓
apply
  ↓
project checks
  ↓
static re-verification
  ↓
authorized replay when required
  ↓
independent verdict
  ↓
commit / rollback / rollback-blocked
  ↓
security memory
```

A patch application is not proof that the original condition disappeared. A model approving its own patch is not independent verification.

## Local-first boundary

Aegis is designed so the developer-facing runtime can operate on the local machine rather than requiring repositories to be uploaded to an Aegis-hosted scanner.

When model-backed review is configured, provider/model provenance stays explicit in the trust record. Controlled dynamic validation remains separately authorized.

## Public surface, private engine

This repository is the **public developer surface** for Aegis:

- product and trust-model documentation;
- integration contracts;
- release artifacts and checksums;
- GitHub Action wrapper;
- examples and brand assets;
- security and support information.

The proprietary engine, orchestration logic, verification internals, model-routing intelligence, private rules, evaluation corpus, and private research implementation are **not published here**.

Public visibility is not an open-source grant. See [LICENSE](LICENSE).

## Developer preview

Aegis is an early developer preview. Interfaces and distribution details can change before 1.0.

The current runtime release targets Linux x64. Use controlled validation only on repositories and systems you own or are explicitly authorized to test.

## Security

Do not report vulnerabilities through a public issue.

See [SECURITY.md](SECURITY.md) or contact **security@aegistrustlayer.com**.

## Company

Aegis is being built toward a broader trust and control layer for autonomous software engineering: permissioned actions, least privilege, evidence, independent verification, recoverability, policy, and durable trust memory.

For design partnerships, enterprise evaluation, research, or investment conversations:

**https://aegistrustlayer.com/contact**

---

**AEGIS — Security claims need proof.**
