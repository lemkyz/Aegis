<p align="center"><img src="assets/icon.png" alt="Aegis" width="112"></p>
<h1 align="center">AEGIS</h1>

<p align="center"><strong>Trust infrastructure for software agents.</strong></p>
<p align="center"><strong>Security claims need proof.</strong></p>

<p align="center">
[![VS Code Marketplace](https://img.shields.io/badge/VS%20Code-Marketplace-007ACC?logo=visualstudiocode&logoColor=white)](https://marketplace.visualstudio.com/items?itemName=aegis-security.aegis-security)
![Release](https://img.shields.io/badge/release-v0.2.1-111111)
![Status](https://img.shields.io/badge/status-preview-C49A45)
</p>

---

Aegis helps developers evaluate security-sensitive software changes with
evidence instead of trusting a claim at face value.

## Find → Prove → Fix → Verify

| Find | Prove | Fix | Verify |
|---|---|---|---|
| Surface security-sensitive behavior. | Attach concrete evidence to the claim. | Prepare a constrained remediation. | Check the result independently. |

## Why Aegis

AI can generate a patch and say it succeeded. That is not enough for a
security-sensitive change.

> A security claim is not trusted simply because the system that produced the
> change says it is correct.

Aegis keeps findings, remediation, and verification visibly separate so teams
can make decisions from evidence rather than confidence alone.

## Developer surfaces

**VS Code** — inspect findings, review evidence, apply approved fixes, and see
verification results without leaving the editor.

**CLI** — bring Aegis into local developer workflows and automation.

**GitHub** — use Aegis as a verification gate around changes before they ship.

This repository is the public product-facing home for Aegis. The proprietary
analysis and verification engine is distributed separately and is not included
here.

## Install

Install Aegis from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=aegis-security.aegis-security).

CLI and GitHub integration distribution will be documented here as their public
release surfaces are finalized.

## What a result should answer

- **What is the claim?**
- **What evidence supports it?**
- **What changed?**
- **Was the fix checked independently?**
- **What remains uncertain?**

Aegis is designed so unavailable, partial, or inconclusive verification does
not silently become a clean result.

## Releases

User-facing releases will be published through
[GitHub Releases](../../releases).

Current product version: **v0.2.1**.

## Security

Do not publish suspected vulnerabilities in public issues. See
[SECURITY.md](SECURITY.md).

## Support

For installation and product questions, see [SUPPORT.md](SUPPORT.md).

## Repository scope

This repository intentionally contains the public Aegis product surface:
documentation, release information, integration guidance, examples, and
public-facing assets.

It intentionally does **not** contain Aegis's proprietary security engine or
private implementation.

---

<p align="center"><strong>AEGIS</strong><br>Security claims need proof.</p>
