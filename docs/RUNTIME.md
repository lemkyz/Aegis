# Aegis Runtime

The Aegis security engine is distributed as a proprietary local runtime.

The current public runtime preview provides native x64 artifacts for:

- Linux
- macOS
- Windows

## Managed runtime

For normal VS Code usage, the Aegis extension manages the runtime lifecycle.

The managed runtime flow is designed to:

1. resolve the pinned public runtime release;
2. download the signed v2 runtime manifest;
3. verify the Ed25519 manifest signature;
4. select the artifact for the current supported platform;
5. verify the artifact SHA-256 before extraction;
6. install the runtime into VS Code global storage with restrictive local permissions;
7. start the runtime on loopback;
8. verify Aegis health before reporting the runtime as ready.

The runtime manager does not spawn a shell.

## Current release authority

Runtime releases are published at:

https://github.com/lemkyz/Aegis/releases

The current Aegis 0.2.5 extension runtime authority is:

`v0.2.5-runtime-preview`

The release contains:

- `runtime-manifest.json`
- `runtime-manifest.sig`
- `aegis-runtime-linux-x64.tar.gz`
- `aegis-runtime-darwin-x64.tar.gz`
- `aegis-runtime-win32-x64.tar.gz`

The signed manifest binds each platform artifact to its platform identity, archive name, byte size, SHA-256 digest, and executable path.

## Verification boundary

The managed release path is designed around:

- a pinned public runtime release;
- an Ed25519-signed v2 manifest;
- signature verification before trusting artifact metadata;
- SHA-256 verification before extraction;
- bounded runtime downloads;
- restrictive local installation permissions;
- runtime health verification before readiness.

Missing or invalid release evidence fails closed.

## Local boundary

The managed runtime binds to loopback.

Model credentials are not required merely to start the runtime or answer `/health`. Model-backed workflows use explicitly configured providers when those workflows require them and preserve provider/model provenance.

Controlled dynamic validation requires explicit authorization and should only target systems you own or are explicitly authorized to test.

## Source boundary

The public runtime archives contain compiled standalone runtime artifacts.

They do not publish the private Aegis engine source tree, private orchestration internals, private security intelligence, private rules, or private research implementation.
