# GitHub Action

The Aegis GitHub Action is a thin public wrapper around the versioned proprietary runtime.

It does **not** install the private Aegis engine source.

```yaml
name: Aegis

on:
  pull_request:

jobs:
  aegis:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4
      - uses: lemkyz/Aegis@main
```

The current developer preview targets Linux x64 GitHub-hosted runners.

The Action downloads the pinned runtime release, verifies its SHA-256 digest, places the runtime on `PATH`, and invokes the public PR gate wrapper.
