# Aegis Runtime

The Aegis security engine is distributed as a proprietary local runtime.

The current developer preview supports **Linux x64**.

## Download

Use the latest runtime release:

- `aegis-runtime-linux-x64.tar.gz`
- `SHA256SUMS`

## Verify

```bash
sha256sum --check SHA256SUMS
```

Do not run an artifact that fails verification.

## Start

```bash
tar -xzf aegis-runtime-linux-x64.tar.gz

export AEGIS_FINGERPRINT_KEY="$(
  python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
)"

./aegis_runtime.dist/aegis-runtime   serve   --host 127.0.0.1   --port 8000
```

Health:

```bash
curl http://127.0.0.1:8000/health
```

The runtime refuses non-loopback bind addresses.

Model credentials are not required for runtime startup or `/health`. A configured model-backed workflow validates its provider credentials when that workflow actually needs them.

The public runtime archive contains the compiled standalone runtime, not the private Aegis Python source tree.
