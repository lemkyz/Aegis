# Website security launch gate

The goal is not to claim “zero vulnerabilities.” The goal is to keep the public website's runtime surface extremely small, reject known high/critical dependency risk, and verify the deployed boundary independently.

## Architecture gate

- [x] Static Astro output only
- [x] No account/login/authentication
- [x] No database
- [x] No server-side contact form
- [x] No analytics/advertising SDK
- [x] No remote fonts
- [x] No third-party JavaScript
- [x] First-party progressive enhancement only
- [x] No inline event handlers
- [x] No `eval`, `new Function`, `document.write`, or DOM `innerHTML` assignment
- [x] Same-origin CSP for script/style/connect
- [x] `frame-ancestors 'none'` / `X-Frame-Options: DENY`
- [x] HSTS configured for production HTTPS
- [x] restrictive Permissions Policy
- [x] `no-referrer`
- [x] `nosniff`
- [x] COOP/CORP
- [x] RFC 9116 `security.txt` contact path

## CI gate

- [ ] generate and commit `package-lock.json` from the public npm registry; production CI must use `npm ci`

- [ ] Pin third-party GitHub Actions to reviewed full commit SHAs before production launch; keep the human-readable release tag in a comment.

- [ ] `npm ci --ignore-scripts`
- [ ] `npm audit --audit-level=high`
- [x] local source security gate
- [ ] `astro check`
- [ ] production build
- [ ] no source maps in `dist/`

The unchecked build items require the public npm registry; the current sandbox registry does not expose Astro packages.

## Pre-production deployment gate

After `aegistrustlayer.com` is purchased and DNS is connected:

- [ ] HTTPS certificate valid on apex + `www`
- [ ] redirect HTTP → HTTPS
- [ ] choose one canonical host and redirect the other
- [ ] verify CSP from the real response, not just the `_headers` file
- [ ] run Mozilla Observatory
- [ ] run SecurityHeaders.com
- [ ] run OWASP ZAP baseline against the deployed static site
- [ ] run Lighthouse desktop + mobile; target 95+ in all requested categories
- [ ] verify no mixed content
- [ ] verify no unexpected third-party requests in browser network log
- [ ] inspect final HTML for email/address leakage or secrets
- [ ] verify `/security`, `/research`, `/company`, `/.well-known/security.txt`, `/robots.txt`, and `/sitemap.xml`
- [ ] validate OpenGraph/Twitter image rendering
- [ ] manually test keyboard-only navigation
- [ ] manually test 200% zoom and narrow mobile widths
- [ ] manually test `prefers-reduced-motion`

## Product-capture gate

Before sending the site to investors:

- [ ] replace the explicitly marked representative VS Code panel with a screenshot from the shipping extension
- [ ] use a controlled checked-in fixture; never show private code or credentials
- [ ] capture GitHub Action output from a real Aegis workflow if available
- [ ] capture CLI output from a real local run
- [ ] redact local usernames, home paths, tokens, provider keys, repository secrets, and machine-identifying information
- [ ] confirm every visible number can be traced to a real run or clearly labeled illustrative state

## Commercial-content gate

- [ ] business plan approves the initial paid ICP
- [ ] business plan locks the value metric
- [ ] exact plan entitlements exist or are explicitly early-access commitments
- [ ] pricing is enabled with `PUBLIC_PRICING_READY=true`
- [ ] domain email exists before it is shown publicly
