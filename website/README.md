# Aegis public website

Production-oriented static Astro site for Aegis.

## Stack

- Astro + TypeScript
- Static output
- No remote fonts
- No third-party analytics
- No server-side contact form
- No authentication/database/session runtime
- Minimal client JavaScript for navigation and product interactions

## Local development

```bash
npm install
npm run validate
npm run dev
```

Production requires a committed `package-lock.json` and a successful `npm audit --audit-level=high` in CI.

## Configuration

```bash
PUBLIC_SITE_URL=https://aegistrustlayer.com
PUBLIC_CONTACT_EMAIL=hello@aegistrustlayer.com
PUBLIC_SECURITY_EMAIL=security@aegistrustlayer.com
PUBLIC_FOUNDER_EMAIL=founder@aegistrustlayer.com
PUBLIC_PARTNERSHIPS_EMAIL=partnerships@aegistrustlayer.com
PUBLIC_BILLING_EMAIL=billing@aegistrustlayer.com
```

## GitHub README snapshot

`npm run build` refreshes the public Aegis README and basic repository metadata at build time. The rendered website uses a bounded, sanitized embed copy and keeps checked-in fallbacks so the public site has no runtime GitHub dependency.

## Validation

```bash
npm run security:gate
npm run a11y:gate
npm run check
npm run build
```

Before public launch, also run external Lighthouse, accessibility, security-header, Mozilla Observatory, and OWASP ZAP baseline checks against the deployed domain.

See `RELEASE_READINESS.md`, `SECURITY_CHECKLIST.md`, `PRODUCT_CAPTURE_GUIDE.md`, and `V8_CHANGELOG.md`.
