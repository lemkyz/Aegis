# Public-site release readiness

## Passed in this environment

- [x] Static source security gate
- [x] Static accessibility structure gate
- [x] JavaScript syntax check
- [x] No third-party scripts
- [x] No third-party analytics
- [x] No iframe
- [x] No server-side form target
- [x] No login/database/session surface
- [x] Strict static security-header policy prepared
- [x] Standalone homepage preview generated
- [x] Preview has one H1, no duplicate IDs, and no images without alt text
- [x] Real public-repository capture included
- [x] Reduced-motion behavior preserved

## Blocked by environment / launch state

- [ ] `package-lock.json` — internal package registry does not expose the required Astro check package
- [ ] `npm audit`
- [ ] `astro check`
- [ ] real Astro production build
- [ ] external Lighthouse
- [ ] external axe/Accessibility Insights
- [ ] OWASP ZAP baseline
- [ ] Mozilla Observatory / SecurityHeaders validation
- [ ] production DNS + HTTPS validation
- [ ] public contact/security email activation

## Product-capture gate

The current site uses evidence-backed representative UI for product explanation and one real public GitHub repository capture. Before the flagship public launch, use redacted current-release captures for VS Code, GitHub Action, and CLI wherever the real product UI is visually ready. Do not fabricate screenshots or edit findings into a state the product did not produce.
