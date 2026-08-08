# Final website release checklist

## Passed in the artifact environment

- `npm run security:gate`
- `npm run a11y:gate`
- `node --check public/scripts/site.js`
- standalone preview structural validation:
  - one page H1
  - no duplicate IDs
  - Research anchor present
  - 4 pricing plans
  - 3 interactive product surfaces
  - 4 security-boundary states
  - 3 repository views
  - 5 contact routes
  - command palette present
  - release drawer present
  - 6 lifecycle rail links present
  - no remote scripts
  - no iframes

## Must run on the real public registry / production domain

1. `npm install`
2. `npm audit --omit=dev`
3. `npm run check`
4. `npm run build`
5. deploy static `dist/`
6. verify DNS + TLS + redirect behavior on `aegistrustlayer.com`
7. Lighthouse: Performance / Accessibility / Best Practices / SEO
8. Mozilla Observatory
9. SecurityHeaders
10. OWASP ZAP baseline against the production origin
11. verify `/.well-known/security.txt`
12. verify Marketplace/GitHub/contact links from desktop and mobile

No release should be described as “zero vulnerabilities guaranteed.” The target is a deliberately minimal public attack surface with no known high/critical issues after the production checks above.
