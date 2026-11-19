# 0xFieldbook

An Astro-powered offensive-security fieldbook of training-exam walkthroughs, methodologies, reusable PoCs and troubleshooting notes.

## Repository layout

- `src/` — Astro pages, components, and styles
- `working-vault/` — 40 sanitized Markdown documents
- `scripts/` — post-build flag and endpoint leak checks
- `package-lock.json` — pinned dependencies

Requires **Node.js >=22.22.0** and npm. From the repository root:

```bash
npm ci
npm run check
npm run build
npm run preview
```

The build generates static pages and a Pagefind index in `dist/`. Publish **only** `dist/`, never the repository root or Markdown vault.

## Publication security

This is a clean-history sanitized source snapshot, **not a fork or Git-history transfer**. The historical private endpoint mapping, raw exam flags and old release archives are excluded. Displayed flags use `IT{FLAG-SECRET}`; reported machine completion is participant-confirmed.

The publication gates reject raw exam flag patterns and unexpected globally routable IPv4 addresses; a trusted private CI runner can supply `PRIVATE_ENDPOINT_NEEDLES` (comma-separated) without committing the historical mapping. Source presence does not establish a successful clean build or deployment.
