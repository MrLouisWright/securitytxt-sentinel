# Changelog

## 1.0.0 - 2026-10-14

### Added before first publish

- `generate` subcommand and `generateSecurityTxt()` / `resolveExpires()`: build an RFC 9116 file (Contact, Expires as `365d`/date, Canonical, Encryption, Policy, ...) that passes the linter.
- `--sign` / `signSecurityTxt()`: clear-sign with the local gpg CLI (`--gpg-key` picks the key).
- `summary.expiresInDays` on every target, and an `expires-in-days` GitHub Action output; opt-in reminder workflow in `docs/examples/expiry-reminder.yml`.
- `--subdomains` / `--subdomains-file` (config `subdomains`): each subdomain is checked for its own security.txt; robots.txt stays limited to the main targets.

### Packaging

- Dual ESM + CommonJS: `import` loads `src/`, `require` loads a bundled `dist/index.cjs`, via package.json `exports`.
- TypeScript declarations are generated from the source (`dist/types`) instead of hand-written.
- CI runs build, tests and a require+import check on Node 18/20/22; releases use `npm publish --provenance`.

- First release: security.txt (RFC 9116) and robots.txt checker for live domains and local files, with 32 rules.
- Text, JSON, SARIF and Markdown output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
