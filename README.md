# securitytxt-sentinel

[![npm version](https://img.shields.io/npm/v/securitytxt-sentinel.svg)](https://www.npmjs.com/package/securitytxt-sentinel) [![CI](https://github.com/MrLouisWright/securitytxt-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/securitytxt-sentinel/actions/workflows/ci.yml) [![Node](https://img.shields.io/node/v/securitytxt-sentinel.svg)](https://nodejs.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![provenance](https://img.shields.io/badge/npm-provenance-blue)](https://docs.npmjs.com/generating-provenance-statements)

> Validate security.txt (RFC 9116) and robots.txt for your domains, or as local files in CI before you deploy them.

`securitytxt-sentinel` fetches `/.well-known/security.txt` (falling back to the legacy `/security.txt`) and `/robots.txt` for each domain and checks them against RFC 9116 and common robots.txt mistakes. It catches the classic failure: a security.txt whose `Expires` passed months ago, so researchers are told to ignore it. Local files can be linted too, so a broken security.txt never ships. CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**.

## What it checks

- **security.txt**: present at the right location, served over HTTPS as `text/plain; charset=utf-8`, not an HTML soft-404, redirects that leave the host, required `Contact` and `Expires`, `Expires` that is invalid, expired, about to expire (`--warn-days`, default 30) or more than a year ahead, duplicate fields, `Contact` values that are not `mailto:`/`tel:`/`https:` URIs, `http://` URIs, `Canonical` missing or not matching the fetched URL, bad `Preferred-Languages` tags, malformed PGP cleartext signatures, unknown fields and invalid lines.
- **robots.txt**: missing file, HTML soft-404, invalid directives, rules before any `User-agent`, sitemaps that are relative or `http://`, files over Google's 500 KiB limit, `Disallow: /` for everyone, and `Disallow` lines that advertise sensitive areas (`/admin`, `/backup`, `/.git`, `/phpmyadmin`…). robots.txt is public and is not access control.

Unreachable hosts (DNS, connection or TLS failures) exit with code 2.

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `missing` | high | No security.txt at /.well-known/security.txt |
| `soft-404` | high | security.txt URL returns HTML or an error page instead of the file |
| `not-https` | high | security.txt is not served over HTTPS |
| `missing-contact` | high | No Contact field (required) |
| `missing-expires` | high | No Expires field (required) |
| `expired` | high | Expires date is in the past |
| `invalid-expires` | high | Expires is not an RFC 3339 date-time |
| `expires-soon` | medium | Expires within the warning window (default 30 days) |
| `expires-too-far` | low | Expires is more than a year ahead (RFC 9116 recommends less) |
| `legacy-location` | low | Only served at /security.txt, not /.well-known/security.txt |
| `content-type` | medium | Content-Type is not text/plain |
| `missing-charset` | low | Content-Type has no charset=utf-8 |
| `duplicate-field` | medium | Field that may appear once appears more than once |
| `invalid-contact` | medium | Contact is not a mailto:, tel: or https: URI |
| `insecure-uri` | medium | Web URI uses http:// instead of https:// |
| `canonical-mismatch` | medium | Fetched URL is not listed in Canonical |
| `missing-canonical` | low | No Canonical field |
| `invalid-line` | medium | Line is not a comment or "Field: value" |
| `invalid-language` | low | Preferred-Languages has an invalid language tag |
| `signature-malformed` | medium | PGP cleartext signature is incomplete |
| `redirect-offsite` | medium | security.txt redirects to a different host |
| `unknown-field` | info | Field not defined by RFC 9116 |
| `unsigned` | info | security.txt is not PGP-signed |
| `robots-missing` | info | No robots.txt |
| `robots-soft-404` | low | robots.txt URL returns HTML |
| `robots-sensitive-path` | low | robots.txt advertises a sensitive path (admin, backups, config…) |
| `robots-invalid-line` | low | robots.txt line is not a valid directive |
| `robots-rule-before-agent` | low | Allow/Disallow before any User-agent line |
| `robots-sitemap-insecure` | low | Sitemap is relative or uses http:// |
| `robots-too-large` | low | robots.txt is larger than 500 KiB (crawlers ignore the rest) |
| `robots-blocks-all` | info | User-agent: * is disallowed from the whole site |
| `fetch-error` | high | Could not fetch the file (network, TLS or HTTP error) |

## Install and run

```bash
npx securitytxt-sentinel example.com www.example.org
npx securitytxt-sentinel example.com --no-robots --warn-days 60 --fail-on medium
npx securitytxt-sentinel public/.well-known/security.txt --canonical https://example.com/.well-known/security.txt
npx securitytxt-sentinel public/robots.txt
```

Run it on a schedule against production so you hear about an expiring `Expires` before researchers do.

## Library

```js
import { check, exitCode } from 'securitytxt-sentinel';
const report = await check(['example.com'], { warnDays: 45 });
console.log(report.targets[0].summary.expires);
process.exitCode = exitCode(report, 'high');
```

## Options

Full CLI reference (`securitytxt-sentinel --help`):

```text
securitytxt-sentinel 1.0.1 — validate security.txt (RFC 9116) and robots.txt

Usage: securitytxt-sentinel <domain|url|file> [...] [options]

Domains and URLs are fetched over HTTPS: /.well-known/security.txt (falling back to /security.txt)
and /robots.txt. Local files are linted directly (names containing "robots" are read as robots.txt).

      --no-robots            Skip robots.txt
      --kind <k>             Treat local files as "security" or "robots"
      --canonical <url>      Expected Canonical URL when linting a local security.txt
      --warn-days <n>        Warn when Expires is closer than this (default 30)
      --timeout <ms>         Per-request timeout (default 10000)
      --subdomains <list>    Also check security.txt on these subdomains (e.g. www,api,shop); repeatable
      --subdomains-file <f>  Subdomains, one per line

Generate
  securitytxt-sentinel generate --contact <mailto:|https:|email> [--expires 365d|<date>] [--canonical <url>]
      [--encryption <url>] [--policy <url>] [--acknowledgments <url>] [--hiring <url>] [--csaf <url>]
      [--preferred-languages en,fr] [--sign [--gpg-key <id>]] [-o <file>]
  Prints (or writes) a valid RFC 9116 security.txt; --sign clear-signs it with your local gpg key.
Policy and output
  -c, --config <file>        JSON config (default .securitytxt-sentinel.json if present)
  -f, --format <fmt>         text (default) | json | sarif | markdown
      --json/--sarif/--markdown <file>  Also write that format to a file
      --fail-on <sev>        critical | high | medium | low | info | none (default high)
      --list-rules           Print rules and default severities
      --no-color             Disable colours
  -v, --version / -h, --help

Exit codes: 0 = passed, 1 = findings at or above --fail-on, 2 = usage error or a target could not be checked.
```

## Configuration

Put a `.securitytxt-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "high",
  "severity": { "expires-too-far": "high" },
  "allow": [
    { "rule": "expires-too-far", "match": "https://example.com*", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `expires-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/securitytxt-sentinel@v1
    with:
      targets: 'example.com'
      fail-on: high
      sarif: securitytxt-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: securitytxt-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `skip-robots`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b) or [GitHub Sponsors](https://github.com/sponsors/MrLouisWright). It helps keep these tools maintained, documented and free for everyone.

[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/MrLouisWright)

## Credit (optional)

Free to use under MIT, no attribution required. If securitytxt-sentinel helps you, a link back is appreciated:

```html
<a href="https://louiswright.co.uk">Built with securitytxt-sentinel by Louis Wright</a>
```

```markdown
[![Built with securitytxt-sentinel by Louis Wright](https://img.shields.io/badge/built%20with-securitytxt--sentinel-blue)](https://louiswright.co.uk)
```

## Generate and sign

```sh
npx securitytxt-sentinel generate --contact security@example.com --expires 365d \
  --canonical https://example.com/.well-known/security.txt --policy https://example.com/disclosure \
  --sign --gpg-key security@example.com -o .well-known/security.txt
```

Contacts without a scheme become `mailto:`. The output is linted before it is written, and `--sign` clear-signs it with your local `gpg`.

## Subdomains

`--subdomains www,api,shop` (or `--subdomains-file subs.txt`) also checks `https://<sub>.<domain>/.well-known/security.txt`, because each host should publish its own file (RFC 9116 section 3).

## Expiry reminder (opt-in)

The Action sets `expires-in-days`, the fewest days left on any checked file. [docs/examples/expiry-reminder.yml](docs/examples/expiry-reminder.yml) runs weekly and opens an issue when fewer than 30 days remain. Nothing happens unless you copy it in.

## Module formats and types

Ships ESM (`import`) and a bundled CommonJS build (`require`), with TypeScript declarations generated from the source:

```js
import * as lib from 'securitytxt-sentinel';      // ESM
const lib = require('securitytxt-sentinel');      // CommonJS
```

Tests live in [`test/`](test) and run on Node 18, 20 and 22 in [GitHub Actions](https://github.com/MrLouisWright/securitytxt-sentinel/actions/workflows/ci.yml), including a require+import check. Releases are published with `npm publish --provenance`.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
