#!/usr/bin/env node
import { runCli, list, UsageError } from '../src/cli-core.js';
import { check, TOOL } from '../src/index.js';

const HELP = `securitytxt-sentinel {VERSION} — validate security.txt (RFC 9116) and robots.txt

Usage: securitytxt-sentinel <domain|url|file> [...] [options]

Domains and URLs are fetched over HTTPS: /.well-known/security.txt (falling back to /security.txt)
and /robots.txt. Local files are linted directly (names containing "robots" are read as robots.txt).

      --no-robots            Skip robots.txt
      --kind <k>             Treat local files as "security" or "robots"
      --canonical <url>      Expected Canonical URL when linting a local security.txt
      --warn-days <n>        Warn when Expires is closer than this (default 30)
      --timeout <ms>         Per-request timeout (default 10000)
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { 'no-robots': { type: 'boolean' }, kind: { type: 'string' }, canonical: { type: 'string' }, 'warn-days': { type: 'string' }, timeout: { type: 'string' } },
  async run(o, pos, cfg) {
    const targets = pos.length ? pos : cfg.targets || [];
    if (!targets.length) throw new UsageError('No domain, URL or file given');
    if (o.kind && !['security', 'robots'].includes(o.kind)) throw new UsageError('--kind must be security or robots');
    const num = (v, n) => { if (v === undefined) return undefined; const x = Number(v); if (!Number.isFinite(x) || x < 0) throw new UsageError(`--${n} must be a number`); return x; };
    return check(targets, { robots: !(o['no-robots'] ?? cfg.noRobots), kind: o.kind, canonicalUrl: o.canonical, warnDays: num(o['warn-days'], 'warn-days') ?? cfg.warnDays, timeout: num(o.timeout, 'timeout') ?? cfg.timeout, allow: cfg.allow, severity: cfg.severity });
  },
});
