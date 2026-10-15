#!/usr/bin/env node
import { runCli, list, UsageError } from '../src/cli-core.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { check, TOOL, generateSecurityTxt, signSecurityTxt } from '../src/index.js';

const HELP = `securitytxt-sentinel {VERSION} — validate security.txt (RFC 9116) and robots.txt

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
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { 'no-robots': { type: 'boolean' }, kind: { type: 'string' }, canonical: { type: 'string' }, 'warn-days': { type: 'string' }, timeout: { type: 'string' }, subdomains: { type: 'string', multiple: true }, 'subdomains-file': { type: 'string' }, contact: { type: 'string', multiple: true }, expires: { type: 'string' }, encryption: { type: 'string', multiple: true }, policy: { type: 'string', multiple: true }, acknowledgments: { type: 'string', multiple: true }, hiring: { type: 'string', multiple: true }, csaf: { type: 'string', multiple: true }, 'preferred-languages': { type: 'string' }, sign: { type: 'boolean' }, 'gpg-key': { type: 'string' }, output: { type: 'string', short: 'o' } },
  async run(o, pos, cfg) {
    if (pos[0] === 'generate') {
      let text;
      try { text = generateSecurityTxt({ contact: o.contact ?? cfg.contact, expires: o.expires ?? cfg.expires, canonical: o.canonical ?? cfg.canonical, encryption: o.encryption ?? cfg.encryption, policy: o.policy ?? cfg.policy, acknowledgments: o.acknowledgments ?? cfg.acknowledgments, hiring: o.hiring ?? cfg.hiring, csaf: o.csaf ?? cfg.csaf, preferredLanguages: o['preferred-languages'] ?? cfg.preferredLanguages }); } catch (e) { throw new UsageError(`generate: ${e.message}`); }
      if (o.sign) { try { text = signSecurityTxt(text, { key: o['gpg-key'] }); } catch (e) { throw new UsageError(e.message); } }
      if (o.output) { writeFileSync(o.output, text); return { output: `wrote ${o.output}\n`, exit: 0 }; }
      return { output: text, exit: 0 };
    }
    let subdomains = [...list(o.subdomains), ...(cfg.subdomains || [])];
    if (o['subdomains-file']) { try { subdomains.push(...readFileSync(o['subdomains-file'], 'utf8').split(/\r?\n/).map((x) => x.trim()).filter((x) => x && !x.startsWith('#'))); } catch (e) { throw new UsageError(`Cannot read ${o['subdomains-file']}: ${e.code || e.message}`); } }
    const targets = pos.length ? pos : cfg.targets || [];
    if (!targets.length) throw new UsageError('No domain, URL or file given');
    if (o.kind && !['security', 'robots'].includes(o.kind)) throw new UsageError('--kind must be security or robots');
    const num = (v, n) => { if (v === undefined) return undefined; const x = Number(v); if (!Number.isFinite(x) || x < 0) throw new UsageError(`--${n} must be a number`); return x; };
    return check(targets, { robots: !(o['no-robots'] ?? cfg.noRobots), kind: o.kind, canonicalUrl: o.canonical, warnDays: num(o['warn-days'], 'warn-days') ?? cfg.warnDays, timeout: num(o.timeout, 'timeout') ?? cfg.timeout, allow: cfg.allow, severity: cfg.severity, subdomains });
  },
});
