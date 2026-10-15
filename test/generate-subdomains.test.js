import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecurityTxt, signSecurityTxt, resolveExpires, check } from '../src/index.js';
import { lintSecurityTxt } from '../src/securitytxt.js';

const now = '2026-01-01T00:00:00Z';
const bin = new URL('../bin/securitytxt-sentinel.js', import.meta.url).pathname;

test('resolveExpires handles durations and dates', () => {
  assert.equal(resolveExpires('30d', new Date(now)), '2026-01-31T00:00:00Z');
  assert.equal(resolveExpires('1y', new Date(now)), '2027-01-01T00:00:00Z');
  assert.equal(resolveExpires('2026-06-01', new Date(now)), '2026-06-01T00:00:00Z');
  assert.throws(() => resolveExpires('soon'));
});

test('generateSecurityTxt produces a lint-clean file', () => {
  const t = generateSecurityTxt({ contact: ['security@example.com', 'https://example.com/report'], expires: '180d', canonical: 'https://example.com/.well-known/security.txt', policy: 'https://example.com/policy', preferredLanguages: 'en,fr', now });
  assert.match(t, /^Contact: mailto:security@example.com$/m);
  assert.match(t, /^Preferred-Languages: en, fr$/m);
  const errs = lintSecurityTxt(t, { now, url: 'https://example.com/.well-known/security.txt' }).raw.filter((f) => f.rule !== 'unsigned');
  assert.deepEqual(errs.map((f) => f.rule), []);
  assert.throws(() => generateSecurityTxt({}), /Contact/);
  assert.throws(() => generateSecurityTxt({ contact: 'http://insecure.example/x', now }));
});

test('generate subcommand writes a file', () => {
  const d = mkdtempSync(join(tmpdir(), 'sts-'));
  const r = spawnSync(process.execPath, [bin, 'generate', '--contact', 'sec@example.com', '-o', join(d, 'security.txt')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(readFileSync(join(d, 'security.txt'), 'utf8'), /Expires: /);
  assert.equal(spawnSync(process.execPath, [bin, 'generate'], { encoding: 'utf8' }).status, 2);
});

const hasGpg = spawnSync('gpg', ['--version']).status === 0;
test('signSecurityTxt clear-signs with gpg', { skip: !hasGpg && 'gpg not installed' }, () => {
  const home = mkdtempSync(join(tmpdir(), 'gpg-'));
  const g = spawnSync('gpg', ['--homedir', home, '--batch', '--passphrase', '', '--quick-gen-key', 'Test <t@example.com>', 'ed25519', 'sign', '1d'], { encoding: 'utf8' });
  assert.equal(g.status, 0, g.stderr);
  const signed = signSecurityTxt(generateSecurityTxt({ contact: 't@example.com', now: new Date().toISOString() }), { homedir: home });
  assert.match(signed, /BEGIN PGP SIGNED MESSAGE/);
  assert.ok(!lintSecurityTxt(signed, {}).raw.some((f) => f.rule === 'unsigned'));
  assert.throws(() => signSecurityTxt('x', { gpg: 'definitely-not-gpg' }), /not installed/);
});

test('subdomains get their own security.txt check and expiresInDays', async () => {
  const good = generateSecurityTxt({ contact: 's@example.com', expires: '40d', now, comment: false });
  const seen = [];
  const fetch = async (url) => {
    seen.push(String(url));
    const u = new URL(url);
    if (u.hostname === 'example.com' && u.pathname === '/.well-known/security.txt') return { status: 200, body: good, url: String(url), chain: [String(url)], contentType: 'text/plain; charset=utf-8' };
    return { status: 404, body: 'nope', url: String(url), chain: [String(url)], contentType: 'text/plain' };
  };
  const rep = await check(['https://example.com'], { fetch, now, subdomains: ['www', 'api'], robots: false });
  const ts = rep.targets.map((t) => t.target);
  assert.ok(ts.some((t) => t.includes('www.example.com')) && ts.some((t) => t.includes('api.example.com')), ts.join());
  const main = rep.targets.find((t) => /\/\/example\.com/.test(t.target));
  assert.equal(main.summary.expiresInDays, 40);
  const www = rep.targets.find((t) => t.target.includes('www.'));
  assert.ok(www.findings.length > 0);
  assert.ok(!seen.some((s) => s.includes('www.') && s.endsWith('/robots.txt')));
});
