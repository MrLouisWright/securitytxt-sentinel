import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { check, lintSecurityTxt, parseSecurityTxt, lintRobots, toOrigin, exitCode } from '../src/index.js';
const F = new URL('./fixtures/', import.meta.url).pathname;
const NOW = '2026-10-14T00:00:00Z';
const rules = (r) => new Set((r.findings || r).map((f) => f.rule));
const GOOD = 'Contact: mailto:a@b.c\nExpires: 2027-06-30T23:59:59Z\nCanonical: URL\n';

let srv, base;
const routes = {};
before(async () => {
  srv = http.createServer((req, res) => {
    const key = req.headers.host.split(':')[0] + req.url; const r = routes[key] || routes[req.url];
    if (!r) { res.writeHead(404); return res.end('nope'); }
    res.writeHead(r.status || 200, r.headers || { 'content-type': 'text/plain; charset=utf-8' }); res.end(r.body || '');
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok)); base = `http://127.0.0.1:${srv.address().port}`;
});
after(() => srv.close());

test('toOrigin', () => { assert.equal(toOrigin('example.com'), 'https://example.com'); assert.equal(toOrigin('https://a.b/x/y?z'), 'https://a.b'); assert.throws(() => toOrigin('ftp://x')); });
test('parse handles PGP cleartext signatures', () => {
  const p = parseSecurityTxt('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:a@b.c\n- -dashed: x\n-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n');
  assert.equal(p.signature.complete, true); assert.equal(p.fields[0].name, 'contact'); assert.equal(p.fields[0].line, 4);
  assert.ok(rules(lintSecurityTxt('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:a@b.c\n', { now: NOW }).raw).has('signature-malformed'));
});
test('good file has only the unsigned note', async () => { const r = await check([F + 'good-security.txt'], { now: NOW }); assert.deepEqual([...rules(r)], ['unsigned']); assert.equal(exitCode(r, 'low'), 0); });
test('bad file', async () => {
  const s = rules(await check([F + 'bad-security.txt'], { now: NOW }));
  for (const k of ['expired', 'duplicate-field', 'insecure-uri', 'invalid-contact', 'invalid-line', 'invalid-language', 'missing-canonical', 'unknown-field']) assert.ok(s.has(k), k);
});
test('expiry windows', () => {
  const r = (e) => rules(lintSecurityTxt(`Contact: mailto:a@b.c\nExpires: ${e}\n`, { now: NOW }).raw);
  assert.ok(r('2026-10-20T00:00:00Z').has('expires-soon'));
  assert.ok(r('2028-10-20T00:00:00Z').has('expires-too-far'));
  assert.ok(r('tomorrow').has('invalid-expires'));
  assert.ok(rules(lintSecurityTxt('Contact: mailto:a@b.c\n', { now: NOW }).raw).has('missing-expires'));
  assert.ok(rules(lintSecurityTxt('Expires: 2027-01-01T00:00:00Z\n', { now: NOW }).raw).has('missing-contact'));
});
test('content type checks', () => {
  assert.ok(rules(lintSecurityTxt(GOOD, { contentType: 'text/html', now: NOW }).raw).has('content-type'));
  assert.ok(rules(lintSecurityTxt(GOOD, { contentType: 'text/plain', now: NOW }).raw).has('missing-charset'));
});
test('robots rules', async () => {
  const s = rules(await check([F + 'robots.txt']));
  for (const k of ['robots-invalid-line', 'robots-rule-before-agent', 'robots-sensitive-path', 'robots-sitemap-insecure']) assert.ok(s.has(k), k);
  assert.ok(rules(lintRobots('User-agent: *\nDisallow: /\n').raw).has('robots-blocks-all'));
  assert.equal(lintRobots('User-agent: *\nDisallow: /search\nSitemap: https://x/s.xml\n').raw.length, 0);
});
test('fetched site: legacy location, http, canonical mismatch, robots', async () => {
  routes['/security.txt'] = { body: GOOD.replace('URL', 'https://example.com/.well-known/security.txt') };
  routes['/robots.txt'] = { body: 'User-agent: *\nDisallow: /wp-admin/\n' };
  const r = await check([base], { now: NOW });
  const s = rules(r);
  for (const k of ['legacy-location', 'not-https', 'canonical-mismatch', 'robots-sensitive-path']) assert.ok(s.has(k), k);
  assert.ok(!s.has('missing'));
});
test('fetched site: missing, soft 404, redirect offsite', async () => {
  delete routes['/security.txt']; delete routes['/robots.txt'];
  assert.ok(rules(await check([base], { now: NOW })).has('missing'));
  assert.ok(rules(await check([base], { now: NOW })).has('robots-missing'));
  routes['/.well-known/security.txt'] = { body: '<!DOCTYPE html><html>not found</html>', headers: { 'content-type': 'text/html' } };
  assert.ok(rules(await check([base], { now: NOW, robots: false })).has('soft-404'));
  routes['/.well-known/security.txt'] = { status: 301, headers: { location: base.replace('127.0.0.1', 'localhost') + '/real.txt' } };
  routes['localhost/real.txt'] = { body: GOOD };
  const s = rules(await check([base], { now: NOW, robots: false }));
  assert.ok(s.has('redirect-offsite')); assert.ok(!s.has('missing'));
});
test('unreachable host is a fatal error (exit 2)', async () => {
  const s2 = http.createServer(); await new Promise((ok) => s2.listen(0, '127.0.0.1', ok)); const port = s2.address().port; await new Promise((ok) => s2.close(ok));
  const r = await check([`http://127.0.0.1:${port}`], {}); assert.equal(exitCode(r, 'high'), 2);
});
test('allowlist and severity', async () => {
  const r = await check([F + 'bad-security.txt'], { now: NOW, allow: [{ rule: 'expired', reason: 'x' }], severity: { unsigned: 'off' } });
  const s = rules(r); assert.ok(!s.has('expired')); assert.ok(!s.has('unsigned'));
});
test('CLI', () => {
  const bin = new URL('../bin/securitytxt-sentinel.js', import.meta.url).pathname;
  for (const f of ['json', 'sarif', 'markdown', 'text']) { const p = spawnSync('node', [bin, F + 'bad-security.txt', '-f', f]); assert.equal(p.status, 1, f); assert.ok(p.stdout.length); }
  assert.equal(spawnSync('node', [bin, F + 'good-security.txt', '--fail-on', 'low']).status, 0);
  assert.equal(spawnSync('node', [bin]).status, 2);
  assert.equal(spawnSync('node', [bin, F + 'robots.txt', '--kind', 'bogus']).status, 2);
});
