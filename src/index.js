import { readFileSync, existsSync, statSync } from 'node:fs';
import { basename } from 'node:path';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { parseSecurityTxt, lintSecurityTxt, looksLikeHtml } from './securitytxt.js';
import { parseRobots, lintRobots } from './robots.js';
import { fetchText } from './fetch.js';

export { parseSecurityTxt, lintSecurityTxt, parseRobots, lintRobots, fetchText, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'securitytxt-sentinel', version: VERSION, rules: RULES, title: 'securitytxt-sentinel', emoji: '📜', defaultFailOn: 'high' };

/** "example.com", "https://example.com/x" -> "https://example.com" */
export function toOrigin(t) {
  const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `https://${t}`);
  if (!/^https?:$/.test(u.protocol)) throw new Error(`unsupported scheme ${u.protocol}`);
  return u.origin;
}
const host = (u) => new URL(u).host;
const ok = (r) => r && !r.error && r.status >= 200 && r.status < 300;

async function checkSite(target, o) {
  let origin; try { origin = toOrigin(target); } catch (e) { return { target, fatal: true, raw: [], errors: [`Invalid target ${target}: ${e.message}`] }; }
  const raw = []; const summary = {}; const get = o.fetch || fetchText;
  const wk = `${origin}/.well-known/security.txt`;
  let r = await get(wk, o); let at = wk;
  if (r.error && /ENOTFOUND|EAI_AGAIN|ECONNREFUSED|certificate|CERT|SSL|TLS/i.test(r.error) && !o.allowUnreachable) {
    return { target: origin, fatal: true, raw: [{ rule: 'fetch-error', location: wk, message: `Cannot fetch ${wk}: ${r.error}` }], errors: [`${origin}: ${r.error}`] };
  }
  const soft = (x) => ok(x) && looksLikeHtml(x.body);
  if (!ok(r) || soft(r)) {
    const legacy = await get(`${origin}/security.txt`, o);
    if (ok(legacy) && !soft(legacy)) { raw.push({ rule: 'legacy-location', location: `${origin}/security.txt`, message: `Found at /security.txt only; RFC 9116 requires /.well-known/security.txt`, fix: 'Serve it (or redirect) at /.well-known/security.txt.' }); r = legacy; at = `${origin}/security.txt`; }
  }
  if (r.error) raw.push({ rule: 'fetch-error', location: at, message: `Cannot fetch ${at}: ${r.error}` });
  else if (soft(r)) raw.push({ rule: 'soft-404', location: at, message: `${r.url} returns HTML with status ${r.status} instead of a security.txt`, fix: 'Return 404 for missing files, and publish a real security.txt.' });
  else if (!ok(r)) raw.push({ rule: 'missing', location: wk, message: `No security.txt (HTTP ${r.status} at ${wk})`, fix: 'Publish one, e.g. with https://securitytxt.org.' });
  else {
    summary.securityTxt = r.url;
    if (r.chain.length > 1) { summary.redirects = r.chain; if (r.chain.some((u) => host(u) !== host(r.chain[0]))) raw.push({ rule: 'redirect-offsite', location: r.chain[0], message: `Redirects to another host: ${r.chain.join(' → ')}`, evidence: r.url }); }
    if (!r.url.startsWith('https://')) raw.push({ rule: 'not-https', location: r.url, message: `security.txt is served from ${r.url}`, fix: 'Serve it over HTTPS only.' });
    const l = lintSecurityTxt(r.body, { url: r.url, contentType: r.contentType, now: o.now, warnDays: o.warnDays });
    raw.push(...l.raw);
    const ex = l.parsed.fields.find((f) => f.name === 'expires'); if (ex) summary.expires = ex.value;
    summary.contacts = l.parsed.fields.filter((f) => f.name === 'contact').map((f) => f.value);
    summary.signed = l.parsed.signature.signed;
  }
  if (o.robots !== false) {
    const rb = await get(`${origin}/robots.txt`, o);
    if (rb.error) raw.push({ rule: 'fetch-error', severity: 'low', location: `${origin}/robots.txt`, message: `Cannot fetch robots.txt: ${rb.error}` });
    else if (rb.status === 404 || rb.status === 410) raw.push({ rule: 'robots-missing', location: `${origin}/robots.txt`, message: 'No robots.txt' });
    else if (ok(rb) && looksLikeHtml(rb.body)) raw.push({ rule: 'robots-soft-404', location: rb.url, message: `robots.txt returns HTML (status ${rb.status})` });
    else if (ok(rb)) { summary.robotsTxt = rb.url; raw.push(...lintRobots(rb.body, { url: rb.url }).raw); }
    else raw.push({ rule: 'fetch-error', severity: 'low', location: `${origin}/robots.txt`, message: `robots.txt returned HTTP ${rb.status}` });
  }
  return { target: origin, summary, raw };
}

function checkFile(path, o) {
  const text = readFileSync(path, 'utf8'); const name = basename(path).toLowerCase();
  const kind = o.kind || (name.includes('robots') ? 'robots' : 'security');
  const raw = kind === 'robots' ? lintRobots(text, { file: path }).raw : lintSecurityTxt(text, { file: path, now: o.now, warnDays: o.warnDays, url: o.canonicalUrl }).raw;
  return { target: path, summary: { kind: kind === 'robots' ? 'robots.txt' : 'security.txt' }, raw };
}

/** Check domains/URLs (fetched) and local files. Options: robots, warnDays, now, timeout, kind, fetch, allow, severity. */
export async function check(targets, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const o = { ...opts }; const results = [];
  const isFile = (t) => existsSync(t) && statSync(t).isFile();
  const queue = [...targets]; const conc = opts.concurrency || 4;
  const out = new Array(queue.length);
  await Promise.all(Array.from({ length: Math.min(conc, queue.length) }, async () => {
    for (;;) { const i = targets.length - queue.length; const t = queue.shift(); if (t === undefined) return; out[i] = isFile(t) ? checkFile(t, o) : await checkSite(t, o); }
  }));
  results.push(...out);
  return buildReport(TOOL, results, opts);
}
