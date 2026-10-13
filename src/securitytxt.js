const ONCE = new Set(['expires', 'preferred-languages']);
const KNOWN = new Set(['acknowledgments', 'canonical', 'contact', 'encryption', 'expires', 'hiring', 'policy', 'preferred-languages', 'csaf']);
const URI_FIELDS = new Set(['acknowledgments', 'canonical', 'contact', 'encryption', 'hiring', 'policy', 'csaf']);
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:\d{2})$/;

/** Parse security.txt. Returns fields (lower-cased names) with line numbers, plus signature info and bad lines. */
export function parseSecurityTxt(text) {
  let lines = String(text).replace(/^\uFEFF/, '').split(/\r?\n/);
  const sig = { signed: false, complete: false };
  let offset = 0;
  const b = lines.findIndex((l) => l.trim() === '-----BEGIN PGP SIGNED MESSAGE-----');
  if (b >= 0) {
    sig.signed = true;
    const s = lines.findIndex((l) => l.trim() === '-----BEGIN PGP SIGNATURE-----');
    const e = lines.findIndex((l) => l.trim() === '-----END PGP SIGNATURE-----');
    sig.complete = s > b && e > s;
    let start = b + 1; while (start < lines.length && lines[start].trim() !== '' ) start++; // Hash: headers
    offset = start + 1; lines = lines.slice(start + 1, s > 0 ? s : undefined).map((l) => l.replace(/^- /, ''));
  }
  const fields = []; const bad = [];
  lines.forEach((l, i) => {
    const line = i + 1 + offset; const t = l.trim();
    if (!t || t.startsWith('#')) return;
    const m = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(t);
    if (!m) { bad.push({ line, text: t }); return; }
    fields.push({ name: m[1].toLowerCase(), rawName: m[1], value: m[2].trim(), line });
  });
  return { fields, bad, signature: sig };
}

/** Lint security.txt content. ctx: { url?, contentType?, now?, warnDays?, file? } */
export function lintSecurityTxt(text, ctx = {}) {
  const now = ctx.now ? new Date(ctx.now) : new Date();
  const warnDays = ctx.warnDays ?? 30;
  const where = ctx.url || ctx.file || 'security.txt';
  const at = (line) => (line ? `${where}:${line}` : where);
  const out = []; const add = (rule, line, message, extra = {}) => out.push({ rule, line, location: at(line), message, ...extra });
  const p = parseSecurityTxt(text);
  const by = (n) => p.fields.filter((f) => f.name === n);
  for (const b of p.bad) add('invalid-line', b.line, `Not a valid line: ${b.text.slice(0, 80)}`, { fix: 'Use "Field: value", or prefix comments with #.' });
  for (const n of ONCE) { const fs = by(n); if (fs.length > 1) add('duplicate-field', fs[1].line, `${fs[0].rawName} appears ${fs.length} times (it must appear at most once)`); }
  const contacts = by('contact');
  if (!contacts.length) add('missing-contact', undefined, 'No Contact field: researchers have no way to reach you', { fix: 'Add "Contact: mailto:security@example.com" or "Contact: https://example.com/security".' });
  for (const c of contacts) if (!/^(mailto:|tel:|https:\/\/)/i.test(c.value) && !/^http:\/\//i.test(c.value)) add('invalid-contact', c.line, `Contact "${c.value}" is not a mailto:, tel: or https: URI`, { evidence: c.value, fix: c.value.includes('@') ? `Use "mailto:${c.value}".` : 'Use a full URI.' });
  for (const f of p.fields) if (URI_FIELDS.has(f.name) && /^http:\/\//i.test(f.value)) add('insecure-uri', f.line, `${f.rawName} uses http:// (${f.value})`, { evidence: f.value, fix: 'Use https://.' });
  const exp = by('expires');
  if (!exp.length) add('missing-expires', undefined, 'No Expires field (required by RFC 9116)', { fix: `Add "Expires: ${new Date(now.getTime() + 300 * 864e5).toISOString().slice(0, 19)}Z".` });
  else {
    const v = exp[0].value; const d = new Date(v.replace(' ', 'T'));
    if (!RFC3339.test(v) || isNaN(d)) add('invalid-expires', exp[0].line, `Expires "${v}" is not an RFC 3339 date-time`, { evidence: v, fix: 'Use e.g. 2027-06-30T23:59:59Z.' });
    else {
      const days = Math.floor((d - now) / 864e5);
      if (d <= now) add('expired', exp[0].line, `Expired on ${v} (${-days} days ago): clients should treat the file as stale`, { evidence: v, fix: 'Review the contacts and set a new Expires date.' });
      else if (days < warnDays) add('expires-soon', exp[0].line, `Expires in ${days} days (${v})`, { evidence: v });
      else if (days > 366) add('expires-too-far', exp[0].line, `Expires is ${days} days ahead; RFC 9116 recommends less than a year`, { evidence: v });
    }
  }
  for (const f of by('preferred-languages')) for (const tag of f.value.split(',').map((s) => s.trim())) if (!/^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$/.test(tag)) add('invalid-language', f.line, `Invalid language tag "${tag}"`, { evidence: tag });
  for (const f of p.fields) if (!KNOWN.has(f.name)) add('unknown-field', f.line, `Unknown field ${f.rawName}`, { evidence: f.rawName });
  const canon = by('canonical');
  if (!canon.length) add('missing-canonical', undefined, 'No Canonical field', { fix: 'Add "Canonical: https://example.com/.well-known/security.txt".' });
  else if (ctx.url && !canon.some((c) => c.value === ctx.url)) add('canonical-mismatch', canon[0].line, `Fetched from ${ctx.url} but Canonical lists ${canon.map((c) => c.value).join(', ')}`, { evidence: ctx.url });
  if (!p.signature.signed) add('unsigned', undefined, 'Not PGP-signed (optional, but lets readers verify it)');
  else if (!p.signature.complete) add('signature-malformed', undefined, 'BEGIN PGP SIGNED MESSAGE without a complete signature block');
  if (ctx.contentType !== undefined) {
    const ct = String(ctx.contentType || '').toLowerCase();
    if (!ct.startsWith('text/plain')) add('content-type', undefined, `Served as "${ctx.contentType || 'no Content-Type'}"`, { fix: 'Serve it as text/plain; charset=utf-8.' });
    else if (!/charset=("?)utf-8/.test(ct)) add('missing-charset', undefined, `Content-Type "${ctx.contentType}" has no charset=utf-8`);
  }
  return { raw: out, parsed: p };
}

export const looksLikeHtml = (t) => /^\s*(<!doctype html|<html|<head|<body|<\?xml)/i.test(String(t).slice(0, 512));
