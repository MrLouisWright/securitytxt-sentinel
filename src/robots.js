const SENSITIVE = /(^|\/)(admin(istrator)?|wp-admin|phpmyadmin|pma|backup?s?|bak|old|dump|db|database|sql|\.git|\.env|\.svn|config(uration)?|secret|private|internal|staging|dev|test|debug|console|actuator|server-status|cgi-bin|logs?|tmp|uploads?\/private|install|setup|api\/internal|manage(ment)?|cpanel|webmail)(\/|$|\.)/i;
const DIRECTIVES = new Set(['user-agent', 'allow', 'disallow', 'sitemap', 'crawl-delay', 'host', 'clean-param', 'noindex', 'request-rate', 'visit-time', 'content-signal']);

export function parseRobots(text) {
  const groups = []; const sitemaps = []; const bad = []; const early = [];
  let cur = null; let lastWasAgent = false;
  String(text).replace(/^\uFEFF/, '').split(/\r?\n/).forEach((l, i) => {
    const line = i + 1; const t = l.replace(/#.*$/, '').trim(); if (!t) return;
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(t);
    if (!m || !DIRECTIVES.has(m[1].toLowerCase())) { bad.push({ line, text: t }); return; }
    const k = m[1].toLowerCase(); const v = m[2].trim();
    if (k === 'sitemap') { sitemaps.push({ value: v, line }); return; }
    if (k === 'user-agent') { if (!lastWasAgent || !cur) { cur = { agents: [], rules: [], line }; groups.push(cur); } cur.agents.push(v.toLowerCase()); lastWasAgent = true; return; }
    lastWasAgent = false;
    if (!cur) { early.push({ line, text: t }); return; }
    if (k === 'allow' || k === 'disallow') cur.rules.push({ type: k, path: v, line });
  });
  return { groups, sitemaps, bad, early };
}

export function lintRobots(text, ctx = {}) {
  const where = ctx.url || ctx.file || 'robots.txt';
  const out = []; const add = (rule, line, message, extra = {}) => out.push({ rule, line, location: line ? `${where}:${line}` : where, message, ...extra });
  const size = Buffer.byteLength(String(text));
  if (size > 500 * 1024) add('robots-too-large', undefined, `robots.txt is ${Math.round(size / 1024)} KiB; Google ignores everything after 500 KiB`);
  const p = parseRobots(text);
  for (const b of p.bad) add('robots-invalid-line', b.line, `Not a valid directive: ${b.text.slice(0, 80)}`);
  for (const e of p.early) add('robots-rule-before-agent', e.line, `"${e.text}" comes before any User-agent line and is ignored`);
  for (const s of p.sitemaps) if (!/^https:\/\//i.test(s.value)) add('robots-sitemap-insecure', s.line, `Sitemap "${s.value}" ${/^http:/i.test(s.value) ? 'uses http://' : 'is not an absolute URL'}`, { evidence: s.value });
  const seen = new Set();
  for (const g of p.groups) for (const r of g.rules) {
    if (r.type === 'disallow' && r.path && SENSITIVE.test(r.path) && !seen.has(r.path)) { seen.add(r.path); add('robots-sensitive-path', r.line, `Disallow ${r.path} tells everyone where a sensitive area is (robots.txt is not access control)`, { evidence: r.path, fix: 'Protect it with authentication and drop it from robots.txt, or use noindex headers.' }); }
  }
  const star = p.groups.filter((g) => g.agents.includes('*'));
  if (star.some((g) => g.rules.some((r) => r.type === 'disallow' && r.path === '/') && !g.rules.some((r) => r.type === 'allow' && r.path))) add('robots-blocks-all', star[0].line, 'User-agent: * is disallowed from the whole site (fine for staging, not for production)');
  return { raw: out, parsed: p };
}
