/** GET a URL following up to 5 redirects by hand so the chain can be inspected. Body capped at 1 MiB. */
export async function fetchText(url, { timeout = 10000, userAgent = 'securitytxt-sentinel' } = {}) {
  const chain = [url]; let cur = url;
  for (let hop = 0; hop <= 5; hop++) {
    const ac = new AbortController(); const t = setTimeout(() => ac.abort(), timeout);
    let res;
    try { res = await fetch(cur, { redirect: 'manual', signal: ac.signal, headers: { 'user-agent': userAgent, accept: 'text/plain, */*;q=0.5' } }); }
    catch (e) { clearTimeout(t); return { error: e.name === 'AbortError' ? `timeout after ${timeout} ms` : (e.cause?.code || e.cause?.message || e.message), chain }; }
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      clearTimeout(t); await res.body?.cancel().catch(() => {});
      cur = new URL(res.headers.get('location'), cur).href; chain.push(cur); continue;
    }
    let body = '';
    try {
      const reader = res.body.getReader(); const dec = new TextDecoder(); let n = 0;
      for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.length; body += dec.decode(value, { stream: true }); if (n > 1048576) { await reader.cancel(); break; } }
    } catch (e) { clearTimeout(t); return { error: e.message, chain }; }
    clearTimeout(t);
    return { status: res.status, url: cur, chain, contentType: res.headers.get('content-type') || '', body };
  }
  return { error: 'too many redirects', chain };
}
