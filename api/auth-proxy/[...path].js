'use strict';

const HOP_BY_HOP = new Set([
  'connection', 'content-length', 'host', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  'accept-encoding'
]);

async function readRequestBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return chunks.length ? Buffer.concat(chunks) : undefined;
}

module.exports = async function firebaseAuthProxy(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');

  const projectId = String(process.env.FIREBASE_PROJECT_ID || '').trim();
  if (!/^[a-z0-9-]+$/.test(projectId)) {
    return res.status(503).json({ ok: false, message: 'FIREBASE_PROJECT_ID belum diatur dengan benar di Vercel.' });
  }

  if (!['GET', 'HEAD', 'POST', 'OPTIONS'].includes(req.method)) {
    return res.status(405).json({ ok: false, message: 'Metode tidak didukung oleh auth proxy.' });
  }

  try {
    const requestUrl = new URL(req.url, 'https://vercel.internal');
    const marker = '/api/auth-proxy';
    const markerAt = requestUrl.pathname.indexOf(marker);
    if (markerAt < 0) return res.status(404).json({ ok: false, message: 'Jalur auth proxy tidak ditemukan.' });

    let suffix = requestUrl.pathname.slice(markerAt + marker.length);
    if (!suffix.startsWith('/')) suffix = `/${suffix}`;
    if (suffix.includes('..')) return res.status(400).json({ ok: false, message: 'Jalur tidak valid.' });

    const upstreamUrl = `https://${projectId}.firebaseapp.com/__/auth${suffix}${requestUrl.search}`;
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers || {})) {
      const lower = name.toLowerCase();
      if (HOP_BY_HOP.has(lower) || lower.startsWith('x-vercel-') || lower.startsWith('x-forwarded-')) continue;
      if (value === undefined) continue;
      headers.set(name, Array.isArray(value) ? value.join(', ') : String(value));
    }

    const options = { method: req.method, headers, redirect: 'manual' };
    if (!['GET', 'HEAD'].includes(req.method)) {
      const body = await readRequestBody(req);
      if (body && body.length) options.body = body;
    }

    const upstream = await fetch(upstreamUrl, options);
    res.statusCode = upstream.status;

    for (const [name, value] of upstream.headers.entries()) {
      const lower = name.toLowerCase();
      if (HOP_BY_HOP.has(lower) || lower === 'set-cookie' || lower === 'content-encoding') continue;
      res.setHeader(name, value);
    }

    const cookies = typeof upstream.headers.getSetCookie === 'function'
      ? upstream.headers.getSetCookie()
      : (upstream.headers.get('set-cookie') ? [upstream.headers.get('set-cookie')] : []);
    if (cookies.length) res.setHeader('set-cookie', cookies);

    if (req.method === 'HEAD') return res.end();
    const payload = Buffer.from(await upstream.arrayBuffer());
    return res.end(payload);
  } catch (error) {
    console.error('[firebase-auth-proxy]', error && error.message ? error.message : error);
    return res.status(502).json({ ok: false, message: 'Tidak dapat menghubungi Firebase Auth. Coba lagi beberapa saat.' });
  }
};

module.exports.config = {
  api: { bodyParser: false, externalResolver: true }
};
