'use strict';

function requestHost(req) {
  const forwarded = req.headers['x-forwarded-host'];
  const raw = String(forwarded || req.headers.host || '').split(',')[0].trim();
  const host = raw.replace(/:\d+$/, '').toLowerCase();
  return /^[a-z0-9.-]+$/.test(host) ? host : '';
}

module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({ message: 'Gunakan GET.' });

  const projectId = process.env.FIREBASE_PROJECT_ID || '';
  const apiKey = process.env.FIREBASE_WEB_API_KEY || '';
  const appId = process.env.FIREBASE_APP_ID || '';
  // Use the same domain that serves this Vercel app as Firebase authDomain.
  // /__/auth/* is reverse-proxied to PROJECT_ID.firebaseapp.com by api/auth-proxy.
  // This keeps the redirect helper same-site in modern Chrome browsers.
  const appDomain = requestHost(req);
  const config = {
    apiKey,
    authDomain: appDomain || `${projectId}.firebaseapp.com`,
    projectId,
    appId,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || ''
  };

  const missing = ['apiKey', 'projectId', 'appId'].filter(key => !config[key]);
  if (missing.length) {
    return res.status(503).json({ ok: false, message: `Konfigurasi Vercel belum lengkap: ${missing.join(', ')}.` });
  }
  return res.status(200).json(config);
};
