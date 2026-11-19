'use strict';

module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
  }

  const projectId = String(process.env.FIREBASE_PROJECT_ID || '').trim();
  const apiKey = String(process.env.FIREBASE_WEB_API_KEY || '').trim();
  const appId = String(process.env.FIREBASE_APP_ID || '').trim();
  const ownerEmail = String(
    process.env.OWNER_EMAIL || 'muhammadbasuki336@gmail.com'
  ).trim().toLowerCase();

  // Use Firebase's own auth domain for the Google popup flow.
  const config = {
    apiKey,
    authDomain: `${projectId}.firebaseapp.com`,
    projectId,
    appId,
    messagingSenderId: String(process.env.FIREBASE_MESSAGING_SENDER_ID || ''),
    // Must match OWNER_EMAIL used by lib/license-service.cjs.
    ownerEmail
  };

  const missing = ['apiKey', 'projectId', 'appId'].filter(key => !config[key]);
  if (missing.length) {
    return res.status(503).json({
      ok: false,
      message: `Konfigurasi Vercel belum lengkap: ${missing.join(', ')}.`
    });
  }

  return res.status(200).json(config);
};
