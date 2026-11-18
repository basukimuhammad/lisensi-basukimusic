'use strict';

module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({ message: 'Gunakan GET.' });

  const projectId = process.env.FIREBASE_PROJECT_ID || '';
  const apiKey = process.env.FIREBASE_WEB_API_KEY || '';
  const appId = process.env.FIREBASE_APP_ID || '';
  // Use Firebase's own auth domain for the popup flow. This avoids sending
  // OAuth callbacks to a Vercel /__/auth/handler route that may return 404.
  const config = {
    apiKey,
    authDomain: `${projectId}.firebaseapp.com`,
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
