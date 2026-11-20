'use strict';

function normalizeAuthDomain(value) {
  let host = String(value || '').trim().toLowerCase();
  if (host.startsWith('https://')) host = host.slice(8);
  else if (host.startsWith('http://')) host = host.slice(7);
  host = host.split('/')[0];

  if (!host || host.length > 253 || !host.includes('.')) return '';
  if (host.includes('..') || host.startsWith('.') || host.endsWith('.')) return '';

  const allowed = 'abcdefghijklmnopqrstuvwxyz0123456789-.';
  for (const ch of host) {
    if (!allowed.includes(ch)) return '';
  }

  const labels = host.split('.');
  if (labels.some(label => !label || label.startsWith('-') || label.endsWith('-'))) return '';

  // A numeric Firebase project number / messaging sender ID is not a hostname.
  const allNumeric = [...host].every(ch => (ch >= '0' && ch <= '9') || ch === '.');
  if (allNumeric) return '';
  if (labels[labels.length - 1].length < 2) return '';

  return host;
}

module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({ message: 'Gunakan GET.' });

  const projectId = String(process.env.FIREBASE_PROJECT_ID || '').trim();
  const apiKey = String(process.env.FIREBASE_WEB_API_KEY || '').trim();
  const appId = String(process.env.FIREBASE_APP_ID || '').trim();

  const configuredAuthDomain = normalizeAuthDomain(process.env.FIREBASE_AUTH_DOMAIN);
  const fallbackAuthDomain = projectId ? projectId + '.firebaseapp.com' : '';
  const authDomain = configuredAuthDomain || fallbackAuthDomain;

  const config = {
    apiKey,
    authDomain,
    projectId,
    appId,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || ''
  };

  const missing = ['apiKey', 'authDomain', 'projectId', 'appId'].filter(key => !config[key]);
  if (missing.length) {
    return res.status(503).json({
      ok: false,
      message: 'Konfigurasi Vercel belum lengkap: ' + missing.join(', ') + '.'
    });
  }

  return res.status(200).json(config);
};
