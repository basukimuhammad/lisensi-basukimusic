'use strict';
const service = require('../lib/license-service.cjs');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const configured = {
    firebaseProject: !!process.env.FIREBASE_PROJECT_ID,
    webAuth: !!(process.env.FIREBASE_WEB_API_KEY && process.env.FIREBASE_APP_ID),
    serviceAccount: !!process.env.FIREBASE_SERVICE_ACCOUNT_JSON,
    licenseEncryption: !!process.env.LICENSE_KEY_ENCRYPTION_SECRET
  };
  const missing = Object.keys(configured).filter(key => !configured[key]);
  if (missing.length) {
    return res.status(503).json({ ok: false, configured, missing, message: 'Environment Variables Vercel belum lengkap.' });
  }
  try {
    const probe = await service.backendHealth();
    return res.status(200).json({ ...probe, configured });
  } catch (error) {
    console.error('[api/health]', error);
    return res.status(503).json({ ok: false, configured, firestore: false, message: error.message || 'Koneksi Firestore gagal.' });
  }
};
