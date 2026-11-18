'use strict';

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
  }

  const configured = {
    firebaseProject: !!process.env.FIREBASE_PROJECT_ID,
    webAuth: !!(process.env.FIREBASE_WEB_API_KEY && process.env.FIREBASE_APP_ID),
    serviceAccount: !!process.env.FIREBASE_SERVICE_ACCOUNT_JSON,
    licenseEncryption: !!process.env.LICENSE_KEY_ENCRYPTION_SECRET
  };
  const missing = Object.keys(configured).filter(key => !configured[key]);
  if (missing.length) {
    return res.status(503).json({
      ok: false,
      stage: 'environment-check',
      configured,
      missing,
      message: 'Environment Variables Vercel belum lengkap.'
    });
  }

  let stage = 'load-license-service';
  try {
    // Lazy-load inside try/catch so a missing/broken Firebase Admin dependency
    // returns actionable JSON instead of a generic Vercel FUNCTION_INVOCATION_FAILED.
    const service = require('../lib/license-service.cjs');
    const credentialChecks = service.serviceAccountDiagnostics();
    stage = 'firebase-admin-init';
    service.initializeFirebase();
    stage = 'google-oauth-token';
    const oauth = await service.testGoogleOAuth();
    stage = 'firestore-read';
    const probe = await service.backendHealth();
    return res.status(200).json({ ...probe, oauth, configured, credentialChecks, stage: 'ready' });
  } catch (error) {
    console.error('[api/health]', {
      stage,
      name: error && error.name,
      code: error && error.code,
      message: error && error.message,
      stack: error && error.stack
    });
    return res.status(503).json({
      ok: false,
      stage,
      configured,
      credentialChecks: (() => { try { return require('../lib/license-service.cjs').serviceAccountDiagnostics(); } catch { return null; } })(),
      errorName: error && error.name || 'Error',
      errorCode: error && error.code != null ? String(error.code) : null,
      message: error && error.message || 'Koneksi Firebase/Firestore gagal.'
    });
  }
};
