'use strict';
module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({
    ok: true,
    service: 'Basuki Music License API',
    configured: {
      firebaseProject: !!process.env.FIREBASE_PROJECT_ID,
      webAuth: !!(process.env.FIREBASE_WEB_API_KEY && process.env.FIREBASE_APP_ID),
      serviceAccount: !!process.env.FIREBASE_SERVICE_ACCOUNT_JSON,
      licenseEncryption: !!process.env.LICENSE_KEY_ENCRYPTION_SECRET
    }
  });
};
