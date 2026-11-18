'use strict';
const STATUS = {
  'unauthenticated': 401,
  'permission-denied': 403,
  'invalid-argument': 400,
  'not-found': 404,
  'already-exists': 409,
  'failed-precondition': 412,
  'deadline-exceeded': 410,
  'resource-exhausted': 429,
  'internal': 500
};

module.exports = async function handler(req, res) {
  const requestId = require('node:crypto').randomUUID();
  let stage = 'request';
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  try {
    stage = 'load-license-service';
    const service = require('../lib/license-service.cjs');
    stage = 'firebase-admin-init';
    service.initializeFirebase();
    stage = 'verify-google-token';
    const header = String(req.headers.authorization || '');
    const match = header.match(/^Bearer\s+(.+)$/i);
    const decoded = await service.verifyFirebaseIdToken(match && match[1]);
    const action = String((req.body && req.body.action) || '');
    const data = req.body && req.body.data && typeof req.body.data === 'object' ? req.body.data : {};
    stage = 'resolve-action';
    const fn = service.handlers[action];
    if (typeof fn !== 'function') return res.status(404).json({ ok: false, message: 'Aksi API tidak dikenal.' });
    stage = `handler:${action || 'empty'}`;
    const result = await fn({ auth: { uid: decoded.uid, token: decoded }, data });
    return res.status(200).json(result || { ok: true });
  } catch (error) {
    const code = error && error.code ? String(error.code) : 'internal';
    const status = STATUS[code] || 500;
    console.error('[api/license]', { requestId, stage, code, message: error && error.message, stack: error && error.stack });
    const rawMessage = error && error.message ? error.message : 'Terjadi kesalahan server.';
    const friendly = status >= 500
      ? `${rawMessage} (tahap: ${stage}, ID: ${requestId})`
      : rawMessage;
    return res.status(status).json({ ok: false, code, stage, requestId, message: friendly });
  }
};
