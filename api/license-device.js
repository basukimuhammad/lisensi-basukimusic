'use strict';

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Cache-Control', 'no-store');
}

module.exports = async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  let stage = 'load-license-service';
  try {
    const service = require('../lib/license-service.cjs');
    stage = 'firebase-admin-init';
    service.initializeFirebase();
    if (typeof service.licenseDevice !== 'function') {
      throw new Error('Fungsi licenseDevice tidak tersedia pada license-service.');
    }
    req.get = name => req.headers[String(name).toLowerCase()] || '';
    const response = {
      set(name, value) { res.setHeader(name, value); return this; },
      status(code) { res.statusCode = code; return this; },
      json(value) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.end(JSON.stringify(value));
        return this;
      },
      send(value) { res.end(value); return this; }
    };
    return await service.licenseDevice(req, response);
  } catch (error) {
    console.error('[api/license-device]', {
      stage,
      name: error && error.name,
      code: error && error.code,
      message: error && error.message,
      stack: error && error.stack
    });
    if (!res.headersSent) {
      return res.status(503).json({
        ok: false,
        error: 'SERVER_CONFIG',
        stage,
        errorName: error && error.name || 'Error',
        errorCode: error && error.code != null ? String(error.code) : null,
        message: error && error.message || 'Server lisensi belum dikonfigurasi.'
      });
    }
  }
};
