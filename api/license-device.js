'use strict';
const service = require('../lib/license-service.cjs');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    return res.status(204).end();
  }
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
  try {
    service.initializeFirebase();
    req.get = name => req.headers[String(name).toLowerCase()] || '';
    const response = {
      set(name, value) { res.setHeader(name, value); return this; },
      status(code) { res.statusCode = code; return this; },
      json(value) { res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(value)); return this; },
      send(value) { res.end(value); return this; }
    };
    return await service.licenseDevice(req, response);
  } catch (error) {
    console.error('[api/license-device]', error);
    if (!res.headersSent) return res.status(500).json({ ok: false, error: 'SERVER_CONFIG', message: error.message || 'Server lisensi belum dikonfigurasi.' });
  }
};
