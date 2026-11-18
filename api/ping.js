'use strict';

module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
  }
  return res.status(200).json({
    ok: true,
    service: 'basuki-music-license-api',
    function: 'deployed',
    node: process.version,
    timestamp: new Date().toISOString()
  });
};
