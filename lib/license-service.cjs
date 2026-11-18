'use strict';

const crypto = require('node:crypto');
const admin = require('firebase-admin');

class HttpsError extends Error {
  constructor(code, message) { super(message); this.name = 'HttpsError'; this.code = code; }
}

let db = null;
let firebaseInitialized = false;
function initializeFirebase() {
  if (firebaseInitialized) return;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('Environment FIREBASE_SERVICE_ACCOUNT_JSON belum diatur di Vercel.');
  let serviceAccount;
  try { serviceAccount = JSON.parse(raw); }
  catch { throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON harus berisi JSON service account yang valid.'); }
  if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) {
    throw new Error('Service account Firebase tidak lengkap.');
  }
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id
    });
  }
  db = admin.firestore();
  firebaseInitialized = true;
}

async function verifyFirebaseIdToken(idToken) {
  initializeFirebase();
  if (!idToken) throw new HttpsError('unauthenticated', 'Silakan masuk dengan Google terlebih dahulu.');
  try { return await admin.auth().verifyIdToken(idToken, true); }
  catch { throw new HttpsError('unauthenticated', 'Sesi Google tidak valid atau sudah berakhir. Silakan masuk kembali.'); }
}

const LICENSE_KEY_ENCRYPTION_SECRET = { value: () => process.env.LICENSE_KEY_ENCRYPTION_SECRET || '' };
const OWNER_EMAIL = 'muhammadbasuki336@gmail.com';
const TRIAL_DAYS = 7;
const MAX_NORMAL_DAYS = 365;
const MAX_DEVICE_LIMIT = 50;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Public key yang sudah tertanam pada APK Basuki Music v11.
// Dipakai untuk menerima kunci lama yang dibuat oleh halaman admin lama.
const LEGACY_PUBLIC_JWK = {
  kty: 'EC', crv: 'P-256',
  x: '5LBo4M1HIh8e7ksNYT0m8VojRQgRkgUuGTyzGAMQqxo',
  y: 'hthL9Z8MgV985dYIglC-tlRm1IF31DhltzNODrBtfL4'
};
const legacyPublicKey = crypto.createPublicKey({ key: LEGACY_PUBLIC_JWK, format: 'jwk' });


function licenseEncryptionKey() {
  const secret = LICENSE_KEY_ENCRYPTION_SECRET.value();
  if (!secret || secret.length < 32) {
    throw new Error('Secret enkripsi kunci lisensi belum diatur. Atur Environment Variable LICENSE_KEY_ENCRYPTION_SECRET di Vercel.');
  }
  return crypto.createHash('sha256').update(secret, 'utf8').digest();
}

function encryptLicenseKey(rawKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', licenseEncryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(rawKey, 'utf8'), cipher.final()]);
  return {
    algorithm: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

function decryptLicenseKey(encrypted) {
  if (!encrypted || encrypted.algorithm !== 'aes-256-gcm') return null;
  const decipher = crypto.createDecipheriv('aes-256-gcm', licenseEncryptionKey(), Buffer.from(encrypted.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
    decipher.final()
  ]).toString('utf8');
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function cleanText(value, max = 160) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

function normKey(value) {
  return String(value || '').toUpperCase().replace(/[\s-]/g, '');
}

function encodeBase32(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function formatKey(body) {
  const chunks = body.match(/.{1,5}/g) || [];
  return 'BSK2-' + chunks.join('-');
}

function generateOnlineKey() {
  // Kunci online berisi 120 bit acak. Backend hanya menyimpan hash-nya.
  return formatKey(encodeBase32(crypto.randomBytes(15)));
}

function isNewOnlineKey(key) {
  // key di sini sudah dinormalisasi (tanda hubung dan spasi dihapus).
  return /^BSK2[A-Z2-7]{24}$/.test(String(key || ''));
}

function newKeyRef(key) {
  const digest = sha256(normKey(key));
  return db.collection('licenses').doc('k_' + digest.slice(0, 48));
}

function authIdentity(request) {
  const auth = request && request.auth;
  if (!auth || !auth.uid) throw new HttpsError('unauthenticated', 'Silakan masuk dengan Google terlebih dahulu.');
  const email = String(auth.token.email || '').trim().toLowerCase();
  const provider = auth.token.firebase && auth.token.firebase.sign_in_provider;
  if (provider !== 'google.com' || !auth.token.email_verified || !email) {
    throw new HttpsError('permission-denied', 'Gunakan akun Google dengan email terverifikasi.');
  }
  return { uid: auth.uid, email };
}

function ownerIdentity(request) {
  const user = authIdentity(request);
  if (user.email !== OWNER_EMAIL) {
    throw new HttpsError('permission-denied', 'Hanya Owner Basuki Music yang dapat membuka menu admin.');
  }
  return user;
}

function decodeBase32(value) {
  let bits = 0;
  let current = 0;
  const output = [];
  for (const ch of value) {
    const n = BASE32.indexOf(ch);
    if (n < 0) return null;
    current = (current << 5) | n;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((current >>> bits) & 255);
      current &= (1 << bits) - 1;
    }
  }
  if (current !== 0) return null;
  return Buffer.from(output);
}

function verifyLegacyKey(raw) {
  let compact = normKey(raw);
  if (compact.length === 122 && compact.startsWith('BSK')) compact = compact.slice(3);
  if (compact.length !== 119) throw new Error('Format kunci lama tidak valid.');
  const bytes = decodeBase32(compact);
  if (!bytes || bytes.length !== 74) throw new Error('Format kunci lama tidak valid.');
  const payload = bytes.subarray(0, 10);
  const signature = bytes.subarray(10, 74);
  if (payload[0] !== 1) throw new Error('Versi kunci lama tidak dikenal.');
  const data = Buffer.concat([Buffer.from('BASUKI-LIC-1', 'utf8'), payload]);
  const valid = crypto.verify('sha256', data, { key: legacyPublicKey, dsaEncoding: 'ieee-p1363' }, signature);
  if (!valid) throw new Error('Tanda tangan kunci tidak valid.');
  const kind = payload[1];
  const val = payload.readUInt32BE(2);
  if (kind > 2) throw new Error('Jenis kunci lama tidak dikenal.');
  const id = payload.subarray(6, 10).toString('hex');
  return { kind, val, id, keyHash: sha256(compact) };
}

async function ensureLegacyLicense(raw, legacyActivatedAtMs, requireLegacyActivationTime = false) {
  const parsed = verifyLegacyKey(raw);
  const ref = db.collection('licenses').doc('legacy_' + parsed.id);
  const existing = await ref.get();
  if (existing.exists) {
    const data = existing.data();
    if (data.keyHash !== parsed.keyHash) throw new Error('ID kunci lama bertabrakan. Hubungi Owner.');
    return ref;
  }

  const now = Date.now();
  if (parsed.kind === 1 && parsed.val > MAX_NORMAL_DAYS * 86400) throw new Error('Kunci lama melebihi batas 1 tahun; minta Owner membuat kunci baru.');
  let expiresAtMs = null;
  let activatedAtMs = null;
  if (parsed.kind === 2) {
    // Kunci permanen v11 lama tetap didukung saat migrasi.
    expiresAtMs = null;
  }
  if (parsed.kind === 0) {
    expiresAtMs = parsed.val * 1000;
    if (expiresAtMs - now > (MAX_NORMAL_DAYS + 1) * 86400000) throw new Error('Kunci lama melebihi batas 1 tahun; minta Owner membuat kunci baru.');
  }
  if (parsed.kind === 1) {
    const suppliedAct = Number(legacyActivatedAtMs);
    const hasValidAct = Number.isFinite(suppliedAct) && suppliedAct > 0 && suppliedAct <= now + 300000;
    // Saat memperbarui APK, gunakan waktu aktivasi lokal lama jika tersedia.
    if (requireLegacyActivationTime && !hasValidAct) {
      throw new Error('Untuk menjaga tanggal kedaluwarsa kunci lama, masukkan kunci langsung di aplikasi Basuki Music yang sudah diperbarui.');
    }
    activatedAtMs = hasValidAct ? suppliedAct : now;
    expiresAtMs = activatedAtMs + parsed.val * 1000;
  }
  if (parsed.kind !== 2 && expiresAtMs && expiresAtMs <= now) throw new Error('Kunci lama sudah kedaluwarsa.')

  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    if (snap.exists) {
      if (snap.data().keyHash !== parsed.keyHash) throw new Error('ID kunci lama bertabrakan.');
      return;
    }
    tx.create(ref, {
      licenseId: 'legacy_' + parsed.id,
      keyHash: parsed.keyHash,
      keyPrefix: 'BSK-LEGACY',
      keySuffix: parsed.id.slice(-4).toUpperCase(),
      kind: 'legacy',
      legacyKind: parsed.kind,
      legacyValue: parsed.val,
      durationDays: parsed.kind === 2 ? null : Math.max(1, Math.ceil((expiresAtMs - now) / 86400000)),
      isPermanent: parsed.kind === 2,
      activatedAtMs,
      expiresAtMs,
      buyerEmail: null,
      assignedUid: null,
      email: null,
      note: 'Kunci lama v11 (otomatis didaftarkan saat aktivasi)',
      deviceLimit: 1,
      revoked: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastUsedAt: null
    });
  });
  return ref;
}

async function resolveLicense(key, legacyActivatedAtMs, requireLegacyActivationTime = false) {
  const normalized = normKey(key);
  if (isNewOnlineKey(normalized)) {
    const ref = newKeyRef(normalized);
    const snap = await ref.get();
    if (!snap.exists || snap.data().keyHash !== sha256(normalized)) throw new Error('Kunci tidak ditemukan. Periksa kembali kunci yang dimasukkan.');
    return ref;
  }
  return ensureLegacyLicense(key, legacyActivatedAtMs, requireLegacyActivationTime);
}

function toMillis(value) {
  if (!value) return null;
  if (typeof value === 'number') return value;
  if (typeof value.toMillis === 'function') return value.toMillis();
  return null;
}

function parseDeviceModel(userAgent, supplied) {
  const explicit = cleanText(supplied, 90);
  if (explicit) return explicit;
  const ua = String(userAgent || '');
  const androidMatch = ua.match(/Android\s+[0-9.]+;\s*([^;)]+)/i);
  if (androidMatch && androidMatch[1]) return cleanText(androidMatch[1].replace(/ Build.*/i, ''), 90) || 'Android';
  return /Android/i.test(ua) ? 'Perangkat Android (model tidak terdeteksi)' : 'Perangkat tidak diketahui';
}

function parseAndroidVersion(userAgent, supplied) {
  const explicit = cleanText(supplied, 40);
  if (explicit) return explicit;
  const match = String(userAgent || '').match(/Android\s+([0-9.]+)/i);
  return match ? 'Android ' + match[1] : 'Tidak terdeteksi';
}

async function appendEvent(licenseId, event, details = {}) {
  try {
    await db.collection('licenseEvents').add({
      licenseId,
      event,
      email: cleanText(details.email, 180) || null,
      deviceModel: cleanText(details.deviceModel, 90) || null,
      deviceId: cleanText(details.deviceId, 80) || null,
      detail: cleanText(details.detail, 240) || null,
      at: admin.firestore.FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.error('[license event]', error.message);
  }
}

function licensePublicData(data, activeDeviceCount) {
  return {
    licenseId: data.licenseId,
    email: data.email || data.buyerEmail || null,
    kind: data.kind,
    durationDays: data.durationDays,
    isPermanent: !!data.isPermanent,
    expiresAtMs: data.expiresAtMs || null,
    deviceLimit: data.deviceLimit || 1,
    activeDeviceCount: activeDeviceCount == null ? 0 : activeDeviceCount,
    revoked: !!data.revoked,
    note: data.note || '',
    keyPrefix: data.keyPrefix || 'BSK',
    keySuffix: data.keySuffix || '',
    createdAtMs: toMillis(data.createdAt),
    updatedAtMs: toMillis(data.updatedAt)
  };
}


async function startTrial(request) {
  const user = authIdentity(request);
  if (user.email === OWNER_EMAIL) throw new HttpsError('failed-precondition', 'Akun Owner tidak menggunakan trial. Buat lisensi permanen dari dashboard admin.');

  const key = generateOnlineKey();
  const hash = sha256(normKey(key));
  const ref = db.collection('licenses').doc('k_' + hash.slice(0, 48));
  // Kunci berdasarkan email Google terverifikasi agar penghapusan akun Firebase tidak memberi trial kedua.
  const trialRef = db.collection('trialClaims').doc(sha256(user.email));
  const now = Date.now();
  const expiresAtMs = now + TRIAL_DAYS * 86400000;

  try {
    await db.runTransaction(async tx => {
      const used = await tx.get(trialRef);
      if (used.exists) throw new HttpsError('already-exists', 'Akun Google ini sudah pernah menggunakan trial.');
      tx.create(ref, {
        licenseId: crypto.randomBytes(8).toString('hex'),
        keyHash: hash,
        encryptedKey: encryptLicenseKey(key),
        keyPrefix: 'BSK2-TRIAL',
        keySuffix: normKey(key).slice(-4),
        kind: 'trial',
        durationDays: TRIAL_DAYS,
        isPermanent: false,
        expiresAtMs,
        buyerEmail: user.email,
        email: user.email,
        assignedUid: user.uid,
        note: 'Trial 7 hari - satu kali per akun Google',
        deviceLimit: 1,
        revoked: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        lastUsedAt: null
      });
      tx.create(trialRef, {
        licenseRef: ref.path,
        email: user.email,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });
  } catch (error) {
    if (error instanceof HttpsError) throw error;
    if (String(error.message).includes('ALREADY_EXISTS')) throw new HttpsError('already-exists', 'Akun Google ini sudah pernah menggunakan trial.');
    console.error('[startTrial]', error);
    throw new HttpsError('internal', 'Gagal membuat trial. Coba lagi.');
  }

  await appendEvent(ref.id, 'trial_created', { email: user.email, detail: 'Trial 7 hari dibuat.' });
  return { ok: true, key, expiresAtMs, durationDays: TRIAL_DAYS, deviceLimit: 1 };

}

async function claimLicense(request) {
  const user = authIdentity(request);
  const key = cleanText(request.data && request.data.key, 180);
  if (!key) throw new HttpsError('invalid-argument', 'Masukkan kunci lisensi.');

  let ref;
  try {
    ref = await resolveLicense(key, request.data && request.data.legacyActivatedAtMs, true);
  } catch (error) {
    throw new HttpsError('invalid-argument', error.message || 'Kunci tidak valid.');
  }

  let response;
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new HttpsError('not-found', 'Lisensi tidak ditemukan.');
    const data = snap.data();
    if (data.revoked) throw new HttpsError('failed-precondition', 'Lisensi ini sedang diblokir.');
    if (data.expiresAtMs && data.expiresAtMs <= Date.now()) throw new HttpsError('deadline-exceeded', 'Lisensi sudah kedaluwarsa.');
    if (data.assignedUid && data.assignedUid !== user.uid) throw new HttpsError('permission-denied', 'Kunci ini sudah terhubung ke akun Google lain.');
    if (data.buyerEmail && data.buyerEmail.toLowerCase() !== user.email) {
      throw new HttpsError('permission-denied', 'Email Google tidak cocok dengan email pembeli yang ditentukan Owner.');
    }
    tx.update(ref, {
      assignedUid: user.uid,
      email: user.email,
      claimedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    response = { licenseId: data.licenseId, email: user.email };
  });

  await appendEvent(ref.id, 'claimed', { email: user.email, detail: 'Lisensi dihubungkan ke akun Google.' });
  return { ok: true, ...response };

}

async function getMyLicenses(request) {
  const user = authIdentity(request);
  const snap = await db.collection('licenses').where('assignedUid', '==', user.uid).limit(20).get();
  const licenses = snap.docs.map(doc => {
    const data = doc.data();
    let key = null;
    try { key = decryptLicenseKey(data.encryptedKey); } catch (error) { console.error('[decrypt user license key]', error.message); }
    return { ...licensePublicData(data, 0), key };
  });
  return { licenses };

}

async function createLicense(request) {
  const owner = ownerIdentity(request);
  const data = request.data || {};
  const email = cleanText(data.email, 180).toLowerCase();
  const note = cleanText(data.note, 180);
  const days = Number(data.days);
  const quantity = Math.max(1, Math.min(100, Math.floor(Number(data.quantity) || 1)));
  const deviceLimit = Math.floor(Number(data.deviceLimit) || 1);
  const permanent = data.permanent === true;

  if (deviceLimit < 1 || deviceLimit > MAX_DEVICE_LIMIT) throw new HttpsError('invalid-argument', `Batas perangkat harus 1-${MAX_DEVICE_LIMIT}.`);
  if (permanent) {
    if (email !== OWNER_EMAIL || quantity !== 1) throw new HttpsError('permission-denied', 'Lisensi permanen hanya boleh dibuat satu untuk akun Owner.');
  } else if (!Number.isInteger(days) || days < 1 || days > MAX_NORMAL_DAYS) {
    throw new HttpsError('invalid-argument', `Lisensi biasa maksimal ${MAX_NORMAL_DAYS} hari.`);
  }

  const created = [];
  for (let i = 0; i < quantity; i++) {
    let key;
    let hash;
    let ref;
    let attempts = 0;
    do {
      key = generateOnlineKey();
      hash = sha256(normKey(key));
      ref = db.collection('licenses').doc('k_' + hash.slice(0, 48));
      attempts++;
      if (attempts > 5) throw new HttpsError('internal', 'Gagal membuat ID kunci unik.');
    } while ((await ref.get()).exists);

    const now = Date.now();
    const expiresAtMs = permanent ? null : now + days * 86400000;
    const licenseId = crypto.randomBytes(8).toString('hex');
    await ref.create({
      licenseId,
      keyHash: hash,
      encryptedKey: encryptLicenseKey(key),
      keyPrefix: 'BSK2',
      keySuffix: normKey(key).slice(-4),
      kind: permanent ? 'owner' : 'paid',
      durationDays: permanent ? null : days,
      isPermanent: permanent,
      expiresAtMs,
      buyerEmail: email || null,
      email: email || null,
      assignedUid: email === owner.email ? owner.uid : null,
      note,
      deviceLimit,
      revoked: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: owner.uid,
      lastUsedAt: null
    });
    await appendEvent(ref.id, 'created', { email, detail: permanent ? 'Lisensi Owner permanen dibuat.' : `Lisensi ${days} hari dibuat.` });
    created.push({ key, licenseId, email: email || null, days: permanent ? null : days, isPermanent: permanent, deviceLimit, expiresAtMs });
  }
  return { ok: true, licenses: created };

}

async function adminListLicenses(request) {
  ownerIdentity(request);
  const snap = await db.collection('licenses').orderBy('createdAt', 'desc').limit(200).get();
  const licenses = await Promise.all(snap.docs.map(async doc => {
    const data = doc.data();
    const devicesSnap = await doc.ref.collection('devices').orderBy('lastUse', 'desc').limit(50).get();
    const devices = devicesSnap.docs.map(deviceDoc => {
      const d = deviceDoc.data();
      return {
        deviceId: deviceDoc.id,
        model: d.deviceModel || 'Tidak diketahui',
        androidVersion: d.androidVersion || 'Tidak diketahui',
        status: d.status || 'active',
        firstLoginMs: toMillis(d.firstLogin),
        lastUseMs: toMillis(d.lastUse)
      };
    });
    const activeCount = devices.filter(d => d.status === 'active').length;
    let fullKey = null;
    try { fullKey = decryptLicenseKey(data.encryptedKey); } catch (error) { console.error('[decrypt license key]', error.message); }
    return { ...licensePublicData(data, activeCount), key: fullKey, devices, docId: doc.id };
  }));
  const eventSnap = await db.collection('licenseEvents').orderBy('at', 'desc').limit(100).get();
  const events = eventSnap.docs.map(doc => {
    const d = doc.data();
    return { licenseId: d.licenseId, event: d.event, email: d.email || null, deviceModel: d.deviceModel || null, deviceId: d.deviceId || null, detail: d.detail || '', atMs: toMillis(d.at) };
  });
  return { licenses, events };

}

async function updateLicense(request) {
  ownerIdentity(request);
  const data = request.data || {};
  const licenseDocId = cleanText(data.licenseDocId, 140);
  const ref = db.collection('licenses').doc(licenseDocId);
  if (!licenseDocId) throw new HttpsError('invalid-argument', 'ID dokumen lisensi tidak ditemukan.');

  const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
  if (typeof data.revoked === 'boolean') updates.revoked = data.revoked;
  if (data.deviceLimit !== undefined) {
    const limit = Math.floor(Number(data.deviceLimit));
    if (limit < 1 || limit > MAX_DEVICE_LIMIT) throw new HttpsError('invalid-argument', `Batas perangkat harus 1-${MAX_DEVICE_LIMIT}.`);
    updates.deviceLimit = limit;
  }

  let event = 'updated';
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new HttpsError('not-found', 'Lisensi tidak ditemukan.');
    const old = snap.data();
    let activeCount = null;
    if (data.deviceLimit !== undefined) {
      const devicesQuery = ref.collection('devices').where('status', '==', 'active').orderBy('lastUse', 'asc');
      const active = await tx.get(devicesQuery);
      const excess = Math.max(0, active.size - updates.deviceLimit);
      active.docs.slice(0, excess).forEach(device => {
        tx.update(device.ref, { status: 'replaced', replacedAt: admin.firestore.FieldValue.serverTimestamp(), replacedReason: 'Batas perangkat diturunkan Owner' });
      });
      activeCount = active.size - excess;
    }
    if (activeCount !== null) updates.activeDeviceCount = activeCount;
    tx.update(ref, updates);
    if (typeof data.revoked === 'boolean') event = data.revoked ? 'license_blocked' : 'license_unblocked';
    if (data.deviceLimit !== undefined) event = 'device_limit_changed';
  });
  await appendEvent(ref.id, event, { detail: data.deviceLimit !== undefined ? `Batas perangkat: ${updates.deviceLimit}` : '' });
  return { ok: true };

}

async function extendLicense(request) {
  ownerIdentity(request);
  const data = request.data || {};
  const licenseDocId = cleanText(data.licenseDocId, 140);
  const addDays = Math.floor(Number(data.addDays));
  if (!licenseDocId) throw new HttpsError('invalid-argument', 'ID dokumen lisensi tidak ditemukan.');
  if (!Number.isInteger(addDays) || addDays < 1 || addDays > MAX_NORMAL_DAYS) {
    throw new HttpsError('invalid-argument', `Tambahan masa aktif harus 1-${MAX_NORMAL_DAYS} hari.`);
  }
  const ref = db.collection('licenses').doc(licenseDocId);
  let newExpiry = null;
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new HttpsError('not-found', 'Lisensi tidak ditemukan.');
    const current = snap.data();
    if (current.isPermanent) throw new HttpsError('failed-precondition', 'Lisensi permanen tidak perlu diperpanjang.');
    const now = Date.now();
    const base = Math.max(Number(current.expiresAtMs) || now, now);
    newExpiry = base + addDays * 86400000;
    if (newExpiry > now + MAX_NORMAL_DAYS * 86400000) {
      throw new HttpsError('failed-precondition', 'Masa aktif setelah perpanjangan tidak boleh melebihi 365 hari dari hari ini.');
    }
    tx.update(ref, {
      expiresAtMs: newExpiry,
      durationDays: Math.ceil((newExpiry - now) / 86400000),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
  });
  await appendEvent(ref.id, 'license_extended', { detail: `Masa aktif diperpanjang ${addDays} hari; tanggal akhir ${new Date(newExpiry).toISOString()}.` });
  return { ok: true, expiresAtMs: newExpiry };

}

async function updateDevice(request) {
  ownerIdentity(request);
  const data = request.data || {};
  const licenseDocId = cleanText(data.licenseDocId, 140);
  const deviceId = cleanText(data.deviceId, 100);
  const blocked = data.blocked === true;
  const licenseRef = db.collection('licenses').doc(licenseDocId);
  if (!licenseDocId) throw new HttpsError('invalid-argument', 'ID dokumen lisensi tidak ditemukan.');
  const deviceRef = licenseRef.collection('devices').doc(deviceId);
  let deviceModel = 'Perangkat';
  await db.runTransaction(async tx => {
    const licenseSnap = await tx.get(licenseRef);
    const deviceSnap = await tx.get(deviceRef);
    if (!licenseSnap.exists || !deviceSnap.exists) throw new HttpsError('not-found', 'Lisensi atau perangkat tidak ditemukan.');
    deviceModel = deviceSnap.data().deviceModel || deviceModel;
    if (blocked) {
      tx.update(deviceRef, { status: 'blocked', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      return;
    }
    const activeQuery = licenseRef.collection('devices').where('status', '==', 'active').orderBy('lastUse', 'asc');
    const activeSnap = await tx.get(activeQuery);
    const currentStatus = deviceSnap.data().status;
    const maxDevices = Math.max(1, Math.min(MAX_DEVICE_LIMIT, Number(licenseSnap.data().deviceLimit) || 1));
    if (currentStatus !== 'active' && activeSnap.size >= maxDevices) {
      const evicted = activeSnap.docs.find(doc => doc.id !== deviceId);
      if (!evicted) throw new HttpsError('failed-precondition', 'Batas perangkat sedang penuh; tidak dapat membuka blokir perangkat ini.');
      tx.update(evicted.ref, { status: 'replaced', replacedAt: admin.firestore.FieldValue.serverTimestamp(), replacedReason: 'Perangkat lain diprioritaskan oleh Owner' });
    }
    tx.update(deviceRef, { status: 'active', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
  });
  await appendEvent(licenseRef.id, blocked ? 'device_blocked' : 'device_unblocked', {
    deviceModel,
    deviceId: deviceId.slice(0, 10),
    detail: blocked ? 'Akses perangkat diblokir Owner.' : 'Akses perangkat dibuka kembali.'
  });
  return { ok: true };

}

async function licenseDevice(req, res) {
  res.set('Cache-Control', 'no-store');
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).send('');
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'METHOD_NOT_ALLOWED', message: 'Gunakan POST.' });

  try {
    const body = req.body || {};
    const key = cleanText(body.key, 180);
    const installationId = cleanText(body.installationId, 128);
    if (!key || installationId.length < 16) return res.status(400).json({ ok: false, error: 'BAD_REQUEST', message: 'Kunci atau ID instalasi tidak valid.' });

    let licenseRef;
    try {
      licenseRef = await resolveLicense(key, body.legacyActivatedAtMs);
    } catch (error) {
      return res.status(401).json({ ok: false, error: 'INVALID_KEY', message: error.message || 'Kunci tidak valid.' });
    }

    const licenseSnap = await licenseRef.get();
    if (!licenseSnap.exists) return res.status(401).json({ ok: false, error: 'INVALID_KEY', message: 'Kunci tidak ditemukan.' });
    const initial = licenseSnap.data();
    const deviceHash = sha256(installationId);
    const deviceRef = licenseRef.collection('devices').doc(deviceHash);
    const deviceModel = parseDeviceModel(req.get('user-agent'), body.deviceModel);
    const androidVersion = parseAndroidVersion(req.get('user-agent'), body.androidVersion);
    let responseData = null;
    let newlyActivated = false;
    let replacedDeviceId = null;

    await db.runTransaction(async tx => {
      const currentLicense = await tx.get(licenseRef);
      const currentDevice = await tx.get(deviceRef);
      const activeQuery = licenseRef.collection('devices').where('status', '==', 'active').orderBy('lastUse', 'asc');
      const activeSnap = await tx.get(activeQuery);
      if (!currentLicense.exists) throw new Error('LICENSE_NOT_FOUND');
      const license = currentLicense.data();
      if (license.revoked) throw new Error('LICENSE_REVOKED');
      if (license.expiresAtMs && Number(license.expiresAtMs) <= Date.now()) throw new Error('LICENSE_EXPIRED');
      // Kunci online baru harus lebih dulu diklaim pada portal Google.
      // Kunci legacy tetap dapat dimigrasikan langsung dari aplikasi v11.
      if (license.kind !== 'legacy' && !license.assignedUid) throw new Error('LICENSE_NOT_CLAIMED');
      if (currentDevice.exists && currentDevice.data().status === 'blocked') throw new Error('DEVICE_BLOCKED');
      // Heartbeat cannot reclaim a seat after another phone has replaced this installation.
      // Re-entry by the user (heartbeat=false) is an explicit device replacement request.
      if (body.heartbeat === true && currentDevice.exists && currentDevice.data().status === 'replaced') throw new Error('DEVICE_REPLACED');

      const isCurrentActive = currentDevice.exists && currentDevice.data().status === 'active';
      newlyActivated = !isCurrentActive;
      const maxDevices = Math.max(1, Math.min(MAX_DEVICE_LIMIT, Number(license.deviceLimit) || 1));
      let evicted = null;
      if (!isCurrentActive && activeSnap.size >= maxDevices) {
        evicted = activeSnap.docs.find(doc => doc.id !== deviceHash) || null;
        if (!evicted) throw new Error('DEVICE_LIMIT');
      }
      if (evicted) {
        replacedDeviceId = evicted.id;
        tx.update(evicted.ref, {
          status: 'replaced',
          replacedAt: admin.firestore.FieldValue.serverTimestamp(),
          replacedReason: 'Perangkat baru memakai kunci yang sama'
        });
      }
      const deviceData = currentDevice.exists ? currentDevice.data() : {};
      tx.set(deviceRef, {
        deviceModel,
        androidVersion,
        status: 'active',
        firstLogin: deviceData.firstLogin || admin.firestore.FieldValue.serverTimestamp(),
        lastUse: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        // User-Agent mentah tidak disimpan; hanya model dan versi Android.
      }, { merge: true });
      const activeCount = Math.min(maxDevices, activeSnap.size + (isCurrentActive ? 0 : 1) - (evicted ? 1 : 0));
      tx.update(licenseRef, {
        lastUsedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        activeDeviceCount: activeCount
      });
      const expiresAtMs = license.expiresAtMs || null;
      responseData = {
        ok: true,
        status: 'active',
        licenseId: license.licenseId,
        email: license.email || license.buyerEmail || null,
        expiresAtMs,
        isPermanent: !!license.isPermanent,
        deviceLimit: maxDevices,
        activeDeviceCount: activeCount
      };
      if (evicted) responseData.replacedDeviceId = evicted.id;
    });

    if (newlyActivated) {
      await appendEvent(initial.licenseId || licenseRef.id, 'device_activated', {
        email: initial.email || initial.buyerEmail,
        deviceModel,
        deviceId: deviceHash.slice(0, 10),
        detail: 'Perangkat baru mengaktifkan lisensi.'
      });
    }
    if (replacedDeviceId) {
      await appendEvent(initial.licenseId || licenseRef.id, 'device_replaced', {
        email: initial.email || initial.buyerEmail,
        deviceModel,
        deviceId: replacedDeviceId.slice(0, 10),
        detail: 'Perangkat sebelumnya digantikan oleh instalasi baru.'
      });
    }
    return res.status(200).json(responseData || { ok: false, error: 'UNKNOWN', message: 'Pemeriksaan gagal.' });
  } catch (error) {
    const code = String(error && error.message || 'UNKNOWN');
    const known = {
      LICENSE_REVOKED: ['LICENSE_REVOKED', 'Lisensi ini diblokir Owner.'],
      LICENSE_EXPIRED: ['LICENSE_EXPIRED', 'Masa berlaku lisensi sudah habis.'],
      LICENSE_NOT_CLAIMED: ['LICENSE_NOT_CLAIMED', 'Masuk ke website Lisensi Basuki Music dengan akun Google, lalu hubungkan kunci ini.'],
      DEVICE_BLOCKED: ['DEVICE_BLOCKED', 'Akses perangkat ini diblokir Owner.'],
      DEVICE_REPLACED: ['DEVICE_REPLACED', 'Perangkat ini sudah digantikan HP lain. Masukkan ulang kunci hanya jika ingin memindahkan lisensi kembali ke HP ini.'],
      DEVICE_LIMIT: ['DEVICE_LIMIT', 'Batas perangkat telah tercapai.']
    };
    const result = known[code];
    if (result) return res.status(403).json({ ok: false, error: result[0], message: result[1] });
    console.error('[licenseDevice]', error);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR', message: 'Server lisensi sedang bermasalah. Coba lagi.' });
  }

}

module.exports = {
  initializeFirebase,
  verifyFirebaseIdToken,
  HttpsError,
  handlers: {
    startTrial, claimLicense, getMyLicenses, createLicense,
    adminListLicenses, updateLicense, extendLicense, updateDevice
  },
  licenseDevice
};
