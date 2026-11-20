'use strict';

const crypto = require('node:crypto');
const { getApps, initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

let firebaseApp = null;
let firebaseCredential = null;

class HttpsError extends Error {
  constructor(code, message) { super(message); this.name = 'HttpsError'; this.code = code; }
}

let db = null;
let firebaseInitialized = false;

function readServiceAccount() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('Environment FIREBASE_SERVICE_ACCOUNT_JSON belum diatur di Vercel.');

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON bukan JSON valid. Salin seluruh isi file service-account JSON tanpa tanda kutip tambahan.');
  }

  const projectId = String(serviceAccount.project_id || '').trim();
  const clientEmail = String(serviceAccount.client_email || '').trim();
  const privateKey = String(serviceAccount.private_key || '')
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .trim() + '\n';

  if (!projectId || !clientEmail || !privateKey.trim()) {
    throw new Error('Service account tidak lengkap: wajib memiliki project_id, client_email, dan private_key.');
  }
  if (!privateKey.includes('-----BEGIN PRIVATE KEY-----') || !privateKey.includes('-----END PRIVATE KEY-----')) {
    throw new Error('private_key bukan PEM Private Key yang valid. Buat ulang JSON key dari Firebase Project Settings → Service accounts.');
  }

  const configuredProjectId = String(process.env.FIREBASE_PROJECT_ID || '').trim();
  if (configuredProjectId && configuredProjectId !== projectId) {
    throw new Error(`Project ID tidak cocok: FIREBASE_PROJECT_ID menunjuk ke "${configuredProjectId}", tetapi service account berasal dari "${projectId}". Gunakan keduanya dari project Firebase yang sama.`);
  }

  return { projectId, clientEmail, privateKey };
}

function serviceAccountDiagnostics() {
  try {
    const account = readServiceAccount();
    return {
      serviceAccountJsonValid: true,
      serviceAccountProjectMatches: account.projectId === String(process.env.FIREBASE_PROJECT_ID || '').trim(),
      privateKeyPemValid: account.privateKey.includes('-----BEGIN PRIVATE KEY-----') && account.privateKey.includes('-----END PRIVATE KEY-----'),
      serviceAccountEmailPresent: !!account.clientEmail
    };
  } catch (error) {
    return {
      serviceAccountJsonValid: false,
      serviceAccountProjectMatches: false,
      privateKeyPemValid: false,
      serviceAccountEmailPresent: false,
      serviceAccountConfigError: error.message
    };
  }
}

function initializeFirebase() {
  if (firebaseInitialized) return;
  const account = readServiceAccount();
  const credential = cert({
    projectId: account.projectId,
    clientEmail: account.clientEmail,
    privateKey: account.privateKey
  });
  firebaseCredential = credential;
  firebaseApp = getApps().find(app => app.name === '[DEFAULT]') || initializeApp({
    credential,
    projectId: account.projectId
  });
  db = getFirestore(firebaseApp);
  firebaseInitialized = true;
}

async function verifyFirebaseIdToken(idToken) {
  initializeFirebase();
  if (!idToken) throw new HttpsError('unauthenticated', 'Silakan masuk dengan Google terlebih dahulu.');
  try { return await getAuth(firebaseApp).verifyIdToken(idToken, false); }
  catch { throw new HttpsError('unauthenticated', 'Sesi Google tidak valid atau sudah berakhir. Silakan masuk kembali.'); }
}

const LICENSE_KEY_ENCRYPTION_SECRET = { value: () => process.env.LICENSE_KEY_ENCRYPTION_SECRET || '' };
const OWNER_EMAIL = 'muhammadbasuki336@gmail.com';
const TRIAL_DAYS = 7;
const MAX_NORMAL_DAYS = 365;
const MAX_DEVICE_LIMIT = 50;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const LEGACY_SIGNER_DOC = ['_basukiSystem', 'legacySigner'];
let legacyPrivateKeyCache = null;

// [DIPERBAIKI] Kunci Public JWK sudah diganti dengan yang baru agar cocok dengan Private Key di Vercel
const LEGACY_PUBLIC_JWK = {
  kty: 'EC', crv: 'P-256',
  x: '5LBo4M1HIh8e7ksNYT0m8VojRQgRkgUuGTyzGAMQqxo',
  y: 'hthL9Z8MgV985dYIglC-tlRm1IF31DhltzNODrBtfL4'
};
const legacyPublicKey = crypto.createPublicKey({ key: LEGACY_PUBLIC_JWK, format: 'jwk' });

async function getLegacyPrivateKey() {
  initializeFirebase();
  if (legacyPrivateKeyCache) return legacyPrivateKeyCache;

  const snap = await db.collection(LEGACY_SIGNER_DOC[0]).doc(LEGACY_SIGNER_DOC[1]).get();
  const encrypted = snap.exists && snap.data() && snap.data().encryptedPrivateJwk;
  if (!encrypted) {
    throw new HttpsError('failed-precondition', 'Kunci penandatangan belum disiapkan. Login sebagai Owner, buka passphrase admin, lalu coba lagi.');
  }

  try {
    const raw = decryptLicenseKey(encrypted);
    if (!raw) throw new Error('Data kunci kosong.');
    const jwk = JSON.parse(raw);
    const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
    const publicJwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
    if (publicJwk.x !== LEGACY_PUBLIC_JWK.x || publicJwk.y !== LEGACY_PUBLIC_JWK.y) {
      throw new Error('Kunci privat tidak cocok dengan kunci publik APK.');
    }
    legacyPrivateKeyCache = privateKey;
    return privateKey;
  } catch {
    throw new HttpsError('failed-precondition', 'Kunci penandatangan di Firestore tidak valid atau secret enkripsinya berubah.');
  }
}

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

function formatLegacyKey(body) {
  const chunks = body.match(/.{1,6}/g) || [];
  return 'BSK-' + chunks.join('-');
}

async function generateLegacyKey(kind, val) {
  const privateKey = await getLegacyPrivateKey();
  const pl = Buffer.alloc(10);
  pl[0] = 1; // versi
  pl[1] = kind; // 0=abs, 1=rel, 2=permanent
  pl.writeUInt32BE(val, 2);
  crypto.randomFillSync(pl, 6, 4); // random ID 4 byte

  const data = Buffer.concat([Buffer.from('BASUKI-LIC-1', 'utf8'), pl]);
  const sig = crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const all = Buffer.concat([pl, sig]);
  
  return { 
    key: formatLegacyKey(encodeBase32(all)), 
    id: pl.subarray(6, 10).toString('hex') 
  };
}


async function installLegacySigner(request) {
  const owner = ownerIdentity(request);
  const supplied = request.data && request.data.privateJwk;
  try {
    const jwk = typeof supplied === 'string' ? JSON.parse(supplied) : supplied;
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d) {
      throw new Error('JWK privat P-256 tidak lengkap.');
    }
    const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
    const publicJwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
    if (publicJwk.x !== LEGACY_PUBLIC_JWK.x || publicJwk.y !== LEGACY_PUBLIC_JWK.y) {
      throw new Error('Kunci privat admin tidak cocok dengan public key APK.');
    }

    await db.collection(LEGACY_SIGNER_DOC[0]).doc(LEGACY_SIGNER_DOC[1]).set({
      encryptedPrivateJwk: encryptLicenseKey(JSON.stringify(jwk)),
      publicKeyVersion: 'BSK-v11-P256',
      publicKey: { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y },
      installedBy: owner.email,
      updatedAt: FieldValue.serverTimestamp()
    }, { merge: true });

    legacyPrivateKeyCache = privateKey;
    return { ok: true, installed: true, publicKeyVersion: 'BSK-v11-P256' };
  } catch (error) {
    throw new HttpsError('failed-precondition', error.message || 'Gagal memasang kunci penandatangan.');
  }
}

function authIdentity(request) {
  const auth = request && request.auth;
  if (!auth || !auth.uid) throw new HttpsError('unauthenticated', 'Silakan masuk dengan Google terlebih dahulu.');
  const token = auth.token || {};
  const email = String(token.email || '').trim().toLowerCase();
  const provider = token.firebase && token.firebase.sign_in_provider;
  if (provider !== 'google.com' || token.email_verified !== true || !email) {
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

async function legacyLicenseRef(parsed) {
  const collection = db.collection('licenses');
  const baseId = 'legacy_' + parsed.id;
  const baseRef = collection.doc(baseId);
  const baseSnap = await baseRef.get();

  if (!baseSnap.exists || baseSnap.data().keyHash === parsed.keyHash) {
    return baseRef;
  }

  // The payload ID is only 4 random bytes. Keep existing records untouched and
  // use the full SHA-256 of this signed key as a stable collision-safe suffix.
  const collisionRef = collection.doc(baseId + '_' + parsed.keyHash);
  const collisionSnap = await collisionRef.get();
  if (collisionSnap.exists && collisionSnap.data().keyHash !== parsed.keyHash) {
    throw new Error('Hash dokumen lisensi tidak cocok. Hubungi Owner.');
  }
  return collisionRef;
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
  const ref = await legacyLicenseRef(parsed);
  const existing = await ref.get();
  if (existing.exists) {
    const data = existing.data();
    if (data.keyHash !== parsed.keyHash) throw new Error('Hash dokumen lisensi tidak cocok. Hubungi Owner.');
    
    if (parsed.kind === 1 && data.activatedAtMs == null && data.expiresAtMs == null) {
      const now = Date.now();
      const suppliedAct = Number(legacyActivatedAtMs);
      const hasValidAct = Number.isFinite(suppliedAct) && suppliedAct > 0 && suppliedAct <= now + 300000;
      const activatedAtMs = hasValidAct ? suppliedAct : now;
      const expiresAtMs = activatedAtMs + parsed.val * 1000;
      await ref.update({
        activatedAtMs,
        expiresAtMs,
        durationDays: Math.ceil((expiresAtMs - activatedAtMs) / 86400000),
        updatedAt: FieldValue.serverTimestamp()
      });
    }
    return ref;
  }

  const now = Date.now();
  if (parsed.kind === 1 && parsed.val > MAX_NORMAL_DAYS * 86400) throw new Error('Kunci lama melebihi batas 1 tahun; minta Owner membuat kunci baru.');
  let expiresAtMs = null;
  let activatedAtMs = null;
  if (parsed.kind === 2) {
    expiresAtMs = null;
  }
  if (parsed.kind === 0) {
    expiresAtMs = parsed.val * 1000;
    if (expiresAtMs - now > (MAX_NORMAL_DAYS + 1) * 86400000) throw new Error('Kunci lama melebihi batas 1 tahun; minta Owner membuat kunci baru.');
  }
  if (parsed.kind === 1) {
    const suppliedAct = Number(legacyActivatedAtMs);
    const hasValidAct = Number.isFinite(suppliedAct) && suppliedAct > 0 && suppliedAct <= now + 300000;
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
      if (snap.data().keyHash !== parsed.keyHash) throw new Error('Hash dokumen lisensi tidak cocok. Hubungi Owner.');
      return;
    }
    tx.create(ref, {
      licenseId: ref.id,
      keyHash: parsed.keyHash,
      encryptedKey: encryptLicenseKey(raw),
      licenseType: 'legacy',
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
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      lastUsedAt: null
    });
  });
  return ref;
}

async function resolveLicense(key, legacyActivatedAtMs, requireLegacyActivationTime = false) {
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
      at: FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.error('[license event]', error.message);
  }
}

function inferLicenseType(data) {
  const explicit = String(data.licenseType || '').toLowerCase();
  if (['trial', 'paid', 'legacy', 'owner'].includes(explicit)) return explicit;

  const note = String(data.note || '').toLowerCase();
  if (note.includes('trial 7 hari') || note.startsWith('trial')) return 'trial';

  const email = String(data.email || data.buyerEmail || '').toLowerCase();
  if (data.isPermanent && email === OWNER_EMAIL) return 'owner';
  if (data.kind === 'paid') return 'paid';
  return data.kind === 'legacy' ? 'legacy' : (data.kind || 'paid');
}

function licensePublicData(data, activeDeviceCount) {
  return {
    licenseId: data.licenseId,
    email: data.email || data.buyerEmail || null,
    kind: data.kind,
    licenseType: inferLicenseType(data),
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

// [DIUBAH] startTrial menggunakan Kunci v11 (BSK) via server
async function startTrial(request) {
  const user = authIdentity(request);
  if (user.email === OWNER_EMAIL) throw new HttpsError('failed-precondition', 'Akun Owner tidak menggunakan trial. Buat lisensi permanen dari dashboard admin.');

  const now = Date.now();
  const expiresAtMs = now + TRIAL_DAYS * 86400000;
  
  const { key } = await generateLegacyKey(0, Math.floor(expiresAtMs / 1000));
  const parsed = verifyLegacyKey(key);
  const ref = await legacyLicenseRef(parsed);
  const trialRef = db.collection('trialClaims').doc(sha256(user.email));

  try {
    await db.runTransaction(async tx => {
      const used = await tx.get(trialRef);
      if (used.exists) throw new HttpsError('already-exists', 'Akun Google ini sudah pernah menggunakan trial.');
      
      tx.create(ref, {
        licenseId: ref.id,
        keyHash: sha256(normKey(key)),
        encryptedKey: encryptLicenseKey(key),
        licenseType: 'trial',
        keyPrefix: 'BSK-LEGACY',
        keySuffix: parsed.id.slice(-4).toUpperCase(),
        kind: 'legacy',
        legacyKind: 0,
        legacyValue: Math.floor(expiresAtMs / 1000),
        durationDays: TRIAL_DAYS,
        isPermanent: false,
        activatedAtMs: now,
        expiresAtMs: expiresAtMs,
        buyerEmail: user.email,
        email: user.email,
        assignedUid: user.uid,
        note: 'Trial 7 hari (Kunci v11)',
        deviceLimit: 1,
        revoked: false,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
        lastUsedAt: null
      });
      
      tx.create(trialRef, {
        licenseRef: ref.path,
        email: user.email,
        createdAt: FieldValue.serverTimestamp()
      });
    });
  } catch (error) {
    if (error instanceof HttpsError) throw error;
    if (String(error.message).includes('ALREADY_EXISTS')) throw new HttpsError('already-exists', 'Akun Google ini sudah pernah menggunakan trial.');
    console.error('[startTrial]', error);
    throw new HttpsError('internal', 'Gagal membuat trial. Coba lagi.');
  }

  await appendEvent(ref.id, 'trial_created', { email: user.email, detail: 'Trial 7 hari (v11) dibuat.' });
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
      claimedAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });
    response = { licenseId: data.licenseId, email: user.email };
  });

  await appendEvent(ref.id, 'claimed', { email: user.email, detail: 'Lisensi dihubungkan ke akun Google.' });
  return { ok: true, ...response };
}

async function getMyLicenses(request) {
  const user = authIdentity(request);
  const snap1 = await db.collection('licenses').where('assignedUid', '==', user.uid).limit(50).get();
  const snap2 = await db.collection('licenses').where('buyerEmail', '==', user.email).limit(50).get();
  const snap3 = await db.collection('licenses').where('email', '==', user.email).limit(50).get();

  const docsMap = new Map();
  snap1.docs.forEach(doc => docsMap.set(doc.id, doc));
  snap2.docs.forEach(doc => docsMap.set(doc.id, doc));
  snap3.docs.forEach(doc => docsMap.set(doc.id, doc));

  const licenses = Array.from(docsMap.values()).map(doc => {
    const data = doc.data();
    let key = null;
    try { key = decryptLicenseKey(data.encryptedKey); } catch (error) { console.error('[decrypt user license key]', error.message); }
    return { ...licensePublicData(data, 0), key };
  });
  return { licenses };
}

// [DIUBAH] createLicense menggunakan Kunci v11 (BSK) via server
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
    const now = Date.now();
    const expiresAtMs = permanent ? null : now + days * 86400000;
    
    let key;
    if (permanent) {
      const gen = await generateLegacyKey(2, 0); // kind 2 = permanen
      key = gen.key;
    } else {
      const gen = await generateLegacyKey(0, Math.floor(expiresAtMs / 1000)); // kind 0 = absolut
      key = gen.key;
    }

    const parsed = verifyLegacyKey(key);
    const ref = await legacyLicenseRef(parsed);
    await ref.create({
      licenseId: ref.id,
      keyHash: sha256(normKey(key)),
      encryptedKey: encryptLicenseKey(key),
      licenseType: permanent ? 'owner' : 'paid',
      keyPrefix: 'BSK-LEGACY',
      keySuffix: parsed.id.slice(-4).toUpperCase(),
      kind: 'legacy',
      legacyKind: permanent ? 2 : 0,
      legacyValue: permanent ? 0 : Math.floor(expiresAtMs / 1000),
      durationDays: permanent ? null : days,
      isPermanent: permanent,
      activatedAtMs: permanent ? null : now,
      expiresAtMs,
      buyerEmail: email || null,
      email: email || null,
      assignedUid: email === owner.email ? owner.uid : null,
      note,
      deviceLimit,
      revoked: false,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      createdBy: owner.uid,
      lastUsedAt: null
    });
    
    await appendEvent(ref.id, 'created', { email, detail: permanent ? 'Lisensi Owner permanen dibuat.' : `Lisensi ${days} hari dibuat.` });
    created.push({ key, licenseId: ref.id, email: email || null, days: permanent ? null : days, isPermanent: permanent, deviceLimit, expiresAtMs });
  }
  return { ok: true, licenses: created };
}


async function registerOnlineLegacyKeys(request) {
  const owner = ownerIdentity(request);
  const data = request.data || {};
  const keys = Array.isArray(data.keys) ? data.keys.slice(0, 100) : [];
  const email = cleanText(data.email, 180).toLowerCase();
  const note = cleanText(data.note, 180);
  const deviceLimit = Math.floor(Number(data.deviceLimit) || 1);

  if (!keys.length) throw new HttpsError('invalid-argument', 'Masukkan setidaknya satu kunci.');
  if (deviceLimit < 1 || deviceLimit > MAX_DEVICE_LIMIT) {
    throw new HttpsError('invalid-argument', 'Batas perangkat harus 1-50.');
  }
  if (email && (!email.includes('@') || email.indexOf('@') === 0 || email.endsWith('@') || !email.slice(email.indexOf('@') + 1).includes('.'))) {
    throw new HttpsError('invalid-argument', 'Format email tidak valid.');
  }

  const results = [];
  for (const raw of keys) {
    try {
      const key = cleanText(raw, 180);
      const parsed = verifyLegacyKey(key);
      const now = Date.now();
      const permanent = parsed.kind === 2;
      let expiresAtMs = null;
      let activatedAtMs = null;
      let durationDays = null;

      if (parsed.kind === 0) {
        expiresAtMs = parsed.val * 1000;
        if (expiresAtMs <= now) throw new Error('Kunci sudah kedaluwarsa.');
        if (expiresAtMs - now > (MAX_NORMAL_DAYS + 1) * 86400000) {
          throw new Error('Masa berlaku melebihi 365 hari.');
        }
        durationDays = Math.max(1, Math.ceil((expiresAtMs - now) / 86400000));
      } else if (parsed.kind === 1) {
        if (parsed.val < 1 || parsed.val > MAX_NORMAL_DAYS * 86400) {
          throw new Error('Durasi harus 1-365 hari.');
        }
        durationDays = Math.max(1, Math.ceil(parsed.val / 86400));
      }

      const ref = await legacyLicenseRef(parsed);
      const licenseId = ref.id;
      await db.runTransaction(async tx => {
        const snap = await tx.get(ref);
        if (snap.exists) {
          const prior = snap.data();
          if (prior.keyHash !== parsed.keyHash) throw new Error('Hash dokumen lisensi tidak cocok.');
          tx.update(ref, {
            buyerEmail: email || prior.buyerEmail || null,
            email: email || prior.email || null,
            note: note || prior.note || '',
            deviceLimit,
            updatedAt: FieldValue.serverTimestamp()
          });
          return;
        }
        tx.create(ref, {
          licenseId,
          keyHash: parsed.keyHash,
          encryptedKey: encryptLicenseKey(key),
          licenseType: note.toLowerCase().includes('trial') ? 'trial' : (permanent && email === OWNER_EMAIL ? 'owner' : 'legacy'),
          keyPrefix: 'BSK-LEGACY',
          keySuffix: parsed.id.slice(-4).toUpperCase(),
          kind: 'legacy',
          legacyKind: parsed.kind,
          legacyValue: parsed.val,
          durationDays,
          isPermanent: permanent,
          activatedAtMs,
          expiresAtMs,
          buyerEmail: email || null,
          email: email || null,
          assignedUid: null,
          note,
          deviceLimit,
          revoked: false,
          createdAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
          createdBy: owner.uid,
          lastUsedAt: null
        });
      });
      await appendEvent(licenseId, 'created', { email, detail: 'Kunci v11 didaftarkan oleh Owner.' });
      results.push({ ok: true, licenseId });
    } catch (error) {
      results.push({ ok: false, error: error.message || 'Registrasi kunci gagal.' });
    }
  }
  return { ok: true, results };
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

  const updates = { updatedAt: FieldValue.serverTimestamp() };
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
      const devicesSnapshot = await tx.get(ref.collection('devices'));
      const activeDevices = devicesSnapshot.docs
        .filter(device => device.data().status === 'active')
        .sort((a, b) => (toMillis(a.data().lastUse) || 0) - (toMillis(b.data().lastUse) || 0));
      const excess = Math.max(0, activeDevices.length - updates.deviceLimit);
      activeDevices.slice(0, excess).forEach(device => {
        tx.update(device.ref, { status: 'replaced', replacedAt: FieldValue.serverTimestamp(), replacedReason: 'Batas perangkat diturunkan Owner' });
      });
      activeCount = activeDevices.length - excess;
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
      updatedAt: FieldValue.serverTimestamp()
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
      tx.update(deviceRef, { status: 'blocked', updatedAt: FieldValue.serverTimestamp() });
      return;
    }
    const devicesSnapshot = await tx.get(licenseRef.collection('devices'));
    const activeDevices = devicesSnapshot.docs
      .filter(device => device.data().status === 'active')
      .sort((a, b) => (toMillis(a.data().lastUse) || 0) - (toMillis(b.data().lastUse) || 0));
    const currentStatus = deviceSnap.data().status;
    const maxDevices = Math.max(1, Math.min(MAX_DEVICE_LIMIT, Number(licenseSnap.data().deviceLimit) || 1));
    if (currentStatus !== 'active' && activeDevices.length >= maxDevices) {
      const evicted = activeDevices.find(doc => doc.id !== deviceId);
      if (!evicted) throw new HttpsError('failed-precondition', 'Batas perangkat sedang penuh; tidak dapat membuka blokir perangkat ini.');
      tx.update(evicted.ref, { status: 'replaced', replacedAt: FieldValue.serverTimestamp(), replacedReason: 'Perangkat lain diprioritaskan oleh Owner' });
    }
    tx.update(deviceRef, { status: 'active', updatedAt: FieldValue.serverTimestamp() });
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
      const devicesSnapshot = await tx.get(licenseRef.collection('devices'));
      const activeDevices = devicesSnapshot.docs
        .filter(device => device.data().status === 'active')
        .sort((a, b) => (toMillis(a.data().lastUse) || 0) - (toMillis(b.data().lastUse) || 0));
      if (!currentLicense.exists) throw new Error('LICENSE_NOT_FOUND');
      const license = currentLicense.data();
      if (license.revoked) throw new Error('LICENSE_REVOKED');
      if (license.expiresAtMs && Number(license.expiresAtMs) <= Date.now()) throw new Error('LICENSE_EXPIRED');
      if (license.kind !== 'legacy' && !license.assignedUid) throw new Error('LICENSE_NOT_CLAIMED');
      if (currentDevice.exists && currentDevice.data().status === 'blocked') throw new Error('DEVICE_BLOCKED');
      if (body.heartbeat === true && currentDevice.exists && currentDevice.data().status === 'replaced') throw new Error('DEVICE_REPLACED');

      const isCurrentActive = currentDevice.exists && currentDevice.data().status === 'active';
      newlyActivated = !isCurrentActive;
      const maxDevices = Math.max(1, Math.min(MAX_DEVICE_LIMIT, Number(license.deviceLimit) || 1));
      let evicted = null;
      if (!isCurrentActive && activeDevices.length >= maxDevices) {
        evicted = activeDevices.find(doc => doc.id !== deviceHash) || null;
        if (!evicted) throw new Error('DEVICE_LIMIT');
      }
      if (evicted) {
        replacedDeviceId = evicted.id;
        tx.update(evicted.ref, {
          status: 'replaced',
          replacedAt: FieldValue.serverTimestamp(),
          replacedReason: 'Perangkat baru memakai kunci yang sama'
        });
      }
      const deviceData = currentDevice.exists ? currentDevice.data() : {};
      tx.set(deviceRef, {
        deviceModel,
        androidVersion,
        status: 'active',
        firstLogin: deviceData.firstLogin || FieldValue.serverTimestamp(),
        lastUse: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      const activeCount = Math.min(maxDevices, activeDevices.length + (isCurrentActive ? 0 : 1) - (evicted ? 1 : 0));
      tx.update(licenseRef, {
        lastUsedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
        activeDeviceCount: activeCount
      });
      const expiresAtMs = license.expiresAtMs || null;
      responseData = {
        ok: true,
        status: 'active',
        licenseId: license.licenseId,
        email: license.email || license.buyerEmail || null,
        expiresAtMs,
        activatedAtMs: license.activatedAtMs || null,
        serverTimeMs: Date.now(),
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
    const diagnosticCode = error && error.code != null ? String(error.code) : 'UNKNOWN';
    const diagnosticType = error && error.name ? String(error.name) : 'Error';
    const diagnosticId = crypto.randomUUID();
    console.error('[licenseDevice]', {
      diagnosticId,
      diagnosticCode,
      diagnosticType,
      message: error && error.message,
      stack: error && error.stack
    });
    return res.status(500).json({
      ok: false,
      error: 'SERVER_ERROR',
      diagnosticCode,
      diagnosticType,
      diagnosticId,
      message: `Server lisensi gagal pada pemeriksaan perangkat. Kode: ${diagnosticCode}. ID: ${diagnosticId}.`
    });
  }
}

async function deleteLicense(request) {
  ownerIdentity(request);
  const data = request.data || {};
  const licenseDocId = cleanText(data.licenseDocId, 140);
  if (!licenseDocId) throw new HttpsError('invalid-argument', 'ID dokumen lisensi tidak ditemukan.');

  const ref = db.collection('licenses').doc(licenseDocId);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError('not-found', 'Lisensi tidak ditemukan atau sudah dihapus.');

  const devicesSnap = await ref.collection('devices').get();
  const batch = db.batch();
  devicesSnap.docs.forEach(doc => batch.delete(doc.ref));
  
  batch.delete(ref);
  await batch.commit();

  await appendEvent(licenseDocId, 'license_deleted', { 
    email: snap.data().email || snap.data().buyerEmail,
    detail: 'Lisensi dihapus permanen oleh Owner.' 
  });

  return { ok: true, message: 'Lisensi berhasil dihapus.' };
}

async function testGoogleOAuth() {
  initializeFirebase();
  if (!firebaseCredential || typeof firebaseCredential.getAccessToken !== 'function') {
    const error = new Error('Firebase Admin credential tidak menyediakan getAccessToken().');
    error.code = 'GOOGLE_OAUTH_CREDENTIAL_MISSING';
    throw error;
  }
  try {
    const tokenInfo = await firebaseCredential.getAccessToken();
    if (!tokenInfo || typeof tokenInfo.access_token !== 'string' || !tokenInfo.access_token) {
      const error = new Error('Google tidak mengembalikan OAuth access token untuk service account ini.');
      error.code = 'GOOGLE_OAUTH_EMPTY_TOKEN';
      throw error;
    }
    return {
      authenticated: true,
      tokenObtained: true,
      expiresInSeconds: Number.isFinite(Number(tokenInfo.expires_in)) ? Number(tokenInfo.expires_in) : null
    };
  } catch (cause) {
    const error = new Error(`Google OAuth token exchange gagal: ${cause && cause.message ? cause.message : 'Unknown OAuth error'}`);
    error.name = 'GoogleOAuthError';
    error.code = cause && cause.code ? cause.code : 'GOOGLE_OAUTH_FAILED';
    throw error;
  }
}

async function backendHealth() {
  initializeFirebase();
  await db.collection('_basukiSystem').doc('health').get();
  const signerSnap = await db.collection(LEGACY_SIGNER_DOC[0]).doc(LEGACY_SIGNER_DOC[1]).get();
  const signerData = signerSnap.exists ? signerSnap.data() : null;
  return {
    ok: true,
    firebaseAdmin: true,
    firestore: true,
    legacySigner: {
      ready: !!(signerData && signerData.encryptedPrivateJwk),
      publicKeyVersion: 'BSK-v11-P256'
    }
  };
}

module.exports = {
  initializeFirebase,
  serviceAccountDiagnostics,
  testGoogleOAuth,
  backendHealth,
  verifyFirebaseIdToken,
  HttpsError,
  handlers: {
    startTrial,
    installLegacySigner,
    registerOnlineLegacyKeys, 
    claimLicense, 
    getMyLicenses, 
    createLicense,
    adminListLicenses, 
    updateLicense, 
    extendLicense, 
    updateDevice,
    deleteLicense
  },
  licenseDevice
};
