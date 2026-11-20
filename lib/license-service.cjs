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
  return { ok: true, firebaseAdmin: true, firestore: true, legacySigner: { ready: !!(signerData && signerData.encryptedPrivateJwk), publicKeyVersion: 'BSK-v11-P256' } };
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
    claimLicense, 
    getMyLicenses, 
    createLicense,
    adminListLicenses, 
    updateLicense, 
    extendLicense, 
    updateDevice,
    deleteLicense
  },
