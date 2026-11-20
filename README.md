# Basuki Music — Website Admin Lisensi (Vercel)

Ini adalah **satu website admin/pembuat kunci**, memakai HTML admin Basuki Music yang kamu kirim sebagai dasar dan mempertahankan pembuat kunci v11 lama. Tidak ada website admin kedua.

## Isi proyek

- `public/index.html` — halaman website tunggal: login Google, trial/klaim kunci pengguna, pembuat kunci dan dashboard Owner.
- `api/` — API serverless yang dijalankan Vercel (konfigurasi, health check, pengelolaan lisensi, validasi perangkat aplikasi).
- `lib/license-service.cjs` — logika server lisensi dan akses Firestore menggunakan Firebase Admin SDK.
- `firestore.rules` dan `firestore.indexes.json` — aturan keamanan dan indeks database Firebase.
- `firebase.json` — hanya untuk deploy rules/indexes Firestore; bukan untuk Firebase Hosting atau Cloud Functions.

`admin-original.html` tidak disertakan karena hanya salinan lama. Halaman produksi adalah `public/index.html`.

## Fitur yang disiapkan

- Trial 7 hari, satu kali per email Google terverifikasi.
- Kunci biasa 1–365 hari dan permanen khusus Owner `muhammadbasuki336@gmail.com`.
- Batas perangkat 1–50 yang dapat diatur per kunci.
- HP baru otomatis menggantikan perangkat aktif yang paling lama tidak dipakai saat batas tercapai.
- Dashboard Owner menampilkan email, kunci online, model HP, versi Android, aktivasi pertama, penggunaan terakhir, status perangkat, dan riwayat aktivitas.
- Owner dapat blokir/buka blokir lisensi atau perangkat, mengubah batas perangkat, dan memperpanjang lisensi.
- Kunci v11 lama dapat didaftarkan ke server saat digunakan pada APK yang sudah dipatch.

## 1. Siapkan Firebase (wajib satu kali)

Website di-host di Vercel, tetapi login Google dan database tetap memakai Firebase.

1. Buat project Firebase.
2. Aktifkan **Authentication → Sign-in method → Google**.
3. Tambahkan domain Vercel (`nama-project.vercel.app`) di **Authentication → Settings → Authorized domains**. Tambahkan custom domain juga bila dipakai.
4. Buat database **Cloud Firestore** (Native mode).
5. Daftarkan Web App di **Project settings → Your apps**. Catat `apiKey`, `appId`, dan `messagingSenderId`.
6. Buat service account Firebase Admin SDK dan unduh JSON key-nya. Beri akun itu izin untuk mengelola Authentication dan Firestore (misalnya role Firebase Admin). **Jangan masukkan JSON ini ke GitHub atau folder `public`.**
7. Siapkan rahasia acak minimal 32 karakter untuk `LICENSE_KEY_ENCRYPTION_SECRET`. Jangan menggantinya setelah kunci online dibuat karena kunci tersimpan terenkripsi dengan secret tersebut.

## 2. Deploy website ke Vercel

1. Unggah isi folder proyek ini ke repository GitHub.
2. Di Vercel pilih **Add New → Project**, impor repository itu, dan deploy. Pilih framework **Other** bila diminta. `vercel.json` sudah mengarahkan file website ke `public/`; API ada di `api/`.
3. Di **Vercel → Project → Settings → Environment Variables**, tambahkan variabel berikut untuk Production (dan Preview bila ingin menguji preview):

| Nama variabel | Nilai |
|---|---|
| `FIREBASE_PROJECT_ID` | Project ID Firebase |
| `FIREBASE_WEB_API_KEY` | `apiKey` dari Firebase Web App |
| `FIREBASE_APP_ID` | `appId` dari Firebase Web App |
| `FIREBASE_AUTH_DOMAIN` | `PROJECT_ID.firebaseapp.com` |
| `FIREBASE_MESSAGING_SENDER_ID` | `messagingSenderId` dari Firebase Web App |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Seluruh isi JSON service account, sebagai satu nilai JSON |
| `LICENSE_KEY_ENCRYPTION_SECRET` | Rahasia acak minimal 32 karakter |

4. Untuk `FIREBASE_SERVICE_ACCOUNT_JSON`, buka file JSON key, salin seluruh isinya, dan tempel sebagai nilai environment variable. Jangan menambah tanda kutip di luar JSON. `private_key` harus tetap bagian dari JSON valid.
5. Klik **Redeploy** agar variabel dipakai oleh API.
6. Buka `https://DOMAIN-VERCEL/api/health`. Empat nilai dalam `configured` harus `true`.
7. Buka `https://DOMAIN-VERCEL/` dan masuk dengan Google. Email Owner yang diizinkan: `muhammadbasuki336@gmail.com`. Setelah login Owner, masukkan passphrase admin lama untuk membuka pembuat kunci dan dashboard.

Tidak ada file kode yang harus kamu edit untuk mengisi Firebase; semua konfigurasi dibaca dari Environment Variables Vercel.

## 3. Pasang rules dan indexes Firestore

Dari folder proyek jalankan satu kali:

```bash
npm install -g firebase-tools
firebase login
firebase use --add
firebase deploy --only firestore:rules,firestore:indexes
```

Pilih project Firebase yang sama dengan `FIREBASE_PROJECT_ID`. Perintah itu hanya memasang Firestore Rules dan Indexes. Website dan API tetap di Vercel, bukan Firebase Hosting atau Cloud Functions.

## 4. API yang tersedia

- `GET /api/config` — memberikan konfigurasi publik untuk Firebase Web SDK.
- `GET /api/health` — memeriksa keberadaan pengaturan server tanpa membocorkan nilainya.
- `POST /api/license` — fungsi website; membutuhkan Firebase ID token pada header `Authorization: Bearer ...`.
- `POST /api/license-device` — validasi aktivasi dan heartbeat dari APK.

## 5. Hubungan website dengan APK

Website Vercel dan APK adalah dua bagian berbeda. Website bisa di-deploy terlebih dahulu. Untuk membuat fitur blokir/batas perangkat berlaku di APK, halaman utama di dalam aplikasi harus dipatch dan APK harus dibangun ulang.

File patch APK terpisah dari ZIP proyek Vercel. Setelah domain Vercel tersedia, isi `LIC_API_URL` dengan `https://DOMAIN-VERCEL/api/license-device` dan `LIC_CONTACT` dengan `https://DOMAIN-VERCEL/`, lalu masukkan sebagai `app/src/main/assets/index.html` dalam project Android/Gradle. Build dan tanda tangani memakai release keystore yang sama dengan APK terpasang.

**Patch bukan APK siap instal.** Mengedit langsung isi APK yang sudah ditandatangani akan merusak tanda tangannya. APK final belum dibuat atau diuji pada perangkat Android dalam paket ini.

## Catatan penting

- Semua operasi lisensi/admin divalidasi di server. Email Owner tidak dipercaya hanya dari tampilan browser.
- ID perangkat berupa ID acak instalasi, bukan IMEI/serial number. Menghapus data aplikasi dapat menghasilkan ID instalasi baru.
- Perubahan blokir berlaku saat aplikasi online dan berhasil memeriksa server berikutnya; perangkat offline baru menerima perubahan setelah tersambung kembali.
- Uji dulu trial kedua pada akun yang sama (harus ditolak), klaim kunci dari akun berbeda, aktivasi perangkat kedua, blokir perangkat, blokir lisensi, dan perpanjangan masa aktif.

## 6. Penyiapan kunci penandatangan APK (satu kali)

Setelah kode terbaru ter-deploy dan Environment Variables terisi:

1. Buka website, login sebagai Owner, lalu buka kunci admin memakai passphrase yang sudah ada.
2. Saat admin terbuka, website mengirim JWK privat melalui HTTPS. Server memastikan pasangan kunci cocok dengan public key yang tertanam di APK, lalu menyimpan JWK privat secara terenkripsi di Firestore.
3. Buka `/api/health`. Pastikan `ok: true` dan `legacySigner.ready: true`. API health tidak mengirim JWK privat.
4. Setelah itu, pengguna dapat menghubungkan kunci dari website dan APK memeriksa lisensi melalui `/api/license-device`.

Jangan mengganti `LICENSE_KEY_ENCRYPTION_SECRET` setelah signer tersimpan. Jika secret berubah, data signer tidak dapat dibuka lagi dan harus dipasang ulang menggunakan kunci yang benar.
