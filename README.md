# 🔐 SecureNote

> Aplikasi catatan terenkripsi berbasis web menggunakan algoritma **Twofish CBC 128-bit** — diimplementasikan secara manual tanpa library kriptografi eksternal.

---

## 📌 Deskripsi

SecureNote adalah aplikasi web yang memungkinkan pengguna menyimpan catatan pribadi secara aman. Setiap catatan dienkripsi menggunakan algoritma **Twofish** dengan mode **CBC (Cipher Block Chaining)** dan kunci **128-bit** sebelum disimpan ke database. Tanpa kunci enkripsi yang benar, isi catatan tidak dapat dibaca oleh siapapun — termasuk administrator database.

Proyek ini dibuat sebagai tugas mata kuliah **Sistem Keamanan** dengan topik **Twofish (Nomor 12)**.

---

## ✨ Fitur

- 🔒 Enkripsi dan dekripsi catatan dengan algoritma Twofish CBC 128-bit
- 👤 Sistem autentikasi (register & login) dengan password di-hash menggunakan **bcrypt**
- 📝 Buat, baca, edit, dan hapus catatan terenkripsi
- 🔑 Validasi kekuatan kunci enkripsi (Lemah / Sedang / Kuat)
- 👁️ Toggle show/hide password
- 🗄️ Penyimpanan data di MySQL — ciphertext tersimpan, bukan plaintext
- 🌐 Dapat diakses secara publik via ngrok

---

## 🛠️ Teknologi

| Komponen | Teknologi |
|----------|-----------|
| Frontend | HTML, CSS, JavaScript (Vanilla) |
| Backend  | PHP 8.x |
| Database | MySQL (via XAMPP) |
| Algoritma | Twofish CBC 128-bit (implementasi manual) |
| Password Hashing | bcrypt (`password_hash` PHP) |
| Web Server | Apache (XAMPP) |

---

## 📁 Struktur Folder

```
siskem/
│
├── login.html          # Halaman login
├── register.html       # Halaman registrasi
├── index.html          # Halaman daftar catatan
├── create.html         # Halaman buat catatan baru
├── view.html           # Halaman buka & kelola catatan
│
├── css/
│   └── style.css       # Styling seluruh halaman
│
├── js/
│   ├── twofish.js      # Implementasi manual algoritma Twofish
│   └── app.js          # Logika aplikasi & koneksi API
│
└── api/
    ├── config.php          # Konfigurasi database & session
    ├── config.example.php  # Contoh konfigurasi (tanpa kredensial)
    ├── database.sql        # SQL pembuatan database & tabel awal
    ├── update_db.sql       # SQL update (tambah tabel users & kolom user_id)
    ├── check_session.php   # Cek status login
    ├── login.php           # API login
    ├── logout.php          # API logout
    ├── register.php        # API registrasi
    ├── get_notes.php       # API ambil semua catatan
    ├── get_note.php        # API ambil catatan by ID
    ├── save_note.php       # API simpan catatan baru
    ├── edit_note.php       # API edit catatan
    └── delete_note.php     # API hapus catatan
```

---

## ⚙️ Cara Instalasi & Menjalankan

### Prasyarat
- [XAMPP](https://www.apachefriends.org/) (Apache + MySQL + PHP 8.x)
- Browser modern (Chrome, Firefox, Edge)

### Langkah-langkah

**1. Clone repository**
```bash
git clone https://github.com/Raihan2407/SecureNote-V2.git
```

**2. Pindahkan ke htdocs XAMPP**
```
Salin folder hasil clone ke:
C:\xampp\htdocs\siskem\
```

**3. Buat file konfigurasi database**
```bash
# Salin file contoh konfigurasi
cp api/config.example.php api/config.php
```
Lalu sesuaikan isi `api/config.php` dengan kredensial database kamu.

**4. Setup database**
- Jalankan XAMPP → Start **Apache** dan **MySQL**
- Buka `http://localhost/phpmyadmin`
- Import file `api/database.sql` terlebih dahulu
- Lalu import file `api/update_db.sql`

**5. Jalankan aplikasi**
```
Buka browser → http://localhost/siskem
```

---

## 🔐 Cara Kerja Enkripsi

```
[Plaintext]
     ↓
[Key Derivation — XOR fold + Q-table mixing → 128-bit key]
     ↓
[Key Schedule — 40 sub-keys]
     ↓
[PKCS#7 Padding]
     ↓
[Random IV (128-bit) via crypto.getRandomValues()]
     ↓
[CBC Mode — XOR plaintext blok dengan IV/ciphertext sebelumnya]
     ↓
[Twofish Block Encryption — 16 putaran Feistel]
     ↓
[Output Whitening]
     ↓
[IV + Ciphertext → Base64 → disimpan ke database]
```

Dekripsi adalah kebalikan dari proses di atas. Kunci yang salah akan menghasilkan padding yang tidak valid dan ditolak oleh sistem.

---

## 👥 Anggota Kelompok

| Nama | NIM |
|------|-----|
| RAIHAN DARMA PUTRA | 2401020138 |
| YEHEZKIEL ALMAN SIAMBATON | 2401020110 |
| MUHAMMAD KHAERUL SUKANDAR | 2401020131 |

**Kelas:** Kelas B — Mata Kuliah Sistem Keamanan

---

## 📚 Referensi

- Schneier, B., et al. (1998). *Twofish: A 128-Bit Block Cipher*. https://www.schneier.com/academic/twofish/
- Rahman, Z., et al. (2020). Implementasi Metode Enkripsi dan Deskripsi File menggunakan Algoritma Twofish. *BUSITI Vol. 1 No. 2*. https://jurnal.fikom.umi.ac.id/index.php/BUSITI/article/view/741
- Awal, E.E., et al. (2022). Analisis Perbandingan Hasil Enkripsi dan Dekripsi Algoritma Kriptografi Rijndael dan Twofish untuk Penyandian Data. *Jurnal Mahasiswa Ilmu Komputer*.

---

## 📄 Lisensi

Proyek ini dibuat untuk keperluan akademik. Bebas digunakan sebagai referensi pembelajaran.