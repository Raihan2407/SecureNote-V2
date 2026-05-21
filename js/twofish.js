/**
 * Twofish Block Cipher - Implementasi Manual
 * Mode: CBC (Cipher Block Chaining)
 * Key Size: 128-bit (16 byte)
 * Block Size: 128-bit (16 byte)
 * Rounds: 16
 *
 * Referensi: Schneier et al. (1998). Twofish: A 128-Bit Block Cipher.
 */

const Twofish = (() => {

  // ─── KONSTANTA ───────────────────────────────────────────────────────────────

  const BLOCK_SIZE = 16;
  const ROUNDS = 16;

  // Q-box permutasi (fixed)
  const Q0 = new Uint8Array([
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
  ]);

  const Q1 = new Uint8Array([
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
  ]);

  // MDS matrix entries di GF(2^8) dengan irreducible polynomial 0x169
  const MDS = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
  ];

  // ─── HELPER ──────────────────────────────────────────────────────────────────

  function u32(n) { return n >>> 0; }

  function rotl32(x, n) { return u32((x << n) | (x >>> (32 - n))); }
  function rotr32(x, n) { return u32((x >>> n) | (x << (32 - n))); }

  // Perkalian GF(2^8) mod 0x169
  function gfMul(a, b) {
    let r = 0;
    a &= 0xFF; b &= 0xFF;
    for (let i = 0; i < 8; i++) {
      if (b & 1) r ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xFF;
      if (hi) a ^= 0x69;
      b >>= 1;
    }
    return r & 0xFF;
  }

  // Little-endian bytes → uint32
  function getU32(buf, off) {
    return u32(buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24));
  }

  // uint32 → little-endian bytes
  function putU32(buf, off, v) {
    v = u32(v);
    buf[off] = v & 0xFF;
    buf[off + 1] = (v >>> 8) & 0xFF;
    buf[off + 2] = (v >>> 16) & 0xFF;
    buf[off + 3] = (v >>> 24) & 0xFF;
  }

  // ─── FUNGSI q ─────────────────────────────────────────────────────────────────

  function q(which, x) {
    return (which ? Q1 : Q0)[x & 0xFF];
  }

  // ─── FUNGSI h (MDS ∘ q) ───────────────────────────────────────────────────────

  // Untuk 128-bit key: menggunakan 2 key words (Me[0], Me[1]) atau (Mo[0], Mo[1])
  function hFunc(x, L) {
    let y0 = (x) & 0xFF;
    let y1 = (x >>> 8) & 0xFF;
    let y2 = (x >>> 16) & 0xFF;
    let y3 = (x >>> 24) & 0xFF;

    // 128-bit: 2 key words
    y0 = q(1, y0) ^ (L[1] & 0xFF);
    y1 = q(0, y1) ^ ((L[1] >>> 8) & 0xFF);
    y2 = q(0, y2) ^ ((L[1] >>> 16) & 0xFF);
    y3 = q(1, y3) ^ ((L[1] >>> 24) & 0xFF);

    y0 = q(1, y0) ^ (L[0] & 0xFF);
    y1 = q(1, y1) ^ ((L[0] >>> 8) & 0xFF);
    y2 = q(0, y2) ^ ((L[0] >>> 16) & 0xFF);
    y3 = q(0, y3) ^ ((L[0] >>> 24) & 0xFF);

    y0 = q(1, y0);
    y1 = q(0, y1);
    y2 = q(1, y2);
    y3 = q(0, y3);

    // MDS multiply
    const z0 = gfMul(MDS[0][0], y0) ^ gfMul(MDS[0][1], y1) ^ gfMul(MDS[0][2], y2) ^ gfMul(MDS[0][3], y3);
    const z1 = gfMul(MDS[1][0], y0) ^ gfMul(MDS[1][1], y1) ^ gfMul(MDS[1][2], y2) ^ gfMul(MDS[1][3], y3);
    const z2 = gfMul(MDS[2][0], y0) ^ gfMul(MDS[2][1], y1) ^ gfMul(MDS[2][2], y2) ^ gfMul(MDS[2][3], y3);
    const z3 = gfMul(MDS[3][0], y0) ^ gfMul(MDS[3][1], y1) ^ gfMul(MDS[3][2], y2) ^ gfMul(MDS[3][3], y3);

    return u32(z0 | (z1 << 8) | (z2 << 16) | (z3 << 24));
  }

  // ─── KEY SCHEDULE ─────────────────────────────────────────────────────────────

  function keySchedule(keyBytes) {
    // 128-bit key → 4 words
    const W = new Uint32Array(4);
    for (let i = 0; i < 4; i++) W[i] = getU32(keyBytes, i * 4);

    // Me = even words, Mo = odd words
    const Me = [W[0], W[2]];
    const Mo = [W[1], W[3]];

    // Sub-key generation
    const K = new Uint32Array(40);
    const RHO = 0x01010101;

    for (let i = 0; i < 20; i++) {
      const A = hFunc(u32(2 * i * RHO), Me);
      const B = rotl32(hFunc(u32((2 * i + 1) * RHO), Mo), 8);
      K[2 * i] = u32(A + B);
      K[2 * i + 1] = rotl32(u32(A + 2 * B), 9);
    }

    return { K, Me, Mo };
  }

  // ─── ENKRIPSI SATU BLOK ───────────────────────────────────────────────────────

  function encryptBlock(src, dst, srcOff, dstOff, K, Me, Mo) {
    // Load plaintext (little-endian)
    let X0 = getU32(src, srcOff);
    let X1 = getU32(src, srcOff + 4);
    let X2 = getU32(src, srcOff + 8);
    let X3 = getU32(src, srcOff + 12);

    // Input whitening
    X0 = u32(X0 ^ K[0]);
    X1 = u32(X1 ^ K[1]);
    X2 = u32(X2 ^ K[2]);
    X3 = u32(X3 ^ K[3]);

    // 16 putaran Feistel
    for (let r = 0; r < ROUNDS; r++) {
      const T0 = hFunc(X0, Me);
      const T1 = hFunc(rotl32(X1, 8), Mo);

      X2 = u32(rotr32(u32(X2 ^ u32(T0 + T1 + K[2 * r + 8])), 1));
      X3 = u32(rotl32(X3, 1) ^ u32(T0 + 2 * T1 + K[2 * r + 9]));

      // Swap (kecuali putaran terakhir)
      if (r < ROUNDS - 1) {
        let tmp;
        tmp = X0; X0 = X2; X2 = tmp;
        tmp = X1; X1 = X3; X3 = tmp;
      }
    }

    // Output whitening (dengan posisi sudah di-swap balik)
    putU32(dst, dstOff, u32(X2 ^ K[4]));
    putU32(dst, dstOff + 4, u32(X3 ^ K[5]));
    putU32(dst, dstOff + 8, u32(X0 ^ K[6]));
    putU32(dst, dstOff + 12, u32(X1 ^ K[7]));
  }

  // ─── DEKRIPSI SATU BLOK ───────────────────────────────────────────────────────

  function decryptBlock(src, dst, srcOff, dstOff, K, Me, Mo) {
    // Load ciphertext
    let X2 = u32(getU32(src, srcOff) ^ K[4]);
    let X3 = u32(getU32(src, srcOff + 4) ^ K[5]);
    let X0 = u32(getU32(src, srcOff + 8) ^ K[6]);
    let X1 = u32(getU32(src, srcOff + 12) ^ K[7]);

    // 16 putaran Feistel terbalik
    for (let r = ROUNDS - 1; r >= 0; r--) {
      // Swap balik (kecuali putaran terakhir yang di-reverse = putaran pertama)
      if (r < ROUNDS - 1) {
        let tmp;
        tmp = X0; X0 = X2; X2 = tmp;
        tmp = X1; X1 = X3; X3 = tmp;
      }

      const T0 = hFunc(X0, Me);
      const T1 = hFunc(rotl32(X1, 8), Mo);

      X2 = u32(rotl32(X2, 1) ^ u32(T0 + T1 + K[2 * r + 8]));
      X3 = u32(rotr32(u32(X3 ^ u32(T0 + 2 * T1 + K[2 * r + 9])), 1));
    }

    // Undo input whitening
    putU32(dst, dstOff, u32(X0 ^ K[0]));
    putU32(dst, dstOff + 4, u32(X1 ^ K[1]));
    putU32(dst, dstOff + 8, u32(X2 ^ K[2]));
    putU32(dst, dstOff + 12, u32(X3 ^ K[3]));
  }

  // ─── PKCS#7 PADDING ───────────────────────────────────────────────────────────

  function addPadding(data) {
    const pad = BLOCK_SIZE - (data.length % BLOCK_SIZE);
    const padded = new Uint8Array(data.length + pad);
    padded.set(data);
    for (let i = data.length; i < padded.length; i++) padded[i] = pad;
    return padded;
  }

  function removePadding(data) {
    const pad = data[data.length - 1];
    if (pad === 0 || pad > BLOCK_SIZE) return null;
    for (let i = data.length - pad; i < data.length; i++) {
      if (data[i] !== pad) return null;
    }
    return data.slice(0, data.length - pad);
  }

  // ─── KEY DERIVATION ───────────────────────────────────────────────────────────

  function deriveKey(password) {
    const enc = new TextEncoder();
    const pw = enc.encode(password);
    const key = new Uint8Array(16);

    // XOR fold
    for (let i = 0; i < pw.length; i++) key[i % 16] ^= pw[i];

    // Mixing dengan Q-tables agar distribusinya lebih baik
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 16; i++) {
        key[i] = Q1[(key[i] ^ Q0[(key[(i + 1) % 16] + round) & 0xFF]) & 0xFF];
      }
    }
    return key;
  }

  // ─── CBC ENCRYPT ──────────────────────────────────────────────────────────────

  function encrypt(plaintext, password) {
    const enc = new TextEncoder();
    const data = addPadding(enc.encode(plaintext));
    const key = deriveKey(password);
    const { K, Me, Mo } = keySchedule(key);

    // Random IV
    const iv = new Uint8Array(BLOCK_SIZE);
    crypto.getRandomValues(iv);

    const out = new Uint8Array(BLOCK_SIZE + data.length);
    out.set(iv, 0);

    // CBC: XOR plaintext blok dengan ciphertext blok sebelumnya (atau IV)
    const prev = new Uint8Array(iv);
    const blk = new Uint8Array(BLOCK_SIZE);
    const enc2 = new Uint8Array(BLOCK_SIZE);

    for (let i = 0; i < data.length; i += BLOCK_SIZE) {
      // XOR dengan prev
      for (let j = 0; j < BLOCK_SIZE; j++) blk[j] = data[i + j] ^ prev[j];

      encryptBlock(blk, enc2, 0, 0, K, Me, Mo);

      out.set(enc2, BLOCK_SIZE + i);
      prev.set(enc2);
    }

    // Base64
    let bin = '';
    for (let i = 0; i < out.length; i++) bin += String.fromCharCode(out[i]);
    return btoa(bin);
  }

  // ─── CBC DECRYPT ──────────────────────────────────────────────────────────────

  function decrypt(ciphertextB64, password) {
    try {
      const bin = atob(ciphertextB64);
      const raw = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);

      // Validasi panjang: IV (16) + minimal 1 blok (16), harus kelipatan 16
      if (raw.length < BLOCK_SIZE * 2 || (raw.length - BLOCK_SIZE) % BLOCK_SIZE !== 0) return null;

      const iv = raw.slice(0, BLOCK_SIZE);
      const ciphertext = raw.slice(BLOCK_SIZE);

      const key = deriveKey(password);
      const { K, Me, Mo } = keySchedule(key);

      const plain = new Uint8Array(ciphertext.length);
      const prev = new Uint8Array(iv);
      const dec = new Uint8Array(BLOCK_SIZE);

      for (let i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
        const blk = ciphertext.slice(i, i + BLOCK_SIZE);
        decryptBlock(blk, dec, 0, 0, K, Me, Mo);

        // XOR dengan prev (CBC)
        for (let j = 0; j < BLOCK_SIZE; j++) plain[i + j] = dec[j] ^ prev[j];
        prev.set(blk);
      }

      // Validasi padding
      const unpadded = removePadding(plain);
      if (unpadded === null) return null;

      // Decode UTF-8 (strict — throw jika bukan UTF-8 valid)
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(unpadded);
      if (decoded.length === 0) return null;

      return decoded;
    } catch (e) {
      return null;
    }
  }

  // ─── PUBLIC API ───────────────────────────────────────────────────────────────

  return { encrypt, decrypt };

})();