/**
 * Twofish Block Cipher - Implementasi Manual
 * Mode: CBC (Cipher Block Chaining)
 * Key Size: 128-bit
 * Block Size: 128-bit
 * 
 * Referensi: Schneier, B., et al. (1998). Twofish: A 128-Bit Block Cipher
 */

const Twofish = (() => {

  // ─── KONSTANTA ───────────────────────────────────────────────────────────────

  const BLOCK_SIZE = 16; // 128-bit = 16 byte
  const ROUNDS = 16;

  // MDS Matrix (Maximum Distance Separable)
  const MDS = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
  ];

  // RS Matrix untuk key schedule
  const RS = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
  ];

  // Q0 dan Q1 permutation tables
  const Q0 = [
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
  ];

  const Q1 = [
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
  ];

  // ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

  function uint32(n) {
    return n >>> 0;
  }

  function rotl32(x, n) {
    return uint32((x << n) | (x >>> (32 - n)));
  }

  function rotr32(x, n) {
    return uint32((x >>> n) | (x << (32 - n)));
  }

  // Perkalian di GF(2^8) dengan polynomial 0x169
  function gfMul(a, b) {
    let result = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) result ^= a;
      const hiBit = a & 0x80;
      a = (a << 1) & 0xFF;
      if (hiBit) a ^= 0x69;
      b >>= 1;
    }
    return result;
  }

  // Konversi bytes ke word 32-bit (little-endian)
  function bytesToWord(bytes, offset) {
    return uint32(
      bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)
    );
  }

  // Konversi word 32-bit ke bytes (little-endian)
  function wordToBytes(word, bytes, offset) {
    bytes[offset]     = word & 0xFF;
    bytes[offset + 1] = (word >> 8) & 0xFF;
    bytes[offset + 2] = (word >> 16) & 0xFF;
    bytes[offset + 3] = (word >> 24) & 0xFF;
  }

  // ─── FUNGSI q (PERMUTASI) ────────────────────────────────────────────────────

  function q(which, x) {
    const table = which === 0 ? Q0 : Q1;
    return table[x & 0xFF];
  }

  // ─── FUNGSI h (S-BOX + MDS) ──────────────────────────────────────────────────

  function h(x, L) {
    let y = [
      (x) & 0xFF,
      (x >> 8) & 0xFF,
      (x >> 16) & 0xFF,
      (x >> 24) & 0xFF,
    ];

    // Untuk 128-bit key (2 kata kunci)
    y[0] = q(1, y[0]) ^ ((L[1]) & 0xFF);
    y[1] = q(0, y[1]) ^ ((L[1] >> 8) & 0xFF);
    y[2] = q(0, y[2]) ^ ((L[1] >> 16) & 0xFF);
    y[3] = q(1, y[3]) ^ ((L[1] >> 24) & 0xFF);

    y[0] = q(1, y[0]) ^ ((L[0]) & 0xFF);
    y[1] = q(1, y[1]) ^ ((L[0] >> 8) & 0xFF);
    y[2] = q(0, y[2]) ^ ((L[0] >> 16) & 0xFF);
    y[3] = q(0, y[3]) ^ ((L[0] >> 24) & 0xFF);

    y[0] = q(1, y[0]);
    y[1] = q(0, y[1]);
    y[2] = q(1, y[2]);
    y[3] = q(0, y[3]);

    // Perkalian MDS
    let result = 0;
    for (let i = 0; i < 4; i++) {
      let val = 0;
      for (let j = 0; j < 4; j++) {
        val ^= gfMul(MDS[i][j], y[j]);
      }
      result |= (val & 0xFF) << (i * 8);
    }
    return uint32(result);
  }

  // ─── KEY SCHEDULE ────────────────────────────────────────────────────────────

  function keySchedule(key) {
    // key adalah array 16 byte (128-bit)
    const Me = [bytesToWord(key, 0), bytesToWord(key, 8)];
    const Mo = [bytesToWord(key, 4), bytesToWord(key, 12)];

    const K = [];
    const RHO = 0x01010101;

    for (let i = 0; i < 20; i++) {
      const A = h(uint32(2 * i * RHO), Me);
      const B = rotl32(h(uint32((2 * i + 1) * RHO), Mo), 8);
      K[2 * i] = uint32(A + B);
      K[2 * i + 1] = rotl32(uint32(A + 2 * B), 9);
    }

    return { K, Me, Mo };
  }

  // ─── ENKRIPSI SATU BLOK ──────────────────────────────────────────────────────

  function encryptBlock(block, K, Me, Mo) {
    let R = [
      bytesToWord(block, 0),
      bytesToWord(block, 4),
      bytesToWord(block, 8),
      bytesToWord(block, 12),
    ];

    // Input whitening
    R[0] = uint32(R[0] ^ K[0]);
    R[1] = uint32(R[1] ^ K[1]);
    R[2] = uint32(R[2] ^ K[2]);
    R[3] = uint32(R[3] ^ K[3]);

    // 16 putaran Feistel
    for (let round = 0; round < ROUNDS; round++) {
      const T0 = h(R[0], Me);
      const T1 = h(rotl32(R[1], 8), Mo);

      R[2] = uint32(rotr32(uint32(R[2] ^ uint32(T0 + T1 + K[2 * round + 8])), 1));
      R[3] = uint32(rotl32(R[3], 1) ^ uint32(T0 + 2 * T1 + K[2 * round + 9]));

      // Tukar pasangan
      if (round < ROUNDS - 1) {
        [R[0], R[2]] = [R[2], R[0]];
        [R[1], R[3]] = [R[3], R[1]];
      }
    }

    // Output whitening
    const out = new Uint8Array(16);
    wordToBytes(uint32(R[2] ^ K[4]), out, 0);
    wordToBytes(uint32(R[3] ^ K[5]), out, 4);
    wordToBytes(uint32(R[0] ^ K[6]), out, 8);
    wordToBytes(uint32(R[1] ^ K[7]), out, 12);

    return out;
  }

  // ─── DEKRIPSI SATU BLOK ──────────────────────────────────────────────────────

  function decryptBlock(block, K, Me, Mo) {
    let R = [
      bytesToWord(block, 0),
      bytesToWord(block, 4),
      bytesToWord(block, 8),
      bytesToWord(block, 12),
    ];

    // Undo output whitening
    R[0] = uint32(R[0] ^ K[4]);
    R[1] = uint32(R[1] ^ K[5]);
    R[2] = uint32(R[2] ^ K[6]);
    R[3] = uint32(R[3] ^ K[7]);

    // 16 putaran Feistel terbalik
    for (let round = ROUNDS - 1; round >= 0; round--) {
      const T0 = h(R[0], Me);
      const T1 = h(rotl32(R[1], 8), Mo);

      R[2] = uint32(rotl32(R[2], 1) ^ uint32(T0 + T1 + K[2 * round + 8]));
      R[3] = uint32(rotr32(uint32(R[3] ^ uint32(T0 + 2 * T1 + K[2 * round + 9])), 1));

      if (round > 0) {
        [R[0], R[2]] = [R[2], R[0]];
        [R[1], R[3]] = [R[3], R[1]];
      }
    }

    // Undo input whitening
    const out = new Uint8Array(16);
    wordToBytes(uint32(R[2] ^ K[0]), out, 0);
    wordToBytes(uint32(R[3] ^ K[1]), out, 4);
    wordToBytes(uint32(R[0] ^ K[2]), out, 8);
    wordToBytes(uint32(R[1] ^ K[3]), out, 12);

    return out;
  }

  // ─── PADDING (PKCS#7) ────────────────────────────────────────────────────────

  function addPadding(data) {
    const pad = BLOCK_SIZE - (data.length % BLOCK_SIZE);
    const padded = new Uint8Array(data.length + pad);
    padded.set(data);
    for (let i = data.length; i < padded.length; i++) {
      padded[i] = pad;
    }
    return padded;
  }

  function removePadding(data) {
    const pad = data[data.length - 1];
    return data.slice(0, data.length - pad);
  }

  // ─── DERIVE KEY DARI PASSWORD ────────────────────────────────────────────────

  function deriveKey(password) {
    // Sederhana: hash password menjadi 16 byte
    const encoder = new TextEncoder();
    const pwBytes = encoder.encode(password);
    const key = new Uint8Array(16);
    for (let i = 0; i < pwBytes.length; i++) {
      key[i % 16] ^= pwBytes[i];
    }
    // Tambahan mixing agar lebih baik
    for (let i = 0; i < 16; i++) {
      key[i] = Q1[(key[i] + i) & 0xFF] ^ Q0[(key[(i + 1) % 16] + i) & 0xFF];
    }
    return key;
  }

  // ─── ENKRIPSI CBC ────────────────────────────────────────────────────────────

  function encrypt(plaintext, password) {
    const encoder = new TextEncoder();
    const data = addPadding(encoder.encode(plaintext));
    const key = deriveKey(password);
    const { K, Me, Mo } = keySchedule(key);

    // Generate IV acak
    const iv = new Uint8Array(BLOCK_SIZE);
    crypto.getRandomValues(iv);

    const ciphertext = new Uint8Array(data.length);
    let prev = iv;

    for (let i = 0; i < data.length; i += BLOCK_SIZE) {
      const block = data.slice(i, i + BLOCK_SIZE);
      // XOR dengan blok sebelumnya (CBC)
      const xored = new Uint8Array(BLOCK_SIZE);
      for (let j = 0; j < BLOCK_SIZE; j++) {
        xored[j] = block[j] ^ prev[j];
      }
      const encrypted = encryptBlock(xored, K, Me, Mo);
      ciphertext.set(encrypted, i);
      prev = encrypted;
    }

    // Gabungkan IV + ciphertext, encode ke base64
    const result = new Uint8Array(BLOCK_SIZE + ciphertext.length);
    result.set(iv);
    result.set(ciphertext, BLOCK_SIZE);

    return btoa(String.fromCharCode(...result));
  }

  // ─── DEKRIPSI CBC ────────────────────────────────────────────────────────────

  function decrypt(ciphertextB64, password) {
    try {
      const raw = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
      const iv = raw.slice(0, BLOCK_SIZE);
      const ciphertext = raw.slice(BLOCK_SIZE);

      const key = deriveKey(password);
      const { K, Me, Mo } = keySchedule(key);

      const plaintext = new Uint8Array(ciphertext.length);
      let prev = iv;

      for (let i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
        const block = ciphertext.slice(i, i + BLOCK_SIZE);
        const decrypted = decryptBlock(block, K, Me, Mo);
        // XOR dengan blok sebelumnya (CBC)
        for (let j = 0; j < BLOCK_SIZE; j++) {
          plaintext[i + j] = decrypted[j] ^ prev[j];
        }
        prev = block;
      }

      const unpadded = removePadding(plaintext);
      return new TextDecoder().decode(unpadded);
    } catch (e) {
      return null; // Kunci salah atau data rusak
    }
  }

  // ─── PUBLIC API ──────────────────────────────────────────────────────────────

  return { encrypt, decrypt };

})();
