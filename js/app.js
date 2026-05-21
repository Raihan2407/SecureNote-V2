/**
 * app.js
 * Pengelolaan data catatan melalui PHP API → MySQL
 * Dengan session management dan auto-redirect jika belum login
 */

const API = 'api';

// Helper: handle response, redirect ke login jika 401
async function handleResponse(res) {
  if (res.status === 401) {
    window.location.href = 'login.html';
    return null;
  }
  return await res.json();
}

const Storage = {

  // Ambil semua catatan milik user yang login
  async getAll() {
    const res = await fetch(`${API}/get_notes.php`);
    const json = await handleResponse(res);
    if (!json) return [];
    if (!json.success) throw new Error(json.message);
    return json.data;
  },

  // Ambil catatan by ID
  async getById(id) {
    try {
      const res = await fetch(`${API}/get_note.php?id=${id}`);
      if (res.status === 401) { window.location.href = 'login.html'; return null; }
      const json = await res.json();
      if (!json.success) return null;
      return json.data;
    } catch (e) {
      return null;
    }
  },

  // Simpan catatan baru
  async add(note) {
    const res = await fetch(`${API}/save_note.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(note),
    });
    const json = await handleResponse(res);
    if (!json) return null;
    if (!json.success) throw new Error(json.message);
    return json.data;
  },

  // Edit catatan
  async update(id, title, ciphertext) {
    const res = await fetch(`${API}/edit_note.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, title, ciphertext }),
    });
    const json = await handleResponse(res);
    if (!json) return false;
    if (!json.success) throw new Error(json.message);
    return true;
  },

  // Hapus catatan
  async remove(id) {
    const res = await fetch(`${API}/delete_note.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const json = await handleResponse(res);
    if (!json) return false;
    if (!json.success) throw new Error(json.message);
    return true;
  },

};

// Cek session dan redirect jika belum login
async function checkAuth() {
  try {
    const res = await fetch(`${API}/check_session.php`);
    const json = await res.json();
    if (!json.loggedIn) {
      window.location.href = 'login.html';
      return null;
    }
    return json.data; // { user_id, username }
  } catch (e) {
    window.location.href = 'login.html';
    return null;
  }
}

// Logout
async function doLogout() {
  await fetch(`${API}/logout.php`);
  window.location.href = 'login.html';
}