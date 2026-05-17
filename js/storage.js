/**
 * storage.js
 * Pengelolaan penyimpanan catatan menggunakan LocalStorage
 */

const Storage = (() => {

  const KEY = 'securenote_notes';

  // Ambil semua catatan
  function getAll() {
    const data = localStorage.getItem(KEY);
    return data ? JSON.parse(data) : [];
  }

  // Simpan semua catatan
  function saveAll(notes) {
    localStorage.setItem(KEY, JSON.stringify(notes));
  }

  // Tambah catatan baru
  function add(note) {
    const notes = getAll();
    note.id = Date.now().toString();
    note.createdAt = new Date().toISOString();
    notes.unshift(note);
    saveAll(notes);
    return note;
  }

  // Ambil catatan berdasarkan ID
  function getById(id) {
    const notes = getAll();
    return notes.find(n => n.id === id) || null;
  }

  // Hapus catatan berdasarkan ID
  function remove(id) {
    const notes = getAll().filter(n => n.id !== id);
    saveAll(notes);
  }

  return { getAll, add, getById, remove };

})();
