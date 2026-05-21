-- Gunakan database securenote
USE securenote;

-- Buat tabel users
CREATE TABLE IF NOT EXISTS users (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username   VARCHAR(50)  NOT NULL UNIQUE,
  password   VARCHAR(255) NOT NULL,  -- bcrypt hash
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tambah kolom user_id ke tabel notes
ALTER TABLE notes
  ADD COLUMN user_id INT UNSIGNED NOT NULL DEFAULT 1 AFTER id,
  ADD INDEX idx_user_id (user_id);