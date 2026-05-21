-- Buat database
CREATE DATABASE IF NOT EXISTS securenote
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE securenote;

-- Buat tabel notes
CREATE TABLE IF NOT EXISTS notes (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title       VARCHAR(255)   NOT NULL,
  ciphertext  LONGTEXT       NOT NULL,
  created_at  DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME        NULL     DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
