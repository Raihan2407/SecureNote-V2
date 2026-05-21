<?php
require_once 'config.php';

$body = json_decode(file_get_contents('php://input'), true);

$id         = isset($body['id'])         ? (int) $body['id']              : 0;
$title      = isset($body['title'])      ? trim($body['title'])           : '';
$ciphertext = isset($body['ciphertext']) ? trim($body['ciphertext'])      : '';

// Validasi
if ($id <= 0 || empty($title) || empty($ciphertext)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Data tidak lengkap.']);
    exit();
}

// Cek catatan ada
$check = $conn->prepare("SELECT id FROM notes WHERE id = ?");
$check->bind_param('i', $id);
$check->execute();
if ($check->get_result()->num_rows === 0) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'Catatan tidak ditemukan.']);
    exit();
}
$check->close();

// Update
$stmt = $conn->prepare("UPDATE notes SET title = ?, ciphertext = ?, updated_at = NOW() WHERE id = ?");
$stmt->bind_param('ssi', $title, $ciphertext, $id);

if ($stmt->execute()) {
    echo json_encode(['success' => true, 'message' => 'Catatan berhasil diperbarui.']);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Gagal memperbarui catatan.']);
}

$stmt->close();
$conn->close();
