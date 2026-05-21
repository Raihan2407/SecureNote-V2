<?php
require_once 'config.php';

// Ambil body JSON
$body = json_decode(file_get_contents('php://input'), true);

$title      = isset($body['title'])      ? trim($body['title'])      : '';
$ciphertext = isset($body['ciphertext']) ? trim($body['ciphertext']) : '';

// Validasi
if (empty($title) || empty($ciphertext)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Judul dan ciphertext tidak boleh kosong.']);
    exit();
}

if (mb_strlen($title) > 255) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Judul terlalu panjang (maks 255 karakter).']);
    exit();
}

// Simpan ke database
$stmt = $conn->prepare("INSERT INTO notes (title, ciphertext, created_at) VALUES (?, ?, NOW())");
$stmt->bind_param('ss', $title, $ciphertext);

if ($stmt->execute()) {
    $newId = $conn->insert_id;
    echo json_encode([
        'success' => true,
        'message' => 'Catatan berhasil disimpan.',
        'data'    => ['id' => $newId]
    ]);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Gagal menyimpan catatan.']);
}

$stmt->close();
$conn->close();
