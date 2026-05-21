<?php
require_once 'config.php';

$body = json_decode(file_get_contents('php://input'), true);
$id   = isset($body['id']) ? (int) $body['id'] : 0;

if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'ID tidak valid.']);
    exit();
}

$stmt = $conn->prepare("DELETE FROM notes WHERE id = ?");
$stmt->bind_param('i', $id);

if ($stmt->execute()) {
    if ($conn->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'Catatan berhasil dihapus.']);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Catatan tidak ditemukan.']);
    }
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Gagal menghapus catatan.']);
}

$stmt->close();
$conn->close();
