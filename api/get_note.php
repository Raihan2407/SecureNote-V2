<?php
require_once 'config.php';

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'ID tidak valid.']);
    exit();
}

$stmt = $conn->prepare("SELECT id, title, ciphertext, created_at, updated_at FROM notes WHERE id = ?");
$stmt->bind_param('i', $id);
$stmt->execute();
$result = $stmt->get_result();
$note   = $result->fetch_assoc();

if (!$note) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'Catatan tidak ditemukan.']);
    exit();
}

echo json_encode([
    'success' => true,
    'data'    => [
        'id'         => (int) $note['id'],
        'title'      => $note['title'],
        'ciphertext' => $note['ciphertext'],
        'created_at' => $note['created_at'],
        'updated_at' => $note['updated_at'],
    ]
]);

$stmt->close();
$conn->close();
