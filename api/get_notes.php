<?php
require_once 'config.php';

// Ambil semua catatan, urut dari terbaru
$sql    = "SELECT id, title, created_at, updated_at FROM notes ORDER BY created_at DESC";
$result = $conn->query($sql);

$notes = [];
while ($row = $result->fetch_assoc()) {
    $notes[] = [
        'id'         => (int) $row['id'],
        'title'      => $row['title'],
        'created_at' => $row['created_at'],
        'updated_at' => $row['updated_at'],
    ];
}

echo json_encode(['success' => true, 'data' => $notes]);
$conn->close();
