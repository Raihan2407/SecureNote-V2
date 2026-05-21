<?php
require_once 'config.php';

$body     = json_decode(file_get_contents('php://input'), true);
$username = isset($body['username']) ? trim($body['username']) : '';
$password = isset($body['password']) ? $body['password']      : '';

// Validasi
if (empty($username) || empty($password)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Username dan password tidak boleh kosong.']);
    exit();
}

if (strlen($username) < 3 || strlen($username) > 50) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Username harus 3-50 karakter.']);
    exit();
}

if (strlen($password) < 6) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Password minimal 6 karakter.']);
    exit();
}

if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Username hanya boleh huruf, angka, dan underscore.']);
    exit();
}

// Cek username sudah ada
$check = $conn->prepare("SELECT id FROM users WHERE username = ?");
$check->bind_param('s', $username);
$check->execute();
if ($check->get_result()->num_rows > 0) {
    http_response_code(409);
    echo json_encode(['success' => false, 'message' => 'Username sudah digunakan.']);
    exit();
}
$check->close();

// Hash password dengan bcrypt
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

// Simpan user baru
$stmt = $conn->prepare("INSERT INTO users (username, password, created_at) VALUES (?, ?, NOW())");
$stmt->bind_param('ss', $username, $hashedPassword);

if ($stmt->execute()) {
    echo json_encode(['success' => true, 'message' => 'Akun berhasil dibuat. Silakan login.']);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Gagal membuat akun.']);
}

$stmt->close();
$conn->close();