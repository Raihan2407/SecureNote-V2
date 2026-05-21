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

// Cari user
$stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
$stmt->bind_param('s', $username);
$stmt->execute();
$result = $stmt->get_result();
$user   = $result->fetch_assoc();
$stmt->close();

// Verifikasi password dengan bcrypt
if (!$user || !password_verify($password, $user['password'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Username atau password salah.']);
    exit();
}

// Set session
$_SESSION['user_id']  = $user['id'];
$_SESSION['username'] = $user['username'];

echo json_encode([
    'success' => true,
    'message' => 'Login berhasil.',
    'data'    => [
        'user_id'  => $user['id'],
        'username' => $user['username'],
    ]
]);

$conn->close();