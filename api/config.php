<?php
session_start();

// Otomatis deteksi environment
// Jika variabel Railway tersedia → pakai Railway, jika tidak → pakai XAMPP lokal
define('DB_HOST', getenv('MYSQLHOST')     ?: 'localhost');
define('DB_USER', getenv('MYSQLUSER')     ?: 'root');
define('DB_PASS', getenv('MYSQLPASSWORD') ?: '');
define('DB_NAME', getenv('MYSQLDATABASE') ?: 'securenote');
define('DB_PORT', getenv('MYSQLPORT')     ?: '3306');

// Header CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Koneksi database
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, (int) DB_PORT);

if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Koneksi database gagal: ' . $conn->connect_error
    ]);
    exit();
}

$conn->set_charset('utf8mb4');

// Helper: cek apakah user sudah login
function requireLogin() {
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode([
            'success'  => false,
            'message'  => 'Silakan login terlebih dahulu.',
            'redirect' => 'login.html'
        ]);
        exit();
    }
    return (int) $_SESSION['user_id'];
}