<?php
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');

if (isset($_SESSION['user_id'])) {
    echo json_encode([
        'success'  => true,
        'loggedIn' => true,
        'data'     => [
            'user_id'  => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
        ]
    ]);
} else {
    echo json_encode(['success' => true, 'loggedIn' => false]);
}