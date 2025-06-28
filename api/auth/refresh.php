<?php
require_once '../../middleware/headers.php';
require_once '../../config/db.php';
require_once '../../vendor/autoload.php';
require_once '../../config/jwt_secret.php';
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    $response = [
        "status" => "error",
        "message" => "Only POST method allowed"
    ];
    echo json_encode($response);
    exit();
}

use Firebase\JWT\JWT;

// Check if refresh token is sent
if (!isset($_COOKIE['refresh_token'])) {
    http_response_code(401); //Unauthorized
    echo json_encode(["status" => "error", "message" => "No refresh token"]);
    exit;
}

$refreshToken = $_COOKIE['refresh_token'];

// Check refresh token in DB
$query = "SELECT id, email, role, remember FROM users WHERE refresh_token = ? AND refresh_token_expiry > NOW()";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $refreshToken);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();

    $newAccessTokenExpiry = time() + 60 * 60; // 1 hour
    // $newAccessTokenExpiry = time() + 10; // 10 seconds

    $newPayload = [
        'iss' => 'http://localhost',
        'iat' => time(),
        'exp' => $newAccessTokenExpiry, 
        'user' => [
            'id' => $user['id'],
            'email' => $user['email'],
            'role' => $user['role']
        ]
    ];

    $newAccessToken = JWT::encode($newPayload, JWT_SECRET, 'HS256');

    echo json_encode([
        "status" => "success",
        "token" => $newAccessToken,
        "remember" => (bool)$user['remember']
    ]);
} else {
    http_response_code(401); //Unauthorized
    echo json_encode(["status" => "error", "message" => "Invalid or expired refresh token"]);
}
