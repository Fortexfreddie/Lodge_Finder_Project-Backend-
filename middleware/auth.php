<?php
// Import classes from the Firebase JWT package for encoding and decoding JWTs
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function authenticateUser() {
    // Use the secret key from the jwt_secret.php file
    $secretKey = JWT_SECRET;

    // Get token from Authorization header
    $headers = apache_request_headers();
    $authHeader = $headers['Authorization'] ?? '';

    // Check if the Authorization header exists and follows the "Bearer <token>" format
    if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        http_response_code(401); // Unauthorized
        $response = [
            "status" => "error",
            "message" => "Access denied. No token provided."
        ];
        echo json_encode($response);
        exit();
    }

    $jwt = $matches[1];

    try {
        $decoded = JWT::decode($jwt, new Key($secretKey, 'HS256'));
        // Optional: return user data for route use
        return $decoded->user;
    } catch (Exception $e) {
        http_response_code(401); // Unauthorized
        $response = [
            "status" => "error",
            "message" => "Invalid or expired token."
        ];
        echo json_encode($response);
        exit();
    }
}