<?php
require_once '../../middleware/headers.php';
require_once '../../config/jwt_secret.php';
require_once '../../vendor/autoload.php';
require_once '../../config/db.php';
require_once '../../middleware/auth.php'; // Include the JWT auth file
header('Content-Type: application/json');


// Allow only GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(["status" => "error", "message" => "Only GET method allowed"]);
    exit();
}

// Get Authenticated User Data from auth.php
$userData = authenticateUser();
$userId = $userData->id ?? null;

if (!$userId) {
    http_response_code(401); // Unauthorized
    echo json_encode(["status" => "error", "message" => "Unauthorized"]);
    exit();
}

try {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $query = "SELECT id, first_name, last_name, email, phone, profile_pic, `role`, is_agent FROM users WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        http_response_code(404); // Not Found
        echo json_encode(["status" => "error", "message" => "User not found"]);
    } else {
        $user = $result->fetch_assoc();
        http_response_code(200); // OK
        echo json_encode(["status" => "success", "data" => $user]);
    }

    $stmt->close();
} catch (Exception $e) {
    http_response_code(500); // Internal Server Error
    echo json_encode(["status" => "error", "message" => "Something went wrong"]);
}
$conn->close();