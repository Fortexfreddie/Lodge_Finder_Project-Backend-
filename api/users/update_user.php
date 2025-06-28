<?php
require_once '../../middleware/headers.php';
require_once '../../middleware/rate_limit.php';
require_once '../../config/jwt_secret.php';
require_once '../../vendor/autoload.php';
require_once '../../config/db.php';
require_once '../../middleware/auth.php'; // Include the JWT auth file
header('Content-Type: application/json');

// Allow only POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(["status" => "error", "message" => "Only POST method allowed"]);
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

// Rate limit user using userId
rateLimit("user_{$userId}_profile_update", 3, 86400); // Add profile update rate limit (3 per day)

try{
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $data = json_decode(file_get_contents("php://input"));

    if ($data && isset($data->firstName, $data->lastName, $data->phone, $data->email)) {
        $firstName = trim($data->firstName);
        $lastName = trim($data->lastName);
        $phone = preg_replace('/\D/', '', trim($data->phone)); // Remove non-numeric characters
        $email = trim($data->email);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Invalid email format"]);
            exit;
        }

        if (!preg_match('/^[0-9]{11}$/', $phone)) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Invalid phonenumber"]);
            exit;
        }

        // Check if email already exists 
        $checkQuery = "SELECT email FROM users WHERE email = ?";
        $checkStmt = $conn->prepare($checkQuery);
        $checkStmt->bind_param("s", $email);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        if ($result->num_rows === 1) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Email already exists"]);
            exit;
        }
        $checkStmt->close();

        // Update the db
        $updateQuery = "UPDATE users SET first_name = ?, last_name = ?, phone = ?, email = ? WHERE id = ?";
        $updateStmt = $conn->prepare($updateQuery);
        $updateStmt->bind_param("sssss", $firstName, $lastName, $phone, $email, $userId);
        $updateStmt->execute();

        if($updateStmt->affected_rows > 0){
            http_response_code(200); // OK
            echo json_encode(["status" => "success", "message" => "Profile update successful"]);
        } else {
            http_response_code(500); // Internal Server Error
            echo json_encode(["status" => "error", "message" => "Failed to update profile in database"]);
            exit;
        }
        $updateStmt->close();

    } else {
        http_response_code(400); // Bad Request
        echo json_encode(["status" => "error", "message" => "Missing required fields"]);
        exit;
    }
} catch (Exception $e) {
    http_response_code(500); // Internal Server Error
    echo json_encode(["status" => "error", "message" => "Something went wrong."]);
    // echo json_encode(["status" => "error", "message" => "Something went wrong.", "debug" => $e->getMessage()]);
}
$conn->close();