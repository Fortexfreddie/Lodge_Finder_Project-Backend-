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
rateLimit("user_{$userId}_password_update", 3, 86400); // Add password update rate limit (3 per day)

try{
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $data = json_decode(file_get_contents("php://input"));

    if ($data && isset($data->currentPassword, $data->password, $data->confirmPassword)){
        $currentPassword = $data->currentPassword;
        $newPassword = $data->password;
        $confirmNewPassword = $data->confirmPassword;

        // Check if password is less than 6 characters
        if (strlen($newPassword) < 6) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Password must be at least 6 characters"]);
            exit;
        }

        // Check if new password and confirm new password match
        if ($newPassword !== $confirmNewPassword) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "New passwords do not match"]);
            exit;
        }
        
        // Check if the user's current password input is valid
        $selectQuery = "SELECT password FROM users WHERE id = ?";
        $selectStmt = $conn->prepare($selectQuery);
        $selectStmt->bind_param("s", $userId);
        $selectStmt->execute();
        $result = $selectStmt->get_result();

        if ($result->num_rows === 1) {
            $hashedPassword = $result->fetch_assoc();
            $storedHashedPassword = $hashedPassword['password'];

            $selectStmt->close();
            
            if (!password_verify($currentPassword, $storedHashedPassword)) {
                http_response_code(400); // Bad Request
                echo json_encode(["status" => "error", "message" => "Incorrect password"]);
                exit;
            }

            // Hash the new password
            $hashedNewPassword = password_hash($newPassword, PASSWORD_DEFAULT);

            // Update new password in the db
            $updateQuery = "UPDATE users SET password = ? WHERE id = ?";
            $updateStmt = $conn->prepare($updateQuery);
            $updateStmt->bind_param("ss", $hashedNewPassword, $userId);
            $updateStmt->execute();

            if ($updateStmt->affected_rows > 0) {
                http_response_code(200); // OK
                echo json_encode(["status" => "success", "message" => "Password update successful"]);
            } else {
                http_response_code(500); // Internal Server Error
                echo json_encode(["status" => "error", "message" => "Failed to update password in database"]);
                exit;
            }
            $updateStmt->close();

        } else {
            http_response_code(404); //Not Found
            echo json_encode(["status" => "error", "message" => "User not found"]);
            exit;
        }

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