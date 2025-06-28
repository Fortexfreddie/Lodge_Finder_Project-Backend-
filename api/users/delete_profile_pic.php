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
rateLimit("user_{$userId}_delete_image", 3, 86400); // Delete image rate limit (3 per day)


try {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $query = "SELECT profile_pic FROM users WHERE id = ?";
    $queryStmt = $conn->prepare($query);
    $queryStmt->bind_param("s", $userId);
    $queryStmt->execute();
    $result = $queryStmt->get_result();

    if($result->num_rows === 1) {
        $result = $result->fetch_assoc();

        $oldImageUrl = $result['profile_pic'];

        if ($oldImageUrl) {
            // Remove image from folder
            $parsedUrl = parse_url($oldImageUrl, PHP_URL_PATH);
            $oldImagePath = $_SERVER['DOCUMENT_ROOT'] . $parsedUrl;

            if (file_exists($oldImagePath)) {
                unlink($oldImagePath);
            } else {
                http_response_code(404); //Not Found
                echo json_encode(["status" => "error", "message" => "Image not found"]);
                exit;
            }
        }

        $queryStmt->close();

        // Set profile_pic to NULL
        $updateQuery = "UPDATE users SET profile_pic = NULL WHERE id = ?";
        $updateStmt = $conn->prepare($updateQuery);
        $updateStmt->bind_param("s", $userId);
        $updateStmt->execute();
        
        if($updateStmt->affected_rows > 0){
            http_response_code(200); // OK
            echo json_encode(["status" => "success", "message" => "Profile picture deleted"]);
        }else{
            http_response_code(500); // Internal Server Error
            echo json_encode(["status" => "error", "message" => "Failed to delete profile picture"]);
        }
        $updateStmt->close();
    } else {
        http_response_code(404); //Not Found
        echo json_encode(["status" => "error", "message" => "User not found"]);
        exit;
    }

} catch (Exception $e) {
    http_response_code(500); // Internal Server Error
    echo json_encode(["status" => "error", "message" => "Something went wrong."]);
}
$conn->close();