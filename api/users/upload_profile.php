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
rateLimit("user_{$userId}_image_upload", 3, 86400); // Add image upload rate limit (3 per day)

try{
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    if(isset($_FILES['profilePic'])) {
        $file = $_FILES['profilePic']; // Get the uploaded file array

        // Extract file details
        $fileName = $file['name'];
        $tmpName = $file['tmp_name'];
        $fileSize = $file['size'];
        $fileType = $file["type"];
        $error = $file['error'];

        // Allowed file extensions
        $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];

        // Get file extension and convert to lowercase
        $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // Validate file extension
        if(!in_array($ext, $allowed)) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Unsupported image extension"]);
            exit;
        }

        // Allowed file type
        $allowType = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

        if(!in_array ($fileType, $allowType)) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Invalid image MIME type"]);
            exit;
        }

        // Perform image validation using getimagesize()
        $imageInfo = getimagesize($tmpName);

        if ($imageInfo === false) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Invalid file type"]);
            exit;
        }

        // Check for file upload errors
        if ($error !== 0) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Upload error"]);
            exit;
        }

        // Limit file size to 2MB
        if ($fileSize > 2 * 1024 * 1024) {
            http_response_code(413); // Payload Too Large
            echo json_encode(["status" => "error", "message" => "File too large"]);
            exit;
        }

        // Generate a new unique filename
        $newName = uniqid("IMG_", true) . '.' . $ext;

        // Target upload path
        $uploadDir = "../../uploads/profile_pics/";
        $uploadPath = $uploadDir . $newName;

        // Move the uploaded file to the uploads directory
        if (move_uploaded_file($tmpName, $uploadPath)) {

            // DELETE OLD IMAGE (before saving new one)
            $getOldImageQuery = "SELECT profile_pic FROM users WHERE id = ?";
            $getOldImageStmt = $conn->prepare($getOldImageQuery);
            $getOldImageStmt->bind_param("s", $userId);
            $getOldImageStmt->execute();
            $result = $getOldImageStmt->get_result();

            if($result->num_rows === 1) {
                $result = $result->fetch_assoc();
                $oldImageUrl = $result['profile_pic'];

                if ($oldImageUrl) {
                    $parsedUrl = parse_url($oldImageUrl, PHP_URL_PATH);
                    $oldImagePath = $_SERVER['DOCUMENT_ROOT'] . $parsedUrl;

                    if (file_exists($oldImagePath)) {
                        unlink($oldImagePath);
                    }
                }
            } else {
                http_response_code(404); //Not Found
                echo json_encode(["status" => "error", "message" => "User not found"]);
                exit;
            }

            $getOldImageStmt->close();

            // Update url in the db
            $url = "http://localhost/lodge-finder-project-backend/uploads/profile_pics/$newName";

            $updateQuery = "UPDATE users SET profile_pic = ? WHERE id = ?";
            $upadateStmt = $conn->prepare($updateQuery);
            $upadateStmt->bind_param("ss", $url, $userId);
            $upadateStmt->execute();
            
            if($upadateStmt->affected_rows > 0){
                http_response_code(200); // OK
                echo json_encode(["status" => "success", "message" => "Upload successful", "url" => $url]);
            } else {
                http_response_code(500); // Internal Server Error
                echo json_encode(["status" => "error", "message" => "Failed to update profile picture in database"]);
                exit;
            }
             
            $upadateStmt->close();

        } else {
            http_response_code(500); // Internal Server Error
            echo json_encode(["status" => "error", "message" => "Failed to move file"]);
            exit;
        }

    } else {
        http_response_code(400); //Bad Request
        echo json_encode(["status" => "error", "message" => "No file uploaded"]);
        exit;
    }
} catch (Exception $e) {
    http_response_code(500); // Internal Server Error
    echo json_encode(["status" => "error", "message" => "Something went wrong."]);
    // echo json_encode(["status" => "error", "message" => "Something went wrong.", "debug" => $e->getMessage()]);
}
$conn->close();