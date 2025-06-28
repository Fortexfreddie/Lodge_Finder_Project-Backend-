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
rateLimit("user_{$userId}_kyc_update", 10, 86400); // Add kyc update rate limit (1 per day)

try{
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    if(isset($_FILES['Passport']) && isset($_POST['Location']) && isset($_POST['Lodge']) && isset($_POST['WhatsappNumber']) && isset($_POST['AccountNumber']) && isset($_POST['Bank'])) {
        $file = $_FILES['Passport'];
        $location = trim($_POST['Location']);
        $lodge = trim($_POST['Lodge']);
        $whatsapp = preg_replace('/\D/', '', trim($_POST['WhatsappNumber'])); // Remove non-numeric characters
        $accountNumber = preg_replace('/\D/', '', trim($_POST['AccountNumber'])); // Remove non-numeric characters
        $bank = trim($_POST['Bank']);
        
        // Validate phone number format
        if (!preg_match('/^[0-9]{11}$/', $whatsapp)) {
            http_response_code(400); // Bad Request
            echo json_encode(["status" => "error", "message" => "Invalid Whatsapp number"]);
            exit;
        }

        // validate passport file

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

        // Limit file size to 3MB
        if ($fileSize > 3 * 1024 * 1024) {
            http_response_code(413); // Payload Too Large
            echo json_encode(["status" => "error", "message" => "File too large"]);
            exit;
        }

        // Generate a new unique filename
        $newName = uniqid("DOC_", true) . '.' . $ext;

        // Define the upload directory
        $uploadDir = '../../uploads/kyc_documents/';
        $uploadPath = $uploadDir . $newName;

        // Url for the uploaded document
        $url = "http://localhost/lodge-finder-project-backend/uploads/kyc_documents/$newName";

        // Move the uploaded file to the upload directory
        if (move_uploaded_file($tmpName, $uploadPath)) {
            
            // Check if the user is already approved and update the old document if it exists

            $checkKycQuery = "SELECT document, status FROM kyc_applications WHERE user_id = ?";
            $stmt = $conn->prepare($checkKycQuery);
            $stmt->bind_param("s", $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();

                // Check if the user has already passed the KYC application
                if ($row['status'] === 'approved') {
                    http_response_code(403); // Forbidden
                    echo json_encode(["status" => "error", "message" => "You have already passed your KYC application"]);
                    exit;
                }

                // If the user has a previous document, delete it and update the KYC application with the new document
                $oldDoc = $row['document'];
                if ($oldDoc) {
                    // Delete old document
                    $parsedDoc = parse_url($oldDoc, PHP_URL_PATH);
                    $oldDocPath = $_SERVER['DOCUMENT_ROOT'] . $parsedDoc;

                    if (file_exists($oldDocPath)) {
                        unlink($oldDocPath);
                    }

                    // Update the KYC application with the new document
                    $updateQuery = "UPDATE kyc_applications SET document = ?, location = ?, lodge = ?, whatsapp = ?, account_number = ?, bank_name = ?, submitted_at = CURRENT_TIMESTAMP WHERE user_id = ?";
                    $stmt = $conn->prepare($updateQuery);
                    $stmt->bind_param("sssssss", $url, $location, $lodge, $whatsapp, $accountNumber, $bank, $userId);
                    if ($stmt->execute()) {
                        http_response_code(200); // OK
                        echo json_encode(["status" => "success", "message" => "KYC document updated successfully"]);
                    } else {
                        http_response_code(500); // Internal Server Error
                        echo json_encode(["status" => "error", "message" => "Failed to update KYC document"]);
                    }
                    $stmt->close();
                }
            } else {
                // If no previous document

                // Get user details from the database
                $userQuery = "SELECT first_name, last_name, email FROM users WHERE id = ?";
                $stmt = $conn->prepare($userQuery);
                $stmt->bind_param("s", $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows === 0) {
                    http_response_code(404); // Not Found
                    echo json_encode(["status" => "error", "message" => "User not found"]);
                    exit;
                }
                $user = $result->fetch_assoc();
                $fullName = $user['first_name'] . ' ' . $user['last_name'];
                $email = $user['email'];
                $stmt->close();

                // Insert new KYC application
                $insertQuery = "INSERT INTO kyc_applications (user_id, full_name, email, whatsapp, location, lodge, account_number, bank_name, document) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                $stmt = $conn->prepare($insertQuery);
                $stmt->bind_param("sssssssss", $userId, $fullName, $email, $whatsapp, $location, $lodge, $accountNumber, $bank, $url);
                if ($stmt->execute()) {
                    http_response_code(201); // Created
                    echo json_encode(["status" => "success", "message" => "KYC application submitted successfully"]);
                } else {
                    http_response_code(500); // Internal Server Error
                    echo json_encode(["status" => "error", "message" => "Failed to submit KYC application"]);
                    exit;
                }
                $stmt->close();
            }
        } else {
            http_response_code(500); // Internal Server Error
            echo json_encode(["status" => "error", "message" => "Failed to upload file"]);
            exit;
        }
        
    } else {
        http_response_code(400); // Bad Request
        echo json_encode(["status" => "error", "message" => "Missing required fields"]);
    }
} catch (Exception $e) {
    http_response_code(500); // Internal Server Error
    echo json_encode(["status" => "error", "message" => "An error occurred"]);
    // echo json_encode(["status" => "error", "message" => "Something went wrong.", "debug" => $e->getMessage()]);
}
$conn->close();