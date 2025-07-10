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

try{
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $query = "SELECT * FROM users";
    $queryStmt = $conn->prepare($query);
    $queryStmt->execute();
    $result = $queryStmt->get_result();

    if ($result->num_rows) {
        $rows = $result->num_rows;

        $data = [];
        while ($users = $result->fetch_assoc()) {
            $data[] = $users;
        }
        http_response_code(200); // OK
        echo json_encode([
            "status" => "success", 
            "message" => "Data fetched successfully", 
            "data" => [
                "total" => $rows,
                "users" => $data
            ]
        ]);
    } else {
        http_response_code(500); // INTERNAL SERVER ERROR
        echo json_encode([
            "message" => "error",
            "message" => "Something went wrong."
        ]);
        exit();
    }

} catch (Exception $e) {
    http_response_code(500); // INTERNAL SERVER ERROR
    echo json_encode([
        "message" => "error",
        "message" => "Something went wrong.",
        // "error" => $e->getMessage()
    ]);
}

$conn->close();
