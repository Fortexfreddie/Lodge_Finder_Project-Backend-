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

$stats = [];

    // Total users
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users");
    $stmt->execute();
    $stmt->bind_result($stats['total_users']);
    $stmt->fetch();
    $stmt->close();

    // Total admins
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
    $stmt->execute();
    $stmt->bind_result($stats['total_admins']);
    $stmt->fetch();
    $stmt->close();

    // Total agents
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE is_agent = 1");
    $stmt->execute();
    $stmt->bind_result($stats['total_agents']);
    $stmt->fetch();
    $stmt->close();

    // Total KYC applications
    $stmt = $conn->prepare("SELECT COUNT(*) FROM kyc_applications");
    $stmt->execute();
    $stmt->bind_result($stats['total_kyc_applications']);
    $stmt->fetch();
    $stmt->close();


    http_response_code(200);
    echo json_encode([
        "status" => "success",
        "message" => "Dashboard stats fetched successfully",
        "data" => $stats
    ]);

} catch (Exception $e) {
    http_response_code(500); // INTERNAL SERVER ERROR
    echo json_encode([
        "message" => "error",
        "message" => "Failed to load stats",
        // "error" => $e->getMessage()
    ]);
}