<?php
    // CORS Headers
    require_once '../../middleware/headers.php';
    require_once '../../middleware/rate_limit.php'; // include the limiter
    header('Content-Type: application/json');

    // get the real IP behind a proxy
    $ip = $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];

    // Rate-limit all methods to 20
    $globalKey = $ip . '_global';
    rateLimit($globalKey, 20, 60); // 20 requests per minute across all endpoints

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405); // Method Not Allowed
        $response = [
            "status" => "error",
            "message" => "Only POST method allowed"
        ];
        echo json_encode($response);
        exit();
    }

    // Use the client's IP as key; Limit reigister attempts to 5 per minute per IP and Rate-limit ONLY real POST requests
    rateLimit($ip . '_register', 5, 60);

    require_once '../../config/db.php';

    // Enable MySQLi exceptions
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    try {
        $data = json_decode(file_get_contents("php://input"));
        $response = [];

        if ($data && isset($data->firstName, $data->lastName, $data->email, $data->password, $data->confirmPassword)) {
            $firstName = trim($data->firstName);
            $lastName = trim($data->lastName);
            $email = trim($data->email);
            $phone = isset($data->phone) ? trim($data->phone) : null;
            $phone = $phone ? preg_replace('/\D/', '', $phone) : null; // Remove non-numeric characters
            $password = $data->password;
            $confirmPassword = $data->confirmPassword;

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                http_response_code(400); // Bad Request
                $response['status'] = "error";
                $response['message'] = "Invalid email format";
                echo json_encode($response);
                exit();
            }

            if (!preg_match('/^[0-9]{11}$/', $phone)) {
                http_response_code(400); // Bad Request
                echo json_encode(["status" => "error", "message" => "Invalid phonenumber"]);
                exit;
            }

            // Check if password is less than 6 characters
            if (strlen($password) < 6) {
                http_response_code(400); // Bad Request
                echo json_encode(["status" => "error", "message" => "Password must be at least 6 characters"]);
                exit;
            }

            if ($password !== $confirmPassword) {
                http_response_code(400); // Bad Request
                $response['status'] = "error";
                $response['message'] = "Passwords do not match";
                echo json_encode($response);
                exit();
            }

            $query = "SELECT * FROM users WHERE email = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 1) {
                $stmt->close();
                http_response_code(409); // Conflict
                $response['status'] = "error";
                $response['message'] = "Email already exists";
                echo json_encode($response);
                exit();
            }

            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            $userId = 'user_' . uniqid(true);

            $query = "INSERT INTO users (id, first_name, last_name, email, phone, password) VALUES (?, ?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("ssssss", $userId, $firstName, $lastName, $email, $phone, $hashedPassword);

            if ($stmt->execute()) {
                $stmt->close();
                http_response_code(201); // Created
                $response['status'] = "success";
                $response['message'] = "User registered successfully. Please verify your email.";
                echo json_encode($response);
            } else {
                $stmt->close();
                http_response_code(500); // Internal Server Error
                $response['status'] = "error";
                $response['message'] = "Registration failed.";
                echo json_encode($response);
            }
        } else {
            http_response_code(400); // Bad Request
            $response['status'] = "error";
            $response['message'] = "Missing required fields";
            echo json_encode($response);
        }
    } catch (Exception $e) {
        http_response_code(500); // Internal Server Error
        $response['status'] = "error";
        $response['message'] = "Something went wrong.";
        // $response['debug'] = $e->getMessage();
        echo json_encode($response);
    }

    $conn->close();
