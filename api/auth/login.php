<?php
    require_once '../../middleware/rate_limit.php'; // include the limiter

    // get the real IP behind a proxy
    $ip = $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];

    // Rate-limit all methods to 20
    $globalKey = $ip . '_global';
    rateLimit($globalKey, 20, 60); // 20 requests per minute across all endpoints

    // Import classes from the Firebase JWT package for encoding and decoding JWTs
    use Firebase\JWT\JWT;
    use Firebase\JWT\Key;

    // Autoload all Composer dependencies, including Firebase JWT
    require_once '../../vendor/autoload.php';
    require_once '../../config/jwt_secret.php';

    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Headers: Content-Type");
    header("Access-Control-Allow-Methods: POST, OPTIONS");

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        // Handle preflight request
        http_response_code(200); // OK
        exit();
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405); // Method Not Allowed
        $response = [
            "status" => "error",
            "message" => "Only POST method allowed"
        ];
        echo json_encode($response);
        exit();
    }

    // Use the client's IP as key; Limit login attempts to 3 per minute per IP and Rate-limit ONLY real POST requests
    rateLimit($ip . '_login', 3, 60);

    require_once '../../config/db.php';

    // Enable MySQLi exceptions
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    try{
        $data = json_decode(file_get_contents("php://input"));
        $response = [];

        if ($data && isset($data->email, $data->password)) {
            $email = trim($data->email);
            $password = $data->password;
            $remember  = isset($data->remember) ? (bool) $data->remember : false;

            $query = "SELECT * FROM users WHERE email = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();

                if (password_verify($password, $user['password'])) {
                    // set when token will expire if remember me was clicked
                    $expiresIn = $remember ? (60 * 60 * 24 * 30) : (60 * 60 * 24); // 30 days or 1 day
                    // Build token payload
                    $payload = [
                        'iss' => 'http://localhost', // issuer
                        "aud" => "http://localhost", // Audience
                        'iat' => time(), // issued at
                        'exp' => time() + $expiresIn, // Expires based on remember flag
                        'user' => [
                            'id' => $user['id'],
                            'email' => $user['email'],
                            'role' => $user['role']
                        ]
                    ];

                    // Generate JWT
                    $jwt = JWT::encode($payload, JWT_SECRET, 'HS256');

                    http_response_code(200);
                    $response['status'] = "success";
                    $response['message'] = "Login successful";
                    $response['token'] = $jwt;
                    $response['ip'] = $ip;
                    $response['data'] = [
                    "userId" => $user['id'],
                    "email" => $user['email'],
                    "firstName" => $user['first_name'],
                    "lastName" => $user['last_name'],
                    "role" => $user['role']
                    ];
                    echo json_encode($response);
                } else {
                    http_response_code(401); //Unauthorized
                    $response['status'] = "error";
                    $response['message'] = "Incorrect password";
                    echo json_encode($response);
                }

            } else {
                http_response_code(404); //Not Found
                $response['status'] = "error";
                $response['message'] = "User not found";
                echo json_encode($response);
            }
            $stmt->close();

        } else {
            http_response_code(400); //Bad Request
            $response['status'] = "error";
            $response['message'] = "Email and password are required";
            echo json_encode($response);
        }

    } catch(Exception $e) {
        http_response_code(500); // Internal Server Error
        $response['status'] = "error";
        $response['message'] = "Something went wrong.";
        // $response['debug'] = $e->getMessage(); 
        echo json_encode($response);
    }

    $conn->close();
?>