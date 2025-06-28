<?php
    // CORS Headers
    require_once '../../middleware/headers.php';
    // Autoload all Composer dependencies, including Firebase JWT
    require_once '../../vendor/autoload.php';
    require_once '../../config/jwt_secret.php';
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

    // Use the client's IP as key; Limit login attempts to 3 per minute per IP and Rate-limit ONLY real POST requests
    rateLimit($ip . '_login', 3, 60);

    
    require_once '../../config/db.php';

    // Import classes from the Firebase JWT package for encoding and decoding JWTs
    use Firebase\JWT\JWT;
    use Firebase\JWT\Key;

    // Enable MySQLi exceptions
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    try{
        $data = json_decode(file_get_contents("php://input"));
        $response = [];

        if ($data && isset($data->email, $data->password)) {
            $email = trim($data->email);
            $password = $data->password;
            $remember  = isset($data->remember) ? (bool) $data->remember : false;

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                http_response_code(400); // Bad Request
                $response['status'] = "error";
                $response['message'] = "Invalid email format";
                echo json_encode($response);
                exit();
            }

            $query = "SELECT * FROM users WHERE email = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();

                if (password_verify($password, $user['password'])) {


                    // // set when token will expire 
                    $accessTokenExpiry = time() + 60 * 60; // 1 hour

                    // // set when the refresh token will expire
                    $refreshTokenExpiry = time() + ($remember ? (60 * 60 * 24 * 30) : (60 * 60 * 24 * 7)); // 30d or 7d


                    // Build access token payload
                    $accessPayload  = [
                        'iss' => 'http://localhost', // issuer
                        "aud" => "http://localhost", // Audience
                        'iat' => time(), // issued at
                        'exp' => $accessTokenExpiry, // Expires based on the duration put
                        'user' => [
                            'id' => $user['id'],
                            'email' => $user['email'],
                            'role' => $user['role'],
                            'isAgent' => $user['is_agent'],
                        ]
                    ];

                    // Generate JWT token
                    $accessToken = JWT::encode($accessPayload, JWT_SECRET, 'HS256');

                    // Generate Refresh Token (a random string)
                    $refreshToken = bin2hex(random_bytes(32));

                    // Store the refresh token securely in the DB
                    $refreshTokenExpiryFormatted = date('Y-m-d H:i:s', $refreshTokenExpiry);

                    $insertQuery = "UPDATE users SET refresh_token = ?, refresh_token_expiry = ? WHERE id = ?";
                    $insertStmt = $conn->prepare($insertQuery);
                    $insertStmt->bind_param("sss", $refreshToken, $refreshTokenExpiryFormatted, $user['id']);
                    $insertStmt->execute();
                    $insertStmt->close();

                    // Set refresh token as HTTP-only cookie
                    setcookie('refresh_token', $refreshToken, [
                        'expires' => $refreshTokenExpiry,
                        'path' => '/',
                        'domain' => 'localhost', // Must match origin
                        'httponly' => true,
                        'secure' => false, // true in production with HTTPS
                        'samesite' => 'Lax'
                    ]);

                    // update last login
                    $now = date('Y-m-d H:i:s'); // Get current timestamp

                    // Store the last login and remember flag in the DB
                    $rememberInt = $remember ? 1 : 0;

                    $updateQuery = "UPDATE users SET last_login = ?, remember = ? WHERE email = ?";
                    $updateStmt = $conn->prepare($updateQuery);
                    $updateStmt->bind_param("sis", $now, $rememberInt, $email);
                    $updateStmt->execute();
                    $updateStmt->close(); 

                    http_response_code(200); // OK
                    $response['status'] = "success";
                    $response['message'] = "Login successful";
                    $response['token'] = $accessToken;
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
                    exit;
                }

            } else {
                http_response_code(404); //Not Found
                $response['status'] = "error";
                $response['message'] = "User not found";
                echo json_encode($response);
                exit;
            }
            $stmt->close();

        } else {
            http_response_code(400); //Bad Request
            $response['status'] = "error";
            $response['message'] = "Email and password are required";
            echo json_encode($response);
            exit;
        }

    } catch(Exception $e) {
        http_response_code(500); // Internal Server Error
        $response['status'] = "error";
        $response['message'] = "Something went wrong.";
        // $response['debug'] = $e->getMessage(); 
        echo json_encode($response);
    }

    $conn->close();