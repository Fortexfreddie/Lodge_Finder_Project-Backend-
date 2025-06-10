<?php
    include 'db.php';

    
    $query = "CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(50) PRIMARY KEY,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password VARCHAR(255) NOT NULL,
        role VARCHAR(10) DEFAULT 'user',
        is_admin TINYINT(1) DEFAULT 0,
        is_agent TINYINT(1) DEFAULT 0,
        is_suspended TINYINT(1) DEFAULT 0,
        is_verified TINYINT(1) DEFAULT 0,
        verification_token VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";

    if ($conn->query($query) !== TRUE) {
        die("Error creating users table: " . $conn->error);
    }

    $conn->close();
?>