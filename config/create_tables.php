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
        profile_pic VARCHAR(255),
        last_login TIMESTAMP NULL,
        refresh_token VARCHAR(255) DEFAULT NULL,
        refresh_token_expiry DATETIME DEFAULT NULL,
        remember TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";

    if ($conn->query($query) !== TRUE) {
        die("Error creating users table: " . $conn->error);
    }

    $kycTable = "CREATE TABLE IF NOT EXISTS kyc_applications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(50),
        full_name VARCHAR(100),
        email VARCHAR(100),
        whatsapp VARCHAR(20),
        location VARCHAR(100),
        lodge VARCHAR(100),
        account_number VARCHAR(30),
        bank_name VARCHAR(100),
        document VARCHAR(255),
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )";

    if ($conn->query($kycTable) !== TRUE) {
        die("Error creating kyc_applications table: " . $conn->error);
    }

    $conn->close();