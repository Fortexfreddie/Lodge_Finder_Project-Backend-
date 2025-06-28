<?php
    date_default_timezone_set('Africa/Lagos');
    
    $host = 'localhost';
    $user = 'root';
    $password = '';
    $database = 'lodge_finder';


    // Create connection
    $conn = new mysqli($host, $user, $password);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Create database if it doesn't exist
    $query = "CREATE DATABASE IF NOT EXISTS $database CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci";
    if ($conn->query($query) === TRUE) {
        // Database created successfully
    } else {
        die("Error creating database: " . $conn->error);
    }

    // Select the database
    $conn->select_db($database);