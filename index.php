<?php
    header("Content-Type: application/json");

    $response = [
        "status" => "online",                
        "message" => "Lodge Finder PHP API is running!"  
    ];

    echo json_encode($response);
?>
