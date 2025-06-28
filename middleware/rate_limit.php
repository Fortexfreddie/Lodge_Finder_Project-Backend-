<?php
/**
 * Rate limit function to block too many requests from a specific key (e.g. IP address or user ID).
 *
 * @param string $key     A unique identifier for the client (IP, user ID, etc).
 * @param int $limit      The maximum number of allowed requests.
 * @param int $seconds    The time window in seconds (e.g., 60 means "5 requests per 60 seconds").
 */
function rateLimit($key, $limit = 5, $seconds = 60) {
    // Store rate limit data as a file in the system temp folder, hashed for uniqueness
    $file = sys_get_temp_dir() . "/rate_limit_" . md5($key) . ".json";
    $now = time(); // Current timestamp

    // If the file exists, load the list of request timestamps; otherwise use an empty array
    $requests = file_exists($file) ? json_decode(file_get_contents($file), true) : [];

    // Remove timestamps that are older than the time window
    $requests = array_filter($requests, function($timestamp) use ($now, $seconds) {
        return ($now - $timestamp) < $seconds;
    });

    // If too many requests were made in the time window, block the request
    if (count($requests) >= $limit) {
        http_response_code(429); // Too Many Requests
        echo json_encode([
            "status" => "error",
            "message" => "Too many requests. Try again later."
        ]);
        exit(); // Stop further execution
    }

    // Add current request timestamp and save the updated list
    $requests[] = $now;
    file_put_contents($file, json_encode($requests));
}