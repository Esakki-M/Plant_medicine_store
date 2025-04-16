<?php
header('Content-Type: application/json');
require_once 'config.php';

try {
    $sql = "SELECT m.*, c.name AS category_name 
            FROM medicines m
            JOIN categories c ON m.category_id = c.id
            WHERE m.is_featured = TRUE AND m.stock > 0
            ORDER BY RAND() LIMIT 8"; // Get 8 random featured items
    
    $result = $conn->query($sql);
    $products = $result->fetch_all(MYSQLI_ASSOC);
    
    // Cache headers
    header('Cache-Control: public, max-age=3600'); // 1 hour cache for featured items
    
    if ($products) {
        echo json_encode([
            'success' => true,
            'data' => $products
        ]);
    } else {
        echo json_encode([
            'success' => true,
            'data' => [],
            'message' => 'No featured products found'
        ]);
    }
    
} catch (Exception $e) {
    error_log("Featured Products Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Failed to load featured products'
    ]);
}