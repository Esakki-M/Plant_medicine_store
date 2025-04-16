<?php
declare(strict_types=1);
require_once 'config.php';

header('Content-Type: application/json');
header('Cache-Control: no-store, max-age=0');

try {
    // Secure session configuration
    session_set_cookie_params([
        'lifetime' => 86400,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'],
        'secure' => true,
        'httponly' true,
        'samesite' => 'Strict'
    ]);
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $response = ['success' => true, 'data' => []];
    $user_id = $_SESSION['user_id'] ?? null;

    if ($user_id) {
        // Database cart
        $stmt = $conn->prepare(
            "SELECT c.id, c.medicine_id, c.quantity, 
                    m.name, m.price, m.image_url, m.stock
             FROM cart c
             JOIN medicines m ON c.medicine_id = m.id
             WHERE c.user_id = ? AND m.stock > 0"
        );
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $response['data'] = $result->fetch_all(MYSQLI_ASSOC);
    } else {
        // Session cart validation
        $response['data'] = array_filter($_SESSION['cart'] ?? [], function($item) {
            return isset($item['medicine_id'], $item['quantity']) && $item['quantity'] > 0;
        });
    }

    // Add product URLs and validate stock
    $response['data'] = array_map(function($item) {
        $item['image_url'] = getProductImageUrl($item['image_url']);
        $item['max_quantity'] = min($item['stock'] ?? 99, 99);
        return $item;
    }, $response['data']);

} catch (Throwable $e) {
    http_response_code(500);
    $response = [
        'success' => false,
        'error' => 'Cart retrieval failed',
        'code' => 'CART_001'
    ];
    error_log("Cart Error: " . $e->getMessage());
}

echo json_encode($response);

function getProductImageUrl(?string $path): string {
    return $path ? "/media/products/{$path}" : '/media/placeholder.jpg';
}