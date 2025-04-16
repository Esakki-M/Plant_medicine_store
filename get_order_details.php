<?php
declare(strict_types=1);
require_once 'config.php';

header('Content-Type: application/json');
header('Cache-Control: no-store, max-age=0');

try {
    if (!isset($_GET['order_id']) || !preg_match('/^ORD-\d+$/', $_GET['order_id'])) {
        throw new InvalidArgumentException('Invalid order ID format', 400);
    }

    $order_id = $_GET['order_id'];
    $response = [];

    // Get order header
    $stmt = $conn->prepare(
        "SELECT o.id, o.total_price, o.status, o.payment_method,
                o.shipping_address, o.created_at,
                u.name AS customer_name, u.email, u.phone
         FROM orders o
         JOIN users u ON o.user_id = u.id
         WHERE o.id = ?"
    );
    $stmt->bind_param("s", $order_id);
    $stmt->execute();
    
    if (!($order = $stmt->get_result()->fetch_assoc())) {
        throw new RuntimeException('Order not found', 404);
    }

    // Get order items
    $stmt = $conn->prepare(
        "SELECT m.name, oi.quantity, oi.price,
                m.image_url, m.id AS medicine_id
         FROM order_items oi
         JOIN medicines m ON oi.medicine_id = m.id
         WHERE oi.order_id = ?"
    );
    $stmt->bind_param("s", $order_id);
    $stmt->execute();
    
    $order['items'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $order['items'] = array_map(function($item) {
        $item['image_url'] = getProductImageUrl($item['image_url']);
        return $item;
    }, $order['items']);

    $response = ['success' => true, 'data' => $order];

} catch (InvalidArgumentException $e) {
    http_response_code($e->getCode());
    $response = ['success' => false, 'error' => $e->getMessage(), 'code' => 'ORDER_001'];
} catch (RuntimeException $e) {
    http_response_code($e->getCode());
    $response = ['success' => false, 'error' => $e->getMessage(), 'code' => 'ORDER_002'];
} catch (Throwable $e) {
    http_response_code(500);
    $response = ['success' => false, 'error' => 'Order lookup failed', 'code' => 'ORDER_003'];
    error_log("Order Error: " . $e->getMessage());
}

echo json_encode($response);

function getProductImageUrl(?string $path): string {
    return $path ? "/media/products/{$path}" : '/media/placeholder.jpg';
}