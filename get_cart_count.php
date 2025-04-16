<?php
declare(strict_types=1);
require_once 'config.php';

header('Content-Type: application/json');
header('Cache-Control: no-store, max-age=0');

try {
    session_start();
    $response = ['count' => 0];
    $user_id = $_SESSION['user_id'] ?? null;

    if ($user_id) {
        $stmt = $conn->prepare(
            "SELECT SUM(c.quantity) AS count
             FROM cart c
             JOIN medicines m ON c.medicine_id = m.id
             WHERE c.user_id = ? AND m.stock > 0"
        );
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $response['count'] = (int)($stmt->get_result()->fetch_column() ?? 0);
    } else {
        $response['count'] = array_reduce(
            $_SESSION['cart'] ?? [],
            fn($carry, $item) => $carry + (isset($item['quantity']) ? (int)$item['quantity'] : 0),
            0
        );
    }

} catch (Throwable $e) {
    http_response_code(500);
    $response = [
        'success' => false,
        'error' => 'Count retrieval failed',
        'code' => 'CART_002'
    ];
    error_log("Cart Count Error: " . $e->getMessage());
}

echo json_encode($response);