<?php
require_once 'config.php';

// Start session securely
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 86400,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'],
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_start();
}

header('Content-Type: application/json');

// Error definitions
const ERROR_CODES = [
    'INVALID_INPUT' => ['code' => 400, 'message' => 'Invalid product ID or quantity'],
    'OUT_OF_STOCK' => ['code' => 400, 'message' => 'Product is out of stock or does not exist'],
    'DATABASE_ERROR' => ['code' => 500, 'message' => 'Database operation failed']
];

// Get and validate input
$data = json_decode(file_get_contents('php://input'), true);
$product_id = filter_var($data['product_id'] ?? 0, FILTER_VALIDATE_INT);
$quantity = filter_var($data['quantity'] ?? 1, FILTER_VALIDATE_INT);

if (!$product_id || $quantity <= 0) {
    http_response_code(ERROR_CODES['INVALID_INPUT']['code']);
    echo json_encode(['success' => false, 'error' => ERROR_CODES['INVALID_INPUT']['message']]);
    exit;
}

$user_id = $_SESSION['user_id'] ?? null;
$response = ['success' => false];

try {
    $conn->begin_transaction();

    // Check product availability with FOR UPDATE lock
    $stmt = $conn->prepare("SELECT id, name, price, stock, image FROM medicines WHERE id = ? AND stock >= ? FOR UPDATE");
    $stmt->bind_param("ii", $product_id, $quantity);
    $stmt->execute();
    $product = $stmt->get_result()->fetch_assoc();

    if (!$product) {
        http_response_code(ERROR_CODES['OUT_OF_STOCK']['code']);
        $response['error'] = ERROR_CODES['OUT_OF_STOCK']['message'];
        $conn->rollback();
        echo json_encode($response);
        exit;
    }

    if ($user_id) {
        // Database cart operations
        $stmt = $conn->prepare("
            INSERT INTO cart (user_id, product_id, quantity) 
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
        ");
        $stmt->bind_param("iii", $user_id, $product_id, $quantity);
        $stmt->execute();

        // Update product stock
        $stmt = $conn->prepare("UPDATE medicines SET stock = stock - ? WHERE id = ?");
        $stmt->bind_param("ii", $quantity, $product_id);
        $stmt->execute();
    } else {
        // Session cart operations
        $_SESSION['cart'] = $_SESSION['cart'] ?? [];
        $cart_key = array_search($product_id, array_column($_SESSION['cart'], 'product_id'));

        if ($cart_key !== false) {
            $_SESSION['cart'][$cart_key]['quantity'] += $quantity;
        } else {
            $_SESSION['cart'][] = [
                'product_id' => $product_id,
                'name' => $product['name'],
                'price' => $product['price'],
                'quantity' => $quantity,
                'image' => $product['image'] ?? 'default.jpg'
            ];
        }
    }

    $conn->commit();
    $response = [
        'success' => true,
        'message' => 'Product added to cart',
        'cartCount' => $user_id ? getDBCartCount($conn, $user_id) : count($_SESSION['cart'])
    ];
} catch (Exception $e) {
    $conn->rollback();
    error_log("Cart Error: " . $e->getMessage());
    http_response_code(ERROR_CODES['DATABASE_ERROR']['code']);
    $response['error'] = ERROR_CODES['DATABASE_ERROR']['message'];
}

echo json_encode($response);

function getDBCartCount($conn, $user_id) {
    $stmt = $conn->prepare("SELECT SUM(quantity) as total FROM cart WHERE user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result['total'] ?? 0;
}