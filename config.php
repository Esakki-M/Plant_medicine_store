<?php
// Strict error reporting for development (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 0); // Disable display in production
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

// Environment-based configuration
define('ENVIRONMENT', 'development'); // Change to 'production' in live server

// Load environment variables (using phpdotenv in real project)
if (ENVIRONMENT === 'development') {
    $host = 'localhost';
    $user = 'dev_user';
    $pass = 'dev_password';
    $db = 'plant_medicine_dev';
} else {
    $host = getenv('DB_HOST');
    $user = getenv('DB_USER');
    $pass = getenv('DB_PASS');
    $db = getenv('DB_NAME');
}

// Database connection with error handling
try {
    $conn = new mysqli($host, $user, $pass, $db);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    // Set charset for security
    $conn->set_charset("utf8mb4");
    
    // Set timezone
    $conn->query("SET time_zone = '+05:30'"); // IST
    
} catch (Exception $e) {
    error_log($e->getMessage());
    header('Content-Type: application/json');
    die(json_encode([
        'error' => 'Service unavailable',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Please try again later'
    ]));
}

/**
 * SECURITY HELPER FUNCTIONS
 */

// Generate CSRF token
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Validate CSRF token
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Sanitize input
function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

/**
 * DATABASE OPERATIONS WITH TRANSACTIONS
 */

// Fetch products with enhanced filtering
function fetchProducts($conn, $filters = []) {
    $defaults = [
        'page' => 1,
        'per_page' => 12,
        'category_id' => null,
        'search' => null,
        'sort' => 'name_asc'
    ];
    $filters = array_merge($defaults, $filters);
    
    try {
        $offset = ($filters['page'] - 1) * $filters['per_page'];
        
        $sql = "SELECT SQL_CALC_FOUND_ROWS m.*, c.name AS category_name 
                FROM medicines m
                JOIN categories c ON m.category_id = c.id
                WHERE m.stock > 0";
        
        $params = [];
        $types = '';
        
        if ($filters['category_id']) {
            $sql .= " AND m.category_id = ?";
            $params[] = $filters['category_id'];
            $types .= 'i';
        }
        
        if ($filters['search']) {
            $sql .= " AND (m.name LIKE ? OR m.description LIKE ?)";
            $searchTerm = "%{$filters['search']}%";
            $params[] = $searchTerm;
            $params[] = $searchTerm;
            $types .= 'ss';
        }
        
        // Sorting
        $sortOptions = [
            'name_asc' => 'm.name ASC',
            'name_desc' => 'm.name DESC',
            'price_asc' => 'm.price ASC',
            'price_desc' => 'm.price DESC',
            'newest' => 'm.created_at DESC'
        ];
        
        $sql .= " ORDER BY " . ($sortOptions[$filters['sort'] ?? 'm.name ASC');
        $sql .= " LIMIT ? OFFSET ?";
        $params[] = $filters['per_page'];
        $params[] = $offset;
        $types .= 'ii';
        
        $stmt = $conn->prepare($sql);
        if ($params) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        
        $products = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        
        // Get total count
        $total = $conn->query("SELECT FOUND_ROWS()")->fetch_row()[0];
        
        return [
            'products' => $products,
            'total' => $total,
            'pages' => ceil($total / $filters['per_page'])
        ];
        
    } catch (Exception $e) {
        error_log("Product fetch error: " . $e->getMessage());
        return ['error' => 'Failed to load products'];
    }
}

// Enhanced cart operations with transactions
function updateCart($conn, $userId, $items) {
    $conn->begin_transaction();
    
    try {
        // Clear existing cart
        $conn->query("DELETE FROM cart WHERE user_id = $userId");
        
        // Add new items
        $stmt = $conn->prepare(
            "INSERT INTO cart (user_id, medicine_id, quantity) 
             VALUES (?, ?, ?)"
        );
        
        foreach ($items as $item) {
            // Validate stock
            $medicine = $conn->query(
                "SELECT stock FROM medicines WHERE id = {$item['medicine_id']}"
            )->fetch_assoc();
            
            if (!$medicine || $medicine['stock'] < $item['quantity']) {
                throw new Exception("Insufficient stock for product {$item['medicine_id']}");
            }
            
            $stmt->bind_param(
                "iii", 
                $userId, 
                $item['medicine_id'], 
                $item['quantity']
            );
            $stmt->execute();
        }
        
        $conn->commit();
        return ['success' => true];
        
    } catch (Exception $e) {
        $conn->rollback();
        error_log("Cart update error: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

// Secure user authentication
function authenticateUser($conn, $email, $password) {
    try {
        $stmt = $conn->prepare(
            "SELECT id, email, password, name, role FROM users 
             WHERE email = ? AND status = 'active' LIMIT 1"
        );
        $stmt->bind_param("s", $email);
        $stmt->execute();
        
        $user = $stmt->get_result()->fetch_assoc();
        
        if ($user && password_verify($password, $user['password'])) {
            // Password is correct, check if needs rehash
            if (password_needs_rehash($user['password'], PASSWORD_BCRYPT)) {
                $newHash = password_hash($password, PASSWORD_BCRYPT);
                $conn->query("UPDATE users SET password = '$newHash' WHERE id = {$user['id']}");
            }
            
            // Start secure session
            session_start();
            session_regenerate_id(true);
            
            $_SESSION['user'] = [
                'id' => $user['id'],
                'email' => $user['email'],
                'name' => $user['name'],
                'role' => $user['role'],
                'logged_in' => true
            ];
            
            return ['success' => true, 'user' => $_SESSION['user']];
        }
        
        return ['success' => false, 'message' => 'Invalid credentials'];
        
    } catch (Exception $e) {
        error_log("Authentication error: " . $e->getMessage());
        return ['success' => false];
    }
}

// Rate limiting helper
function checkRateLimit($key, $limit = 5, $timeout = 60) {
    $cache = new Memcached();
    $cache->addServer('localhost', 11211);
    
    $current = $cache->get($key);
    if ($current && $current >= $limit) {
        return false;
    }
    
    $cache->add($key, 0, $timeout);
    $cache->increment($key);
    return true;
}