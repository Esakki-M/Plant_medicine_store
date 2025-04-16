<?php
header('Content-Type: application/json');
require_once 'config.php';

// Secure session configuration
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

// Define error constants
const ERRORS = [
    'INVALID_REQUEST' => ['code' => 400, 'message' => 'Invalid request'],
    'UNAUTHORIZED' => ['code' => 401, 'message' => 'Unauthorized'],
    'METHOD_NOT_ALLOWED' => ['code' => 405, 'message' => 'Method not allowed'],
    'SERVER_ERROR' => ['code' => 500, 'message' => 'Internal server error']
];

try {
    $method = $_SERVER['REQUEST_METHOD'];
    
    switch ($method) {
        case 'POST':
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (!$input) {
                throw new Exception('Invalid JSON input', ERRORS['INVALID_REQUEST']['code']);
            }
            
            if (isset($input['login'])) {
                handleLogin($conn, $input);
            } elseif (isset($input['register'])) {
                handleRegistration($conn, $input);
            } else {
                throw new Exception('Invalid action', ERRORS['INVALID_REQUEST']['code']);
            }
            break;
            
        case 'GET':
            checkSession();
            break;
            
        case 'DELETE':
            handleLogout();
            break;
            
        default:
            throw new Exception(ERRORS['METHOD_NOT_ALLOWED']['message'], 
                              ERRORS['METHOD_NOT_ALLOWED']['code']);
    }
} catch (Exception $e) {
    $code = $e->getCode() ?: 500;
    http_response_code($code);
    error_log("Auth Error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}

// Handler Functions
function handleLogin($conn, $input) {
    $email = filter_var($input['email'], FILTER_VALIDATE_EMAIL);
    $password = $input['password'] ?? '';
    
    if (!$email || empty($password)) {
        throw new Exception('Invalid email or password', 400);
    }
    
    // Get user from database
    $stmt = $conn->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        throw new Exception('Invalid credentials', 401);
    }
    
    $user = $result->fetch_assoc();
    
    // Verify password
    if (!password_verify($password, $user['password'])) {
        throw new Exception('Invalid credentials', 401);
    }
    
    // Set session
    $_SESSION['logged_in'] = true;
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['user_name'] = $user['name'];
    
    // Generate CSRF token
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    
    echo json_encode([
        'success' => true,
        'user' => [
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email']
        ],
        'csrf_token' => $_SESSION['csrf_token']
    ]);
}

function handleRegistration($conn, $input) {
    $name = trim($input['name'] ?? '');
    $email = filter_var($input['email'], FILTER_VALIDATE_EMAIL);
    $password = $input['password'] ?? '';
    
    // Validate input
    if (empty($name) || !$email || strlen($password) < 8) {
        throw new Exception('Name, valid email and password (min 8 chars) required', 400);
    }
    
    // Check if email exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows > 0) {
        throw new Exception('Email already registered', 400);
    }
    
    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    
    // Insert new user
    $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $name, $email, $hashedPassword);
    
    if (!$stmt->execute()) {
        throw new Exception('Registration failed', 500);
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Registration successful'
    ]);
}

function checkSession() {
    if (isset($_SESSION['logged_in'])) {
        echo json_encode([
            'success' => true,
            'user' => [
                'id' => $_SESSION['user_id'],
                'name' => $_SESSION['user_name'],
                'email' => $_SESSION['user_email']
            ],
            'csrf_token' => $_SESSION['csrf_token'] ?? null
        ]);
    } else {
        throw new Exception('Not authenticated', 401);
    }
}

function handleLogout() {
    // Clear session data
    $_SESSION = [];
    
    // Delete session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    
    session_destroy();
    echo json_encode(['success' => true]);
}
