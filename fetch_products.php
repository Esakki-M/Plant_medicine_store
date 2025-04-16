<?php
header('Content-Type: application/json');
require_once 'config.php';

// Input validation
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = min(max(1, (int)($_GET['per_page'] ?? 12)), 50); // Limit to 50 items per page
$categoryId = isset($_GET['category_id']) ? (int)$_GET['category_id'] : null;
$searchQuery = isset($_GET['query']) ? trim($_GET['query']) : null;
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'name_asc';

try {
    // Build base query with SQL_CALC_FOUND_ROWS for total count
    $sql = "SELECT SQL_CALC_FOUND_ROWS m.*, c.name AS category_name 
            FROM medicines m
            JOIN categories c ON m.category_id = c.id
            WHERE m.stock > 0"; // Only show in-stock items

    $params = [];
    $types = '';
    
    // Search condition
    if ($searchQuery && strlen($searchQuery) >= 2) {
        $sql .= " AND (MATCH(m.name, m.description) AGAINST(? IN BOOLEAN MODE)";
        $params[] = "$searchQuery*";
        $types .= 's';
    }
    
    // Category filter
    if ($categoryId) {
        $sql .= " AND m.category_id = ?";
        $params[] = $categoryId;
        $types .= 'i';
    }
    
    // Sorting options
    $sortOptions = [
        'name_asc' => 'm.name ASC',
        'name_desc' => 'm.name DESC',
        'price_asc' => 'm.price ASC',
        'price_desc' => 'm.price DESC',
        'newest' => 'm.created_at DESC'
    ];
    $orderBy = $sortOptions[$sort] ?? 'm.name ASC';
    $sql .= " ORDER BY $orderBy";
    
    // Pagination
    $sql .= " LIMIT ? OFFSET ?";
    $params = array_merge($params, [$perPage, ($page - 1) * $perPage]);
    $types .= 'ii';
    
    // Execute query
    $stmt = $conn->prepare($sql);
    if ($params) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $products = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    
    // Get total count
    $total = $conn->query("SELECT FOUND_ROWS()")->fetch_row()[0];
    
    // Prepare response
    $response = [
        'success' => true,
        'data' => $products,
        'meta' => [
            'page' => $page,
            'per_page' => $perPage,
            'total' => $total,
            'total_pages' => ceil($total / $perPage),
            'sort' => $sort
        ]
    ];
    
    // Cache headers
    header('Cache-Control: public, max-age=300'); // 5 minute cache
    echo json_encode($response);
    
} catch (Exception $e) {
    error_log("Product API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false, 
        'error' => 'Internal server error',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : null
    ]);
}