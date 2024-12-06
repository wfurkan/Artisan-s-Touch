<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (!isset($_SESSION['cart'])) {
        $_SESSION['cart'] = [];
    }

    $product_id = $input['product_id'];

    if (isset($_SESSION['cart'][$product_id])) {
        $_SESSION['cart'][$product_id]++; // Increment quantity
    } else {
        $_SESSION['cart'][$product_id] = 1; // Add new product with quantity 1
    }

    echo json_encode(['message' => 'Product added to cart successfully.']);
}
?>
