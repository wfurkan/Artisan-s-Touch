<?php
// Start session
session_start();

// Check if the cart exists in the session, if not, initialize it
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// Check if product_id is sent via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['product_id'])) {
    $product_id = intval($_POST['product_id']);

    // Increment the quantity if the product is already in the cart
    if (isset($_SESSION['cart'][$product_id])) {
        $_SESSION['cart'][$product_id]++;
    } else {
        // Add new product with a quantity of 1
        $_SESSION['cart'][$product_id] = 1;
    }

    // Redirect back to the previous page (e.g., product page)
    header('Location: ' . $_SERVER['HTTP_REFERER']);
    exit();
} else {
    // If product_id is not set, redirect to the home page
    header('Location: index.html');
    exit();
}
