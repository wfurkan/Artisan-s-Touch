<?php
session_start();

if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// Add product to cart logic remains as-is
require 'db.php';

// Fetch cart items
$cart_items = [];
if (!empty($_SESSION['cart'])) {
    $product_ids = implode(',', array_keys($_SESSION['cart']));
    $sql = "SELECT * FROM products WHERE id IN ($product_ids)";
    $result = $conn->query($sql);

    while ($product = $result->fetch_assoc()) {
        $product['quantity'] = $_SESSION['cart'][$product['id']];
        $cart_items[] = $product;
    }
}

// Remove item from cart
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove_id'])) {
    unset($_SESSION['cart'][$_POST['remove_id']]);
    header('Location: cart.php');
    exit;
}

// Update item quantity
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_id'], $_POST['update_quantity'])) {
    $id = $_POST['update_id'];
    $quantity = $_POST['update_quantity'];
    if ($quantity <= 0) {
        unset($_SESSION['cart'][$id]);
    } else {
        $_SESSION['cart'][$id] = $quantity;
    }
    header('Location: cart.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shopping Cart</title>
    <link rel="stylesheet" href="css/cart.css"> <!-- Updated cart-specific CSS -->
    <link rel="stylesheet" href="css/nav.css">
</head>
<body>
    <header class="navbar">
        <div class="logo-title">
            <a href="index.html">
                <img src="img/logo.png" alt="Artisan's Touch Logo" style="width:80px; height:auto;">
            </a>
            <h1>Artisan's Touch</h1>
        </div>
        <nav>
            <ul>
                <li><a href="index.html">Home</a></li>
                <li><a href="about.html">About Us</a></li>
                <li><a href="contact.html">Contact</a></li>
                <li><a href="products1.php">Products 1</a></li>
                <li><a href="products2.php">Products 2</a></li>
                <li><a href="products3.php">Products 3</a></li>
                <li><a href="products4.php">Products 4</a></li>
                <li><a href="profile.php">Profile</a></li>
                <li><a href="cart.php">Cart</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <h1>Your Shopping Cart</h1>
        <?php if (!empty($cart_items)) { ?>
            <table>
    <thead>
        <tr>
            <th>Image</th>
            <th>Product</th>
            <th>Price</th>
            <th>Quantity</th>
            <th>Total</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php $grand_total = 0; ?>
        <?php foreach ($cart_items as $item) { ?>
        <tr>
            <td>
                <img src="<?php echo $item['img']; ?>" alt="<?php echo $item['name']; ?>" style="width: 50px; height: 50px; object-fit: cover; border-radius: 5px;">
            </td>
            <td><?php echo $item['name']; ?></td>
            <td>$<?php echo $item['price']; ?></td>
            <td>
                <form action="cart.php" method="POST">
                    <input type="number" name="update_quantity" value="<?php echo $item['quantity']; ?>" min="1">
                    <input type="hidden" name="update_id" value="<?php echo $item['id']; ?>">
                    <button type="submit" class="update-btn">Update</button>
                </form>
            </td>
            <td>$<?php echo $item['price'] * $item['quantity']; ?></td>
            <td>
                <form action="cart.php" method="POST">
                    <input type="hidden" name="remove_id" value="<?php echo $item['id']; ?>">
                    <button type="submit" class="remove-btn">Remove</button>
                </form>
            </td>
        </tr>
        <?php $grand_total += $item['price'] * $item['quantity']; ?>
        <?php } ?>
        <tr>
            <td colspan="4" style="text-align: right; font-weight: bold;">Grand Total</td>
            <td colspan="2" style="text-align: center; font-weight: bold;">$<?php echo $grand_total; ?></td>
        </tr>
    </tbody>
</table>

            <a href="checkout.php" class="checkout-btn">Proceed to Checkout</a>
        <?php } else { ?>
            <p>Your cart is empty.</p>
        <?php } ?>
    </main>

    <script src="js/nav.js"></script>
</body>
</html>
