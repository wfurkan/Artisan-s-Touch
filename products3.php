<?php
session_start();
require 'db.php';

// Fetch products for the current page
$sql = "SELECT * FROM products WHERE id BETWEEN 25 AND 36";
$result = $conn->query($sql);

$products = [];
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $products[] = $row;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Products 3 | Artisan's Touch</title>
    <link rel="stylesheet" href="css/products_style.css">
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

    <section class="product-section">
        <h2>Lighting and Decor</h2>
        <div id="product-grid" class="product-grid">
            <?php foreach ($products as $product): ?>
                <div class="product">
                    <img src="<?php echo $product['img']; ?>" alt="<?php echo $product['name']; ?>">
                    <h3><?php echo $product['name']; ?></h3>
                    <p><?php echo $product['description']; ?></p>
                    <p>Price: $<?php echo $product['price']; ?></p>
                    <p>Origin: <?php echo $product['origin']; ?></p>
                    <button class="add-to-cart" data-id="<?php echo $product['id']; ?>">Add to Cart</button>
                </div>
            <?php endforeach; ?>
        </div>
    </section>

    <footer>
        <p>&copy; 2024 Artisan's Touch. All rights reserved.</p>
    </footer>

    <script>
        document.querySelectorAll('.add-to-cart').forEach(button => {
            button.addEventListener('click', () => {
                const productId = button.getAttribute('data-id');
                fetch('add_to_cart.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `product_id=${productId}`
                }).then(response => {
                    if (response.ok) {
                        alert('Product added to cart!');
                    } else {
                        alert('Error adding product to cart.');
                    }
                }).catch(error => {
                    console.error('Error:', error);
                });
            });
        });
    </script>
</body>
</html>
