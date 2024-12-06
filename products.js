/* Student Info */
/* Name: Furkan Bilgi */
/* Student ID: 24378020 */
/* File: products.css */


const products = {
    "products1": [
        { id: 1, name: "Turkish Kilim Rug", description: "A vibrant, handwoven rug featuring traditional Turkish geometric patterns.", price: "$250", origin: "Made in Turkey", img: "img/turkish_kilim_rug.jpg" },
        { id: 2, name: "Mexican Otomi Tapestry", description: "A colorful embroidered wall hanging with intricate animal and floral designs.", price: "$180", origin: "Made in Mexico", img: "img/mexican_otomi_tapestry.jpg" },
        { id: 3, name: "Moroccan Wool Blanket", description: "A hand-loomed wool blanket with bold stripes and delicate tassels.", price: "$200", origin: "Made in Morocco", img: "img/moroccan_wool_blanket.jpg" },
        { id: 4, name: "Indian Block-Printed Quilt", description: "A lightweight cotton quilt hand-printed with intricate block patterns.", price: "$150", origin: "Made in India", img: "img/indian_block_quilt.jpg" },
        { id: 5, name: "Peruvian Alpaca Throw", description: "A luxuriously soft throw made from alpaca wool, featuring vibrant Andean designs.", price: "$120", origin: "Made in Peru", img: "img/peruvian_alpaca_throw.jpg" },
        { id: 6, name: "African Mud Cloth", description: "A traditional Mali mud cloth dyed with natural pigments, perfect as a wall hanging or throw.", price: "$110", origin: "Made in Mali", img: "img/african_mud_cloth.jpg" },
        { id: 7, name: "Guatemalan Huipil Pillowcase", description: "A colorful pillowcase crafted from repurposed traditional Guatemalan clothing.", price: "$45", origin: "Made in Guatemala", img: "img/guatemalan_huipil_pillowcase.jpg" },
        { id: 8, name: "Japanese Indigo Furoshiki", description: "A hand-dyed indigo cloth used for wrapping gifts or as décor.", price: "$35", origin: "Made in Japan", img: "img/japanese_indigo_furoshiki.jpg" },
        { id: 9, name: "Afghan Embroidered Table Runner", description: "A detailed table runner with floral embroidery from Afghan artisans.", price: "$60", origin: "Made in Afghanistan", img: "img/afghan_table_runner.jpg" },
        { id: 10, name: "Swedish Wool Lap Blanket", description: "A minimalist design inspired by Swedish folk art, made from organic wool.", price: "$90", origin: "Made in Sweden", img: "img/swedish_wool_blanket.jpg" },
        { id: 11, name: "Chinese Silk Brocade Cushion Cover", description: "A luxurious silk cushion cover with golden dragon motifs.", price: "$55", origin: "Made in China", img: "img/chinese_silk_cushion.jpg" },
        { id: 12, name: "Vietnamese Silk Scarf", description: "A lightweight silk scarf with hand-painted floral designs.", price: "$40", origin: "Made in Vietnam", img: "img/vietnamese_silk_scarf.jpg" },
    ],
    "products2": [
        { id: 13, name: "Japanese Raku Tea Bowl", description: "A handcrafted tea bowl with a rustic, uneven glaze used in Japanese tea ceremonies.", price: "$75", origin: "Made in Japan", img: "img/japanese_raku_tea_bowl.jpg" },
        { id: 14, name: "Greek Amphora Vase", description: "A ceramic vase featuring ancient Greek patterns and mythology-inspired designs.", price: "$140", origin: "Made in Greece", img: "img/greek_amphora_vase.jpg" },
        { id: 15, name: "Turkish Iznik Plate", description: "A hand-painted ceramic plate with vibrant floral and geometric patterns.", price: "$100", origin: "Made in Turkey", img: "img/turkish_iznik_plate.jpg" },
        { id: 16, name: "Moroccan Tagine Pot", description: "A traditional earthenware pot for cooking and serving Moroccan dishes.", price: "$60", origin: "Made in Morocco", img: "img/moroccan_tagine_pot.jpg" },
        { id: 17, name: "Italian Majolica Bowl", description: "A colorful, hand-painted bowl inspired by Renaissance Italian ceramics.", price: "$85", origin: "Made in Italy", img: "img/italian_majolica_bowl.jpg" },
        { id: 18, name: "Mexican Talavera Mug", description: "A brightly painted ceramic mug with intricate floral designs.", price: "$35", origin: "Made in Mexico", img: "img/mexican_talavera_mug.jpg" },
        { id: 19, name: "Korean Celadon Vase", description: "A jade-green ceramic vase with a smooth glaze, showcasing Korean craftsmanship.", price: "$120", origin: "Made in Korea", img: "img/korean_celadon_vase.jpg" },
        { id: 20, name: "Polish Pottery Soup Bowl", description: "A durable ceramic soup bowl with intricate blue-and-white floral designs.", price: "$45", origin: "Made in Poland", img: "img/polish_pottery_soup_bowl.jpg" },
        { id: 21, name: "Ethiopian Coffee Set", description: "A set of small ceramic coffee cups and a jebena (coffee pot) for traditional coffee rituals.", price: "$80", origin: "Made in Ethiopia", img: "img/ethiopian_coffee_set.jpg" },
        { id: 22, name: "Spanish Cazuela Dish", description: "A terracotta dish for cooking and serving tapas, featuring rustic designs.", price: "$50", origin: "Made in Spain", img: "img/spanish_cazuela_dish.jpg" },
        { id: 23, name: "Indian Blue Pottery Candle Holder", description: "A ceramic candle holder with intricate floral patterns in blue.", price: "$25", origin: "Made in India", img: "img/indian_blue_pottery_candle_holder.jpg" },
        { id: 24, name: "Persian Miniature Tile", description: "A decorative ceramic tile with intricate Persian miniature art.", price: "$35", origin: "Made in Iran", img: "img/persian_miniature_tile.jpg" },
    ],
    "products3": [
        { id: 25, name: "Turkish Mosaic Lamp", description: "A stunning table lamp with colorful glass mosaics and brass detailing.", price: "$130", origin: "Made in Turkey", img: "img/turkish_mosaic_lamp.jpg" },
        { id: 26, name: "Moroccan Brass Lantern", description: "An intricately carved brass lantern casting unique patterns of light.", price: "$150", origin: "Made in Morocco", img: "img/moroccan_brass_lantern.jpg" },
        { id: 27, name: "Indian Peacock Oil Lamp", description: "A brass oil lamp with a peacock motif, used in traditional Indian ceremonies.", price: "$80", origin: "Made in India", img: "img/indian_peacock_oil_lamp.jpg" },
        { id: 28, name: "Chinese Red Paper Lantern", description: "A red lantern with hand-painted calligraphy for festive occasions.", price: "$30", origin: "Made in China", img: "img/chinese_red_paper_lantern.jpg" },
        { id: 29, name: "Egyptian Alabaster Candle Holder", description: "A smooth, translucent alabaster candle holder emitting a warm glow.", price: "$45", origin: "Made in Egypt", img: "img/egyptian_alabaster_candle_holder.jpg" },
        { id: 30, name: "Thai Bamboo Lantern", description: "A handwoven bamboo lantern with a minimalist design.", price: "$35", origin: "Made in Thailand", img: "img/thai_bamboo_lantern.jpg" },
        { id: 31, name: "Japanese Shoji Lamp", description: "A wooden frame lamp with rice paper panels, creating soft diffused light.", price: "$110", origin: "Made in Japan", img: "img/japanese_shoji_lamp.jpg" },
        { id: 32, name: "Philippine Capiz Shell Chandelier", description: "A chandelier crafted from translucent capiz shells for an ethereal look.", price: "$180", origin: "Made in the Philippines", img: "img/philippine_capiz_chandelier.jpg" },
        { id: 33, name: "Italian Murano Glass Pendant Light", description: "A colorful, blown-glass pendant light from Murano Island.", price: "$250", origin: "Made in Italy", img: "img/italian_murano_glass_light.jpg" },
        { id: 34, name: "African Beaded Floor Lamp", description: "A tall lamp with a base decorated with intricate Maasai beadwork.", price: "$120", origin: "Made in Kenya", img: "img/african_beaded_lamp.jpg" },
        { id: 35, name: "French Art Nouveau Desk Lamp", description: "A sculptural lamp inspired by the flowing lines of Art Nouveau design.", price: "$200", origin: "Made in France", img: "img/french_art_nouveau_lamp.jpg" },
        { id: 36, name: "Scandinavian Minimalist Pendant Lamp", description: "A sleek, simple pendant light in natural wood tones.", price: "$100", origin: "Made in Denmark", img: "img/scandinavian_minimalist_lamp.jpg" },
    ],
    "products4": [
        { id: 37, name: "Turkish Evil Eye Necklace", description: "A delicate necklace featuring the iconic Turkish evil eye bead for protection.", price: "$40", origin: "Made in Turkey", img: "img/turkish_evil_eye_necklace.jpg" },
        { id: 38, name: "Indian Kundan Bracelet", description: "An intricate bracelet with colorful gemstones in the traditional Kundan style.", price: "$120", origin: "Made in India", img: "img/indian_kundan_bracelet.jpg" },
        { id: 39, name: "Mexican Silver Earrings", description: "Handcrafted sterling silver earrings with Aztec-inspired designs.", price: "$60", origin: "Made in Mexico", img: "img/mexican_silver_earrings.jpg" },
        { id: 40, name: "Kenyan Beaded Necklace", description: "A bold, colorful necklace made with Maasai-style beadwork.", price: "$50", origin: "Made in Kenya", img: "img/kenyan_beaded_necklace.jpg" },
        { id: 41, name: "Peruvian Chakana Pendant", description: "A silver pendant shaped like the Andean cross, a symbol of Incan culture.", price: "$80", origin: "Made in Peru", img: "img/peruvian_chakana_pendant.jpg" },
        { id: 42, name: "Balinese Filigree Ring", description: "A detailed sterling silver ring with intricate filigree designs.", price: "$70", origin: "Made in Indonesia", img: "img/balinese_filigree_ring.jpg" },
        { id: 43, name: "Native American Turquoise Cuff", description: "A handcrafted silver cuff bracelet with a turquoise stone centerpiece.", price: "$150", origin: "Made in the USA", img: "img/native_american_turquoise_cuff.jpg" },
        { id: 44, name: "Japanese Kanzashi Hairpin", description: "A traditional decorative hairpin adorned with hand-painted floral designs.", price: "$45", origin: "Made in Japan", img: "img/japanese_kanzashi_hairpin.jpg" },
        { id: 45, name: "Tibetan Prayer Beads", description: "A mala necklace made with wooden beads and a tassel, used for meditation.", price: "$30", origin: "Made in Tibet", img: "img/tibetan_prayer_beads.jpg" },
        { id: 46, name: "Italian Venetian Glass Pendant", description: "A vibrant pendant made from Murano glass with swirled patterns.", price: "$90", origin: "Made in Italy", img: "img/italian_venetian_glass_pendant.jpg" },
        { id: 47, name: "Egyptian Scarab Amulet", description: "A pendant inspired by ancient Egyptian scarab symbols, made of brass and enamel.", price: "$50", origin: "Made in Egypt", img: "img/egyptian_scarab_amulet.jpg" },
        { id: 48, name: "South African Zulu Beaded Anklet", description: "A colorful anklet featuring traditional Zulu beadwork patterns.", price: "$25", origin: "Made in South Africa", img: "img/south_african_zulu_anklet.jpg" }
    ]
};
function generateProducts(pageId, containerId) {
    const productList = products[pageId];
    let productHTML = "";

    productList.forEach(product => {
        productHTML += `
            <div class="product">
                <img src="${product.img}" alt="${product.name}">
                <h3>${product.name}</h3>
                <p>${product.description}</p>
                <p>Price: $${product.price}</p>
                <p>${product.origin}</p>
                <p>Product ID: ${product.id}</p>
                <button class="add-to-cart" data-id="${product.id}">Add to Cart</button>
            </div>
        `;
    });

    document.getElementById(containerId).innerHTML = productHTML;

    // Attach event listeners to "Add to Cart" buttons
    attachAddToCartListeners();
}

// Function to attach event listeners to "Add to Cart" buttons
function attachAddToCartListeners() {
    const cartButtons = document.querySelectorAll(".add-to-cart");
    cartButtons.forEach(button => {
        button.addEventListener("click", () => {
            const productId = button.getAttribute("data-id");
            addToCart(productId);
        });
    });
}

// Function to handle "Add to Cart" functionality
function addToCart(productId) {
    fetch("add_to_cart.php", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `product_id=${productId}`,
    })
        .then(response => {
            if (response.ok) {
                alert("Product added to cart!");
            } else {
                alert("Failed to add product to cart. Please try again.");
            }
        })
        .catch(error => {
            console.error("Error adding product to cart:", error);
            alert("An error occurred. Please try again later.");
        });
}

// Automatically call generateProducts on page load
const currentPage = window.location.pathname.split("/").pop().split(".")[0]; 
if (currentPage in products) {
    generateProducts(currentPage, "product-grid");
}