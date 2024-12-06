/* Student Info */
/* Name: Furkan Bilgi */
/* Student ID: 24378020 */
/* File: nav.js */

var nav = [
    { "title": "Home", "url": "index.html" },
    { "title": "About", "url": "about.html" },
    { "title": "Contact", "url": "contact.html" },
    { "title": "Products 1", "url": "products1.html" },
    { "title": "Products 2", "url": "products2.html" },
    { "title": "Products 3", "url": "products3.html" },
    { "title": "Products 4", "url": "products4.html" },
    { "title": "Cart", "url": "cart.php" },
    { "title": "Profile", "url": "profile.php" } // Make sure this line exists
];

var menu_list = "";

for (var i = 0; i < nav.length; i++) {
    menu_list += `<li><a href="${nav[i].url}">${nav[i].title}</a></li>`;
}

document.getElementById("nav").innerHTML = menu_list;


