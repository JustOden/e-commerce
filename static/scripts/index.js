function addToCart(item_id, anon_cart='{}') {
    let amountToBuy = document.getElementById(item_id).value;
    let itemToAdd = [item_id, amountToBuy];
    if (amountToBuy >= 0) {
        let aCart = JSON.parse(anon_cart);
        if (Object.keys(cart).length === 0 &&
        aCart.constructor === Object) {
            cart = aCart;
        }
        cart[item_id] = amountToBuy;
        $.ajax({
            url: '/process',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                'item': itemToAdd,
                'cart': cart
            }),
            success: function(response) {
                let total = document.getElementById("total");
                total.innerHTML = `Total: $${response.result[2]}`;
                // let newAdded = document.getElementById("new");
                // newAdded.innerHTML = `${response.result[1]} ${response.result[0]} added!`;
            },
            error: function(error) {
                console.log(error);
            }
        });
    }
}

function searchField(all_items) {
    let dataList = document.getElementById("searchResults");
    let items = JSON.parse(all_items);
    for (const item of items) {
        let optionElement = document.createElement("OPTION");
        optionElement.setAttribute("id", item);
        let textNode = document.createTextNode(item);
        optionElement.appendChild(textNode);
        dataList.appendChild(optionElement);
    }
}

function cartPage() {
    location.replace("/cart");
}

let cart = {};


