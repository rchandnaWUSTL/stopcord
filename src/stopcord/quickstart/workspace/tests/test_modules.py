from shop import cart, inventory, orders, shipping, tax, users


def test_modules_describe_themselves():
    for mod, name in [(cart, "cart"), (inventory, "inventory"), (orders, "orders"),
                      (shipping, "shipping"), (tax, "tax"), (users, "users")]:
        assert mod.describe() == name
