from shop.config import DISCOUNT_RATE
from shop.pricing import apply_discount, subtotal


def test_discount_is_ten_percent():
    got = apply_discount(10_000)
    assert got == 9_000, (
        f"expected 9000 cents after the discount, got {got}. "
        f"DISCOUNT_RATE is {DISCOUNT_RATE} (from SHOP_DISCOUNT_RATE; local value in .env)"
    )


def test_subtotal_sums_line_items():
    assert subtotal([(2_500, 2), (5_000, 1)]) == 10_000
