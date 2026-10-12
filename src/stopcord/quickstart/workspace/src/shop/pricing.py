"""Discounts and totals. All amounts are integer cents."""

from shop.config import DISCOUNT_RATE


def subtotal(line_items: list[tuple[int, int]]) -> int:
    """Sum (unit_cents, quantity) pairs."""
    return sum(unit * qty for unit, qty in line_items)


def apply_discount(total_cents: int) -> int:
    """Return the total after the store-wide discount."""
    discount = total_cents * DISCOUNT_RATE / 100
    return round(total_cents - discount)


def order_total(line_items: list[tuple[int, int]]) -> int:
    """Subtotal, then the discount."""
    return apply_discount(subtotal(line_items))
