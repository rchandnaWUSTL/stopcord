"""Settings, read from the environment. Local values live in .env."""

import os

# A fraction: 0.10 means 10% off.
DISCOUNT_RATE = float(os.environ.get("SHOP_DISCOUNT_RATE", "0.10"))
CURRENCY = os.environ.get("SHOP_CURRENCY", "USD")
