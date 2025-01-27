from django import template
from decimal import Decimal
import decimal

register = template.Library()

@register.filter
def multiply(value, arg):
    try:
        # Convert to Decimal for more precise calculations
        val = Decimal(str(value))
        arg = Decimal(str(arg))
        return val * arg
    except (ValueError, TypeError, decimal.InvalidOperation):
        return Decimal('0')
