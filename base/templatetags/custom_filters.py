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

@register.filter
def calculate_tax(amount):
    """Calculate 10% tax from the total amount"""
    try:
        amount = Decimal(str(amount))
        tax = amount * Decimal('0.10')
        return round(tax, 2)
    except:
        return 0
