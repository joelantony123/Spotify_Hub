from django.contrib import admin
from .models import Customer, Product, Order, OrderItem, DeliveryBoy, OrderAssigned
# Register your models here.

admin.site.register(Customer)
admin.site.register(Product)
admin.site.register(Order)
admin.site.register(OrderItem)
admin.site.register(DeliveryBoy)
admin.site.register(OrderAssigned)


