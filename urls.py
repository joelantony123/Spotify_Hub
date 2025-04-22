from django.urls import path
from . import views

urlpatterns = [
    path('process-delivery-payment/', views.process_delivery_payment, name='process_delivery_payment'),
] 