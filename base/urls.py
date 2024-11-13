from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.custom_logout, name='logout'),
    path('signup/', views.signup_view, name='signup'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('cart/', views.cart_view, name='cart_view'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:token>/', views.reset_password, name='reset_password'),
    path('auth/google/login/', views.google_login, name='google_login'),
    path('auth/google/callback/', views.google_callback, name='google_callback'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/customers/', views.customer_table, name='customer_table'),
    path('toggle-user-status/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),
    path('delete-product/<int:product_id>/', views.delete_product, name='delete_product'),
    path('edit-product/<int:product_id>/', views.edit_product, name='edit_product'),
    path('remove-from-cart/<int:item_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('update-cart/<int:item_id>/', views.update_cart_item, name='update_cart_item'),
    path('create-checkout-session/', views.create_checkout_session, name='create_checkout_session'),
    path('payment/success/', views.payment_success, name='payment_success'),
    path('payment/cancelled/', views.payment_cancelled, name='payment_cancelled'),
    path('webhook/stripe/', views.stripe_webhook, name='stripe_webhook'),
    path('purchase-history/', views.purchase_history, name='purchase_history'),
]
