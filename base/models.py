from django.db import models
from django.contrib.auth.hashers import make_password, check_password

class Customer(models.Model):
    USER_TYPE_CHOICES = [
        ('customer', 'Customer'),
        ('admin', 'Admin'),
    ]

    customer_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    phone = models.CharField(max_length=15)
    address = models.TextField()
    reset_password_token = models.CharField(max_length=100, null=True, blank=True)
    reset_password_expires = models.DateTimeField(null=True, blank=True)
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='customer')
    is_active = models.BooleanField(default=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.name

class Product(models.Model):
    CATEGORY_CHOICES = [
        ('cricket', 'Cricket'),
        ('football', 'Football'),
        ('badminton', 'Badminton'),
        ('table_games', 'Table Games'),
    ]

    name = models.CharField(max_length=200)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    image = models.ImageField(upload_to='product_images/')
    stock = models.PositiveIntegerField()

    def __str__(self):
        return self.name

class Cart(models.Model):
    user = models.OneToOneField(Customer, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Cart for {self.user.username}"

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, related_name='items', on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.quantity} of {self.product.name}"

    @property
    def total_price(self):
        return self.quantity * self.product.price



        
