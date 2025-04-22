class OrderAssigned(models.Model):
    order = models.OneToOneField(Order, on_delete=models.CASCADE, related_name='assigned_delivery')
    delivery_boy = models.ForeignKey(DeliveryBoy, on_delete=models.SET_NULL, null=True)
    assigned_date = models.DateTimeField(auto_now_add=True)
    delivery_status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('picked_up', 'Picked Up'),
        ('in_transit', 'In Transit'),
        ('delivered', 'Delivered'),
        ('failed', 'Failed')
    ], default='pending')
    delivery_notes = models.TextField(blank=True, null=True)
    estimated_delivery_time = models.DateTimeField(null=True, blank=True)
    
    # Payment tracking fields
    payment_processed = models.BooleanField(default=False)
    payment_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    payment_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-assigned_date']

    def __str__(self):
        return f"Order #{self.order.id} - {self.delivery_status}" 