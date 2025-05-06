from django.forms import ValidationError
from django.shortcuts import render, redirect
from django.http import HttpResponse,request
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from .models import Customer,Product,Cart,CartItem,Order,OrderItem,DeliveryBoy,OrderAssigned
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST,require_http_methods
from django.contrib.auth.decorators import user_passes_test
from decimal import Decimal
import logging
from django.core.mail import send_mail
from django.db.models import Avg
from django.contrib import messages 
from django.shortcuts import render, redirect
from django.utils.crypto import get_random_string
from django.conf import settings
import datetime
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from django.conf import settings
from django.shortcuts import redirect
import json
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.http import JsonResponse
from django.contrib import messages
import stripe
from django.urls import reverse
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from django.http import FileResponse
import os
from .models import Review
from django.template.loader import get_template, render_to_string
from django.template.exceptions import TemplateDoesNotExist
from .models import ChatMessage
from .chatbot import get_chatbot_response
from django.db.models import Q
import google.generativeai as genai
from .models import Order, DeliveryBoy, OrderAssigned
from django.db.models import Q
from django.utils import timezone
from django.db.models import Count, Q
from django.db.models.functions import Coalesce
from .product_categorizer import predict_image_category  # Add this import

stripe.api_key = settings.STRIPE_SECRET_KEY

from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.cache import never_cache
from .models import Customer, Order, DeliveryBoy, OrderAssigned
import logging

logger = logging.getLogger(__name__)

@never_cache
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        try:
            customer = Customer.objects.get(email=email)

            # Check if user is active before allowing login
            if not customer.is_active:
                return render(request, 'login.html', {
                    'error_message': "Your account has been deactivated. Please contact admin.",
                    'email': email
                })

            if check_password(password, customer.password):
                request.session['customer_id'] = customer.customer_id
                request.session['is_authenticated'] = True
                request.session['customer_email'] = customer.email
                request.session['customer_name'] = customer.name

                if customer.user_type == 'admin':
                    return redirect('admin_dashboard')
                else:
                    return redirect('home')
            else:
                return render(request, 'login.html', {
                    'error_message': "Invalid email or password.",
                    'email': email
                })
        except Customer.DoesNotExist:
            return render(request, 'login.html', {
                'error_message': "Invalid email or password.",
                'email': email
            })
    
    return render(request, 'login.html')


@never_cache
def home(request):
    customer_id = request.session.get('customer_id')
    if customer_id:
        try:
            customer = Customer.objects.get(customer_id=customer_id)
            # Get all products and order them by name
            products = Product.objects.all().order_by('name')
            
            # Get chat users for the current customer
            chat_users = []
            if customer.user_type == 'admin':
                chat_users = Customer.objects.filter(user_type='customer', is_active=True)
            else:
                chat_users = Customer.objects.filter(user_type='admin', is_active=True)
            
            # Get initial messages for the first admin (for customers)
            messages_list = []
            if chat_users.exists():
                messages_list = ChatMessage.objects.filter(
                    (Q(sender=customer) & Q(receiver=chat_users.first())) |
                    (Q(sender=chat_users.first()) & Q(receiver=customer))
                ).order_by('timestamp')
            
            # Get actual unread message count
            total_unread = ChatMessage.objects.filter(
                receiver=customer,
                is_read=False
            ).count()
            
            return render(request, 'home.html', {
                'customer': customer, 
                'products': products,
                'chat_users': chat_users,
                'messages': messages_list,
                'total_unread': total_unread,
                'current_customer': customer
            })
            
        except Customer.DoesNotExist:
            request.session.flush()
            return redirect('login')
    return redirect('login')

@never_cache
def signup_view(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        phone = request.POST['phone']
        address = request.POST['address']

        if password != confirm_password:
            return HttpResponse("Passwords do not match.")

        # Check if the email already exists
        if Customer.objects.filter(email=email).exists():
            return render(request, 'signup.html', {
                'error_message': "Email already exists. Please use a different email address."
            })

        # If email is unique, create the user with phone and address
        hashed_password = make_password(password)
        user = Customer(
            name=name, 
            email=email, 
            password=hashed_password, 
            user_type='customer',
            phone=phone,
            address=address
        )
        user.save()
        return redirect('login')

    return render(request, 'signup.html')

from django.contrib.auth import logout

# views.py
# @never_cache

@never_cache
@require_http_methods(["GET", "POST"])
def custom_logout(request):
    print("Logging out user")
    logout(request)
    request.session.flush()
    print("Session flushed")
    response = redirect('login')
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

@never_cache
def admin_dashboard(request):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('login')
        
    try:
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access.')
            return redirect('login')
            
        # Initialize prediction variables
        predicted_category = None
        prediction_confidence = 0
        
        if request.method == 'POST':
            try:
                name = request.POST.get('product_name')
                description = request.POST.get('product_description')
                price = request.POST.get('product_price')
                category = request.POST.get('product_category')
                image = request.FILES.get('product_image')
                stock = request.POST.get('product_stock')

                # Auto-categorize if image is provided and no category is selected
                if image and (not category or category == ''):
                    # Read image data
                    image_data = image.read()
                    # Reset file pointer for later use
                    image.seek(0)
                    
                    # Predict category
                    prediction = predict_image_category(image_data)
                    if prediction:
                        predicted_category = prediction['category']
                        prediction_confidence = prediction['confidence']
                        
                        # Use prediction if confidence is high enough
                        if prediction_confidence >= 0.5:
                            category = predicted_category
                            messages.success(request, f"Image automatically categorized as '{predicted_category}' with {prediction_confidence:.2f} confidence.")
                        else:
                            # Default to first category if confidence is low
                            category = 'cricket'  # Default category
                            messages.info(request, f"Category prediction confidence was low ({prediction_confidence:.2f}). Using default category.")

                product = Product(
                    name=name,
                    description=description,
                    price=price,
                    category=category,
                    image=image,
                    stock=stock
                )
                product.save()
                messages.success(request, f'Product "{name}" has been added successfully.')
                return redirect('admin_dashboard')
            except Exception as e:
                messages.error(request, f'Error adding product: {str(e)}')
        
        # Get all products to display in admin dashboard
        products = Product.objects.all()
        
        # Get total unread messages for admin
        total_unread = ChatMessage.objects.filter(
            receiver=admin_user,
            is_read=False
        ).count()
        
        # Get chat users (all active customers for admin)
        chat_users = Customer.objects.filter(user_type='customer', is_active=True)
        
        context = {
            'products': products,
            'total_unread': total_unread,
            'chat_users': chat_users,
            'current_customer': admin_user,  # Add current customer (admin) to context
            'predicted_category': predicted_category,
            'prediction_confidence': prediction_confidence
        }
        
        return render(request, 'admin.html', context)
        
    except Customer.DoesNotExist:
        return redirect('login')
    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        messages.error(request, "An error occurred while loading the admin dashboard")
        return redirect('login')
def is_admin(user):
    try:
        customer_id = user.session.get('customer_id')
        customer = Customer.objects.get(customer_id=customer_id)
        return customer.user_type == 'admin'
    except (AttributeError, Customer.DoesNotExist):
        return False

# @user_passes_test(is_admin, login_url='login')
from django.contrib import messages
from django.shortcuts import redirect, render
from .models import Product

from .product_categorizer import predict_image_category
@never_cache
def add_product(request):
    if request.method == 'POST':
        name = request.POST.get('product_name')
        description = request.POST.get('product_description')
        price = request.POST.get('product_price')
        category = request.POST.get('product_category')
        image = request.FILES.get('product_image')
        stock = request.POST.get('product_stock')

        # Validate required fields
        if not all([name, description, price, stock]):
            messages.error(request, 'Please fill in all required fields')
            return render(request, 'admin.html')
            
        # Auto-categorize if image is provided and no category is selected
        predicted_category = None
        prediction_confidence = 0
        
        if image and (not category or category == ''):
            # Read image data
            image_data = image.read()
            # Reset file pointer for later use
            image.seek(0)
            
            # Predict category
            prediction = predict_image_category(image_data)
            if prediction:
                predicted_category = prediction['category']
                prediction_confidence = prediction['confidence']
                
                # Use prediction if confidence is high enough
                if prediction_confidence >= 0.5:
                    category = predicted_category
                    messages.success(request, f"Image automatically categorized as '{predicted_category}' with {prediction_confidence:.2f} confidence.")
                else:
                    # Default to first category if confidence is low
                    category = 'cricket'  # Default category
                    messages.info(request, f"Category prediction confidence was low ({prediction_confidence:.2f}). Using default category.")
        
        # If still no category, return an error
        if not category:
            messages.error(request, 'Please select a category or upload an image for auto-detection')
            return render(request, 'admin.html')

        try:
            product = Product(
                name=name,
                description=description,
                price=price,
                category=category,
                image=image,
                stock=stock
            )
            product.save()
            messages.success(request, f'Product "{name}" has been added successfully.')
            return redirect('admin_dashboard')
        except Exception as e:
            messages.error(request, f'Error adding product: {str(e)}')

    return render(request, 'admin.html')

@login_required
@never_cache
def product_admin(request):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('login')
    try:
        customer = Customer.objects.get(customer_id=customer_id)
        
        # Get search query
        search_query = request.GET.get('search', '')
        
        # Filter products based on search query
        if search_query:
            products = Product.objects.filter(
                Q(name__icontains=search_query) |
                Q(description__icontains=search_query) |
                Q(category__icontains=search_query)
            )
        else:
            products = Product.objects.all()
        
        if not request.session.get('customer_email'):
            request.session['customer_email'] = customer.email
        
        context = {
            'customer': customer, 
            'products': products,
            'search_query': search_query
        }
        
        return render(request, 'product.html', context)
    except Customer.DoesNotExist:
        return redirect('login')

@never_cache
def edit_profile(request):
    if not request.session.get('customer_id'):
        return redirect('login')
    
    customer = Customer.objects.get(customer_id=request.session['customer_id'])
    
    if request.method == 'POST':
        # Validate pincode
        pincode = request.POST.get('pincode')
        if not pincode.isdigit() or len(pincode) != 6:
            messages.error(request, 'Pincode must be exactly 6 digits')
            return redirect('edit_profile')
            
        customer.name = request.POST['name']
        customer.email = request.POST['email']
        customer.phone = request.POST['phone']
        customer.address = request.POST['address']
        customer.pincode = pincode
        
        if request.POST.get('new_password'):
            customer.set_password(request.POST['new_password'])
        
        customer.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('home')
    
    return render(request, 'edit_profile.html', {'customer': customer})

import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Product, Cart, CartItem, Customer
from decimal import Decimal
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

@never_cache
@require_http_methods(["GET", "POST"])
@csrf_exempt  # Remember to remove this after debugging
def cart_view(request):
    logger.info(f"Cart view accessed. Method: {request.method}")
    customer_id = request.session.get('customer_id')
    logger.info(f"Customer ID from session: {customer_id}")

    if not customer_id:
        logger.error("Customer not found in session")
        return JsonResponse({'status': 'error', 'message': 'Customer not found in session'}, status=400)

    try:
        customer = Customer.objects.get(customer_id=customer_id)
        logger.info(f"Customer found: {customer}")
    except Customer.DoesNotExist:
        logger.error(f"Customer with ID {customer_id} not found in database")
        return JsonResponse({'status': 'error', 'message': 'Customer not found in database'}, status=400)

    try:
        cart, created = Cart.objects.get_or_create(user=customer)
        logger.info(f"Cart {'created' if created else 'retrieved'} for customer")
    except Exception as e:
        logger.error(f"Error getting or creating cart: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Error accessing cart'}, status=500)

    if request.method == 'POST':
        product_id = request.POST.get('product_id')
        logger.info(f"Adding product ID {product_id} to cart")

        if not product_id:
            logger.error("Product ID not provided")
            return JsonResponse({'status': 'error', 'message': 'Product ID not provided'}, status=400)

        try:
            product = Product.objects.get(id=product_id)
            logger.info(f"Product found: {product}")
        except Product.DoesNotExist:
            logger.error(f"Product with ID {product_id} not found")
            return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)

        try:
            cart_item, item_created = CartItem.objects.get_or_create(cart=cart, product=product)
            logger.info(f"CartItem {'created' if item_created else 'retrieved'}")
            
            if not item_created:
                cart_item.quantity += 1
            else:
                cart_item.quantity = 1
            
            if cart_item.quantity <= product.stock:
                cart_item.save()
                message = f"{product.name} has been added to your cart."
                status = 'success'
            else:
                message = f"Sorry, we only have {product.stock} of {product.name} in stock."
                status = 'error'
            
            logger.info(f"Cart item saved. Status: {status}")
            
            cart_total = sum(item.product.price * item.quantity for item in cart.items.all())
            tax = Decimal('0.10') * cart_total
            total_with_tax = cart_total + tax
            
            return JsonResponse({
                'status': status,
                'message': message,
                'cart_total': str(cart_total),
                'tax': str(tax),
                'total_with_tax': str(total_with_tax),
                'cart_count': cart.items.count(),
            })
        except Exception as e:
            logger.error(f"Error adding item to cart: {str(e)}")
            return JsonResponse({'status': 'error', 'message': 'Error adding item to cart'}, status=500)
    
    # GET request
    try:
        cart_items = cart.items.all()
        cart_total = sum(item.product.price * item.quantity for item in cart_items)
        tax = Decimal('0.10') * cart_total  # Assuming 10% tax
        total_with_tax = cart_total + tax

        context = {
            'cart_items': cart_items,
            'cart_total': cart_total,
            'tax': tax,
            'total_with_tax': total_with_tax,
            'stripe_publishable_key': settings.STRIPE_PUBLISHABLE_KEY,
        }
        logger.info("Rendering cart template")
        return render(request, 'cart.html', context)
    except Exception as e:
        logger.error(f"Error rendering cart: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Error rendering cart'}, status=500)

@never_cache
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            customer = Customer.objects.get(email=email)
            # Generate password reset token
            token = get_random_string(length=32)
            customer.reset_password_token = token
            customer.reset_password_expires = datetime.datetime.now() + datetime.timedelta(hours=1)
            customer.save()
            
            # Send reset email
            reset_link = f"{request.scheme}://{request.get_host()}/reset-password/{token}/"
            send_mail(
                'Password Reset Request',
                f'Click the following link to reset your password: {reset_link}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            return render(request, 'forgot_password.html', {
                'message': {
                    'type': 'success',
                    'title': 'Success!',
                    'text': 'Password reset link has been sent to your email.'
                }
            })
        except Customer.DoesNotExist:
            return render(request, 'forgot_password.html', {
                'message': {
                    'type': 'error',
                    'title': 'Error',
                    'text': 'No account found with this email address.'
                }
            })
    
    return render(request, 'forgot_password.html')

@never_cache
def reset_password(request, token):
    try:
        customer = Customer.objects.get(
            reset_password_token=token,
            reset_password_expires__gt=datetime.datetime.now()
        )
        
        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            
            if password != confirm_password:
                return render(request, 'reset_password.html', {
                    'message': {
                        'type': 'error',
                        'title': 'Error',
                        'text': 'Passwords do not match.'
                    }
                })
            
            customer.password = make_password(password)
            customer.reset_password_token = None
            customer.reset_password_expires = None
            customer.save()
            
            messages.success(request, 'Password has been reset successfully. Please login with your new password.')
            return redirect('login')
            
        return render(request, 'reset_password.html')
        
    except Customer.DoesNotExist:
        return render(request, 'reset_password.html', {
            'message': {
                'type': 'error',
                'title': 'Error',
                'text': 'Invalid or expired reset link.'
            }
        })\
        
@never_cache
def google_login(request):
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
            }
        },
        scopes=['https://www.googleapis.com/auth/userinfo.email', 
                'https://www.googleapis.com/auth/userinfo.profile',
                'openid']
    )
    
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    request.session['google_auth_state'] = state
    
    return redirect(authorization_url)

@never_cache
def google_callback(request):
    try:
        # Create the flow using the client secrets
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
                }
            },
            scopes=['https://www.googleapis.com/auth/userinfo.email', 
                    'https://www.googleapis.com/auth/userinfo.profile',
                    'openid']
        )
        
        flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
        
        # Use the authorization server's response to fetch the OAuth 2.0 tokens
        authorization_response = request.build_absolute_uri()
        flow.fetch_token(authorization_response=authorization_response)
        
        # Get credentials and create a service
        credentials = flow.credentials
        service = build('oauth2', 'v2', credentials=credentials)
        
        # Get user info
        user_info = service.userinfo().get().execute()
        
        logger.info(f"Google user info: {user_info}")  # Debug log
        
        # Check if user exists
        try:
            customer = Customer.objects.get(email=user_info['email'])
            logger.info(f"Existing customer found: {customer.email}")
        except Customer.DoesNotExist:
            # Create new customer
            customer = Customer.objects.create(
                name=user_info.get('name', ''),
                email=user_info['email'],
                password=make_password(None),  # Set a random password
                # Add any other required fields with default values
                phone='',  # Add default value if this is required
                address=''  # Add default value if this is required
            )
            logger.info(f"New customer created: {customer.email}")
        
        # Set session data
        request.session['customer_id'] = customer.customer_id
        request.session['is_authenticated'] = True
        request.session['customer_email'] = customer.email
        request.session['customer_name'] = customer.name
        
        logger.info(f"Session data set for customer: {customer.customer_id}")
        
        messages.success(request, f'Welcome, {customer.name}!')
        return redirect('home')
        
    except Exception as e:
        logger.error(f"Google login error: {str(e)}")
        messages.error(request, 'Google login failed. Please try again.')
        return redirect('login')
 
@never_cache
def customer_table(request):
    # Add admin check
    customer_id = request.session.get('customer_id')
    try:
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access.')
            return redirect('login')
    except Customer.DoesNotExist:
        return redirect('login')

    customers = Customer.objects.all()
    return render(request, 'customer_table.html', {'customers': customers})

@never_cache
def toggle_user_status(request, user_id):
    # Check if user is admin
    customer_id = request.session.get('customer_id')
    try:
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access.')
            return redirect('login')
    except Customer.DoesNotExist:
        return redirect('login')

    if request.method == 'POST':
        try:
            customer = Customer.objects.get(customer_id=user_id)
            customer.is_active = not customer.is_active  # Toggle the status
            customer.save()
            
            status_text = "activated" if customer.is_active else "deactivated"
            messages.success(request, f'User {customer.name} has been {status_text}.')
        except Customer.DoesNotExist:
            messages.error(request, 'User not found.')
        except Exception as e:
            messages.error(request, f'Error updating user status: {str(e)}')
    
    return redirect('customer_table')

@require_POST
def delete_product(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
        product_name = product.name
        product.delete()
        messages.success(request, f'Product "{product_name}" has been deleted successfully.')
    except Product.DoesNotExist:
        messages.error(request, 'Product not found.')
    return redirect('admin_dashboard')

def edit_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    
    if request.method == 'POST':
        # Handle form submission
        product.name = request.POST.get('product_name')
        product.description = request.POST.get('product_description')
        product.price = request.POST.get('product_price')
        product.category = request.POST.get('product_category')
        product.stock = request.POST.get('product_stock')
        
        if 'product_image' in request.FILES:
            product.image = request.FILES['product_image']
            
        product.save()
        messages.success(request, 'Product updated successfully!')
        return redirect('admin_dashboard')
        
    return render(request, 'edit_product.html', {'product': product})

@csrf_protect
@require_POST
@never_cache
def remove_from_cart(request, item_id):
    logger.info(f"Removing cart item ID: {item_id}")
    
    # Get customer from session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return JsonResponse({'status': 'error', 'message': 'Not authenticated'}, status=401)
    
    try:
        # Get the cart item and verify it belongs to the current user
        cart_item = CartItem.objects.select_related('cart', 'product').get(
            id=item_id,
            cart__user__customer_id=customer_id
        )
        
        # Store product name before deletion
        product_name = cart_item.product.name
        
        # Delete the cart item
        cart_item.delete()
        
        # Add success message
        messages.success(request, f'{product_name} has been removed from your cart.')
        
        return JsonResponse({
            'status': 'success',
            'message': f'{product_name} has been removed from your cart'
        })
        
    except CartItem.DoesNotExist:
        logger.error(f"Cart item {item_id} not found or doesn't belong to user")
        return JsonResponse({
            'status': 'error',
            'message': 'Item not found'
        }, status=404)
        
    except Exception as e:
        logger.error(f"Error removing cart item: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'An error occurred while removing the item'
        }, status=500)

@require_POST
@never_cache
def update_cart_item(request, item_id):
    try:
        cart_item = CartItem.objects.select_related('cart', 'product').get(
            id=item_id,
            cart__user__customer_id=request.session.get('customer_id')
        )
        
        quantity = int(request.POST.get('quantity', 1))
        if quantity > cart_item.product.stock:
            return JsonResponse({
                'status': 'error',
                'message': f'Only {cart_item.product.stock} items available in stock'
            }, status=400)
        
        cart_item.quantity = quantity
        cart_item.save()
        
        # Calculate new totals
        cart = cart_item.cart
        cart_total = sum(item.product.price * item.quantity for item in cart.items.all())
        tax = Decimal('0.10') * cart_total
        total_with_tax = cart_total + tax
        
        return JsonResponse({
            'status': 'success',
            'message': 'Cart updated successfully',
            'cart_total': str(cart_total),
            'tax': str(tax),
            'total_with_tax': str(total_with_tax)
        })
        
    except CartItem.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Cart item not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error updating cart: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Error updating cart'
        }, status=500)

@never_cache
def create_checkout_session(request):
    try:
        customer = Customer.objects.get(customer_id=request.session.get('customer_id'))
        cart = Cart.objects.get(user=customer)
        cart_items = cart.items.all()
        
        # Calculate totals
        cart_total = sum(item.product.price * item.quantity for item in cart_items)
        tax = Decimal('0.10') * cart_total  # 10% tax
        total_with_tax = cart_total + tax
        
        # Convert total to paise (Indian currency's smallest unit)
        amount_in_paise = int(total_with_tax * 100)
        
        # Create line items for Stripe
        line_items = [{
            'price_data': {
                'currency': 'inr',
                'product_data': {
                    'name': item.product.name,
                    'description': item.product.description,
                },
                'unit_amount': int(item.product.price * 100),  # Convert to paise
            },
            'quantity': item.quantity,
        } for item in cart_items]

        # Add tax as a separate line item
        line_items.append({
            'price_data': {
                'currency': 'inr',
                'product_data': {
                    'name': 'Tax (10%)',
                    'description': 'Sales tax',
                },
                'unit_amount': int(tax * 100),  # Convert to paise
            },
            'quantity': 1,
        })

        # Create Stripe checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            customer_email=customer.email,
            success_url=request.build_absolute_uri(reverse('payment_success')) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.build_absolute_uri(reverse('payment_cancelled')),
            metadata={
                'customer_id': customer.customer_id,
                'total_amount': str(total_with_tax)
            }
        )
        
        return JsonResponse({'sessionId': checkout_session.id})
        
    except Exception as e:
        logger.error(f"Error creating checkout session: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@never_cache
def payment_success(request):
    try:
        session_id = request.GET.get('session_id')
        if (session_id):
            session = stripe.checkout.Session.retrieve(session_id)
            customer_id = session.metadata.get('customer_id')
            total_amount = float(session.metadata.get('total_amount'))
            
            customer = Customer.objects.get(customer_id=customer_id)
            cart = Cart.objects.get(user=customer)
            
            # Create order
            order = Order.objects.create(
                customer=customer,
                total_amount=total_amount,
                status='paid',
                payment_id=session.payment_intent
            )
            
            # Create order items
            for cart_item in cart.items.all():
                OrderItem.objects.create(
                    order=order,
                    product=cart_item.product,
                    product_name=cart_item.product.name,
                    quantity=cart_item.quantity,
                    price=cart_item.product.price
                )
            
            # Get all approved delivery boys
            delivery_boys = DeliveryBoy.objects.filter(
                status='approved'
            ).select_related('user')

            # Find best delivery boy using existing function
            best_boy = get_best_delivery_boy(order, delivery_boys)
            
            if best_boy:
                # Create assignment
                OrderAssigned.objects.create(
                    order=order,
                    delivery_boy=best_boy,
                    delivery_status='pending',
                    assigned_date=timezone.now()
                )
                
                # Update delivery boy status
                best_boy.is_available = False
                best_boy.total_deliveries += 1
                best_boy.save()
                
                # Update order status
                order.status = 'assigned'
                order.save()
                
                messages.success(request, 'Payment successful! Your order has been placed and assigned to a delivery partner.')
            else:
                messages.warning(request, 'Payment successful! Your order has been placed. We will assign a delivery partner soon.')
            
            # Clear cart
            cart.items.all().delete()
            
            return render(request, 'payment_success.html', {
                'order': order,
                'has_delivery_boy': bool(best_boy)
            })
            
    except Exception as e:
        logger.error(f"Error processing successful payment: {str(e)}")
        messages.error(request, 'Error processing payment confirmation.')
        return redirect('cart_view')

@never_cache
def payment_cancelled(request):
    messages.warning(request, 'Payment was cancelled.')
    return render(request, 'payment_cancelled.html')

@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )

        if event['type'] == 'checkout.session.paid':
            session = event['data']['object']
            customer_id = session['metadata']['customer_id']
            
            # Handle successful payment (e.g., update order status, send confirmation email)
            logger.info(f"Payment completed for customer {customer_id}")

    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return HttpResponse(status=400)

    return HttpResponse(status=200)

@never_cache
def purchase_history(request):
    logger.info("Accessing purchase history view")
    customer_id = request.session.get('customer_id')
    
    if not customer_id:
        logger.warning("No customer_id in session")
        messages.error(request, 'Please login to view purchase history')
        return redirect('login')
    
    try:
        customer = Customer.objects.get(customer_id=customer_id)
        orders = Order.objects.filter(customer=customer)\
            .order_by('-order_date')\
            .prefetch_related('items', 'items__product')
        
        logger.info(f"Found {orders.count()} orders for customer {customer.name}")
        
        # Process orders and items
        processed_orders = []
        for order in orders:
            processed_items = []
            for item in order.items.all():
                # Create a dictionary with item data including review status
                item_data = {
                    'id': item.id,
                    'product': item.product,
                    'product_name': item.product_name,
                    'quantity': item.quantity,
                    'price': item.price,
                    'product_exists': bool(item.product),
                    'has_review': False
                }
                
                # Check for review if product exists
                if item.product:
                    item_data['has_review'] = Review.objects.filter(
                        product=item.product,
                        customer=customer
                    ).exists()
                
                processed_items.append(item_data)
            
            # Add processed items to order
            order.processed_items = processed_items
            processed_orders.append(order)
        
        context = {
            'orders': processed_orders,
            'customer': customer,
            'page_title': 'Purchase History'
        }
        
        return render(request, 'purchase_his.html', context)
                
    except Customer.DoesNotExist:
        logger.error(f"Customer with ID {customer_id} not found")
        messages.error(request, 'Customer account not found')
        return redirect('login')
    except Exception as e:
        logger.error(f"Error in purchase history: {str(e)}")
        messages.error(request, "Error retrieving purchase history")
        return redirect('home')

@never_cache
def download_invoice(request, order_id):
    try:
        # Get the order and verify it belongs to the current user
        order = Order.objects.select_related('customer').get(
            id=order_id,
            customer__customer_id=request.session.get('customer_id')
        )
        
        # Verify order is paid or delivered (using lowercase status values)
        if order.status not in ['paid', 'delivered']:
            logger.warning(f"Attempted to download invoice for non-paid order {order_id} with status {order.status}")
            messages.error(request, "Invoice is only available for paid orders")
            return redirect('purchase_history')
            
        # Create the PDF buffer
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        
        # Add logging for debugging
        logger.info(f"Generating invoice for order {order_id}")
        
        # Header
        p.setFont("Helvetica-Bold", 24)
        p.drawString(50, 750, "INVOICE")
        
        # Order details
        p.setFont("Helvetica", 12)
        p.drawString(50, 720, f"Order #: {order.id}")
        p.drawString(50, 700, f"Date: {order.order_date.strftime('%B %d, %Y %I:%M %p')}")
        p.drawString(50, 680, f"Customer: {order.customer.name}")
        
        # Items table
        y = 620
        p.drawString(50, y, "Item")
        p.drawString(300, y, "Quantity")
        p.drawString(400, y, "Price")
        p.drawString(500, y, "Total")
        
        y -= 20
        p.line(50, y, 550, y)
        y -= 20
        
        # Add items
        for item in order.items.all():
            p.drawString(50, y, item.product_name[:40])
            p.drawString(300, y, str(item.quantity))
            p.drawString(400, y, f"₹{item.price}")
            total = item.price * item.quantity
            p.drawString(500, y, f"₹{total}")
            y -= 20
        
        # Total
        y -= 20
        p.line(50, y, 550, y)
        y -= 20
        p.setFont("Helvetica-Bold", 12)
        p.drawString(400, y, "Total:")
        p.drawString(500, y, f"₹{order.total_amount}")
        
        # Footer
        p.setFont("Helvetica", 10)
        p.drawString(50, 50, "Thank you for your purchase!")
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        logger.info(f"Successfully generated invoice for order {order_id}")
        return FileResponse(buffer, as_attachment=True, filename=f'invoice_{order.id}.pdf')
    
    except Order.DoesNotExist:
        logger.error(f"Order {order_id} not found or unauthorized access")
        messages.error(request, "Order not found or unauthorized access")
        return redirect('purchase_history')
    except Exception as e:
        logger.error(f"Error generating invoice for order {order_id}: {str(e)}")
        messages.error(request, f"Error generating invoice: {str(e)}")
        return redirect('purchase_history')

@never_cache
def admin_order_history(request):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('login')
        
    try:
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access.')
            return redirect('login')
            
        # Get all orders grouped by date, excluding cancelled orders from delivery status checks
        orders = Order.objects.all().order_by('-order_date')
        
        # Group orders by date
        orders_by_date = {}
        for order in orders:
            date = order.order_date.date()
            if date not in orders_by_date:
                orders_by_date[date] = []
            # Add order to the date group
            orders_by_date[date].append(order)
            
        # Check for failed deliveries (excluding cancelled orders)
        failed_deliveries = OrderAssigned.objects.filter(
            delivery_status='failed',
            order__status__in=['paid', 'assigned', 'picked_up', 'in_transit']
        ).count()
        
        if failed_deliveries > 0:
            messages.warning(request, f'There are {failed_deliveries} failed deliveries that need to be reassigned.')
            
        context = {
            'orders_by_date': orders_by_date,
            'stripe_publishable_key': settings.STRIPE_PUBLISHABLE_KEY,
        }
        
        return render(request, 'admin_order_history.html', context)
        
    except Customer.DoesNotExist:
        return redirect('login')
    except Exception as e:
        logger.error(f"Error in admin order history: {str(e)}")
        messages.error(request, "An error occurred while loading the order history")
        return redirect('admin_dashboard')

@never_cache
def product_detail(request, product_id):
    # Added by Copilot: Product detail view with reviews
    try:
        product = Product.objects.get(id=product_id)
        reviews = product.reviews.select_related('customer').all()
        
        # Check if the user has purchased this product
        customer_id = request.session.get('customer_id')
        has_purchased = False
        can_review = False
        
        if customer_id:
            customer = Customer.objects.get(customer_id=customer_id)
            # Check if user has purchased this product
            has_purchased = OrderItem.objects.filter(
                order__customer=customer,
                product_name=product.name,
                order__status='paid'
            ).exists()
            
            # Check if user hasn't already reviewed
            has_reviewed = Review.objects.filter(
                product=product,
                customer=customer
            ).exists()
            
            can_review = has_purchased and not has_reviewed

        # Calculate average rating
        avg_rating = reviews.aggregate(Avg('rating'))['rating__avg'] or 0
        
        context = {
            'product': product,
            'reviews': reviews,
            'can_review': can_review,
            'average_rating': round(avg_rating, 1),
            'has_purchased': has_purchased
        }
        return render(request, 'product_detail.html', context)
    except Product.DoesNotExist:
        messages.error(request, 'Product not found')
        return redirect('home')

@never_cache
@require_POST
def add_review(request, product_id):
    print("kjldsf")
    if not request.session.get('customer_id'):
        messages.error(request, 'Please login to add a review')
        return redirect('purchase_history')
    
    try:
        product = Product.objects.get(id=product_id)
        customer = Customer.objects.get(customer_id=request.session['customer_id'])
        
        # Verify purchase
        has_purchased = OrderItem.objects.filter(
            order__customer=customer,
            product=product,
            order__status='paid'
        ).exists()
        
        if not has_purchased:
            messages.error(request, 'You must purchase this product to review it')
            return redirect('purchase_history')
        
        # Check if already reviewed
        if Review.objects.filter(product=product, customer=customer).exists():
            messages.error(request, 'You have already reviewed this product')
            return redirect('purchase_history')
        
        # Get form data
        rating = request.POST.get('rating')
        comment = request.POST.get('comment', '').strip()
        
        # Validate input
        if not rating or not comment:
            messages.error(request, 'Please provide both rating and comment')
            return redirect('purchase_history')
        
        try:
            rating = int(rating)
            if not (1 <= rating <= 5):
                raise ValueError('Invalid rating range')
        except ValueError:
            messages.error(request, 'Please provide a valid rating between 1 and 5')
            return redirect('purchase_history')
        
        # Create review
        Review.objects.create(
            product=product,
            customer=customer,
            rating=rating,
            comment=comment,
            purchase_verified=True
        )
        
        messages.success(request, 'Thank you for your review!')
        return redirect('purchase_history')
        
    except Product.DoesNotExist:
        messages.error(request, 'Product not found')
        return redirect('purchase_history')
    except Customer.DoesNotExist:
        messages.error(request, 'Please login to add a review')
        return redirect('login')
    except Exception as e:
        logger.error(f"Error adding review: {str(e)}")
        messages.error(request, 'An error occurred while adding your review')
        return redirect('purchase_history')
    
from django.http import JsonResponse
from django.db.models import Q
from .models import ChatMessage, Customer
from django.contrib.auth.decorators import login_required
from django.utils import timezone

@never_cache
def chat_view(request):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        messages.error(request, 'Please login to access chat')
        return redirect('login')
    
    try:
        current_customer = Customer.objects.get(customer_id=customer_id)
        
        # Get all users who have chatted with the current customer
        chat_users = Customer.objects.filter(
            Q(customer_id__in=ChatMessage.objects.filter(receiver=current_customer).values('sender__customer_id')) |
            Q(customer_id__in=ChatMessage.objects.filter(sender=current_customer).values('receiver__customer_id'))
        ).distinct()

        # If this is an admin, show all customers
        if current_customer.user_type == 'admin':
            customers = Customer.objects.filter(user_type='customer', is_active=True)
            chat_users = chat_users.union(customers)
        else:
            # If this is a customer, make sure they can chat with admin
            admins = Customer.objects.filter(user_type='admin', is_active=True)
            chat_users = chat_users.union(admins)

        # Get unread counts for each user
        unread_counts = {}
        for user in chat_users:
            unread_counts[user.customer_id] = ChatMessage.objects.filter(
                sender=user,
                receiver=current_customer,
                is_read=False
            ).count()

        # Get current chat user and messages
        current_chat_user_id = request.GET.get('user')
        current_chat_user = None
        messages_list = []
        
        if current_chat_user_id:
            try:
                current_chat_user = Customer.objects.get(customer_id=current_chat_user_id)
                messages_list = ChatMessage.objects.filter(
                    (Q(sender=current_customer) & Q(receiver=current_chat_user)) |
                    (Q(sender=current_chat_user) & Q(receiver=current_customer))
                ).order_by('timestamp')
                
                # Mark messages as read for current chat
                messages_list.filter(receiver=current_customer, is_read=False).update(is_read=True)
                # Update unread count for current chat user
                unread_counts[current_chat_user_id] = 0
            except Customer.DoesNotExist:
                pass

        context = {
            'chat_users': chat_users,
            'current_chat_user': current_chat_user,
            'messages': messages_list,
            'unread_counts': unread_counts,
            'current_customer': current_customer,
        }
        
        return render(request, 'chat.html', context)
                
    except Customer.DoesNotExist:
        messages.error(request, 'Customer account not found')
        return redirect('login')
    except Exception as e:
        logger.error(f"Error in chat view: {str(e)}")
        messages.error(request, "Error accessing chat")
        return redirect('home')

@never_cache
def get_new_messages(request, user_id):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return JsonResponse({'messages': [], 'unread_counts': {}})
    
    try:
        current_customer = Customer.objects.get(customer_id=customer_id)
        other_user = Customer.objects.get(customer_id=user_id)
        
        # Get recent messages
        recent_messages = ChatMessage.objects.filter(
            (Q(sender=current_customer) & Q(receiver=other_user)) |
            (Q(sender=other_user) & Q(receiver=current_customer))
        ).order_by('-timestamp')[:50]
        
        # Mark messages as read for current chat
        ChatMessage.objects.filter(
            sender=other_user,
            receiver=current_customer,
            is_read=False
        ).update(is_read=True)
        
        # Get updated unread counts for all users
        chat_users = Customer.objects.filter(
            Q(customer_id__in=ChatMessage.objects.filter(receiver=current_customer).values('sender__customer_id')) |
            Q(customer_id__in=ChatMessage.objects.filter(sender=current_customer).values('receiver__customer_id'))
        ).distinct()
        
        unread_counts = {}
        for user in chat_users:
            unread_counts[str(user.customer_id)] = ChatMessage.objects.filter(
                sender=user,
                receiver=current_customer,
                is_read=False
            ).count()
        
        messages_data = [{
            'message': msg.message,
            'timestamp': msg.timestamp.strftime("%b %d, %Y %I:%M %p"),
            'is_sender': msg.sender == current_customer
        } for msg in reversed(recent_messages)]
        
        return JsonResponse({
            'messages': messages_data,
            'unread_counts': unread_counts
        })
        
    except Customer.DoesNotExist:
        return JsonResponse({'messages': [], 'unread_counts': {}})

@never_cache
def product_list(request):
    # Check if user is admin
    customer_id = request.session.get('customer_id')
    try:
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access.')
            return redirect('login')
    except Customer.DoesNotExist:
        return redirect('login')

    # Get all products
    products = Product.objects.all()
    
    # Handle search
    search_query = request.GET.get('search', '')
    if search_query:
        products = products.filter(
            Q(name__icontains=search_query) |
            Q(category__icontains=search_query)
        )
    
    # Get total unread messages for admin
    total_unread = ChatMessage.objects.filter(
        receiver=admin_user,
        is_read=False
    ).count()

    context = {
        'products': products,
        'total_unread': total_unread
    }
    return render(request, 'product_list.html', context)

@require_POST
@never_cache
def send_chat_message(request):
    if not request.session.get('customer_id'):
        return JsonResponse({'status': 'error', 'message': 'Please login to send messages'})
    
    try:
        current_customer = Customer.objects.get(customer_id=request.session['customer_id'])
        message_text = request.POST.get('message', '').strip()
        receiver_id = request.POST.get('receiver_id')
        
        if not message_text:
            return JsonResponse({'status': 'error', 'message': 'Message cannot be empty'})
            
        if not receiver_id:
            return JsonResponse({'status': 'error', 'message': 'No recipient selected'})
            
        try:
            receiver = Customer.objects.get(customer_id=receiver_id)
        except Customer.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Recipient not found'})
        
        # Create and save the message
        message = ChatMessage.objects.create(
            sender=current_customer,
            receiver=receiver,
            message=message_text
        )
        
        return JsonResponse({
            'status': 'success',
            'message': message_text,
            'timestamp': message.timestamp.strftime("%b %d, %Y %I:%M %p")
        })
        
    except Exception as e:
        logger.error(f"Error sending chat message: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'An error occurred while sending the message'
        })

@require_POST
def chatbot_message(request):
    try:
        message = request.POST.get('message', '').strip()
        if not message:
            return JsonResponse({
                'status': 'error',
                'message': 'Message cannot be empty'
            })
        
        response = get_chatbot_response(message)
        logger.info(f"Chatbot response status: {response['status']}")
        
        return JsonResponse(response)
        
    except Exception as e:
        logger.error(f"Chatbot view error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'An error occurred while processing your request'
        }, status=500)

@never_cache
def search_products(request):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        search_query = request.GET.get('search', '')
        try:
            if search_query:
                products = Product.objects.filter(
                    Q(name__icontains=search_query) |
                    Q(description__icontains=search_query) |
                    Q(category__icontains=search_query)
                ).order_by('name')
            else:
                products = Product.objects.all().order_by('name')

            html = render_to_string(
                template_name='product_list_partial.html',
                context={'products': products},
                request=request
            )
            
            return JsonResponse({
                'status': 'success',
                'html': html,
                'count': products.count()
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })
    return JsonResponse({'status': 'error', 'message': 'Invalid request'})

@require_http_methods(["GET"])
def filter_products(request):
    try:
        category = request.GET.get('category', 'all')
        search_query = request.GET.get('search', '')
        
        # Start with all products
        products = Product.objects.all()
        
        # Apply category filter if not 'all'
        if category != 'all':
            products = products.filter(category__iexact=category)
            
        # Apply search filter if exists
        if search_query:
            products = products.filter(
                Q(name__icontains=search_query) |
                Q(description__icontains=search_query)
            )
        
        # Render only the products section
        html = render_to_string('product_list_partial.html', {
            'products': products
        }, request=request)
        
        return JsonResponse({
            'status': 'success',
            'html': html
        })
        
    except Exception as e:
        logger.error(f"Error filtering products: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@csrf_exempt
def gemini_chat(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            message = data.get('message', '').lower()
            customer_id = request.session.get('customer_id')
            
            if not message:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Message cannot be empty'
                })

            # Check for profile-related queries
            profile_keywords = ['my profile', 'my details', 'my information', 'who am i', 'my name']
            if any(keyword in message for keyword in profile_keywords):
                if customer_id:
                    try:
                        customer = Customer.objects.get(customer_id=customer_id)
                        return JsonResponse({
                            'status': 'success',
                            'profile_data': {
                                'name': customer.name,
                                'email': customer.email,
                                'phone': customer.phone or 'Not provided',
                                'address': customer.address or 'Not provided'
                            }
                        })
                    except Customer.DoesNotExist:
                        pass
                return JsonResponse({
                    'status': 'success',
                    'response': "I'm sorry, but you need to be logged in to view your profile information."
                })

            # Check for order-related queries
            elif 'my order' in message or 'my orders' in message:
                if customer_id:
                    try:
                        customer = Customer.objects.get(customer_id=customer_id)
                        orders = Order.objects.filter(customer=customer).order_by('-order_date')[:5]
                        if orders:
                            response = "Here are your recent orders:\n"
                            for order in orders:
                                response += f"Order #{order.id}: {order.status}, Total: ${order.total_amount}, Date: {order.order_date.strftime('%B %d, %Y %I:%M %p')}\n"
                        else:
                            response = "You don't have any orders yet. Would you like to browse our products?"
                        return JsonResponse({
                            'status': 'success',
                            'response': response
                        })
                    except Customer.DoesNotExist:
                        pass
                return JsonResponse({
                    'status': 'success',
                    'response': "Please log in to view your order information."
                })

            # Check for cart-related queries
            elif 'my cart' in message or 'shopping cart' in message:
                if customer_id:
                    try:
                        customer = Customer.objects.get(customer_id=customer_id)
                        cart = Cart.objects.filter(user=customer).first()
                        if cart:
                            cart_items = CartItem.objects.filter(cart=cart)
                            if cart_items:
                                response = "Here's what's in your cart:\n"
                                total = 0
                                for item in cart_items:
                                    subtotal = item.quantity * item.product.price
                                    total += subtotal
                                    response += f"- {item.quantity}x {item.product.name}: ${subtotal}\n"
                                response += f"\nTotal: ${total}"
                            else:
                                response = "Your cart is empty. Would you like to see our products?"
                        else:
                            response = "Your cart is empty. Would you like to see our products?"
                        return JsonResponse({
                            'status': 'success',
                            'response': response
                        })
                    except Customer.DoesNotExist:
                        pass
                return JsonResponse({
                    'status': 'success',
                    'response': "Please log in to view your cart information."
                })

            # Default product search behavior
            else:
                products = []
                if any(word in message for word in ['product', 'price', 'stock', 'cricket', 'football', 'badminton', 'table games']):
                    products = Product.objects.filter(
                        Q(name__icontains=message) |
                        Q(description__icontains=message) |
                        Q(category__icontains=message)
                    )[:5]

                product_info = ""
                if products:
                    product_info = "Here are some relevant products:\n"
                    for product in products:
                        product_info += f"- {product.name}: ${product.price}, Category: {product.category}, Stock: {product.stock}\n"
                        avg_rating = product.reviews.aggregate(Avg('rating'))['rating__avg']
                        if avg_rating:
                            product_info += f"  Average Rating: {avg_rating:.1f}/5\n"

                context = f"""You are a helpful shopping assistant for a sports equipment store. 
                {product_info if product_info else 'No specific products found for this query.'}
                
                Available product categories: {', '.join(dict(Product.CATEGORY_CHOICES).values())}
                
                Please provide a helpful response to the customer's query: {message}"""

                genai.configure(api_key='AIzaSyDRG6Ape9UUYl270adHwxWKbK2wTXlQhQU')
                model = genai.GenerativeModel('gemini-pro')
                response = model.generate_content(context)
                
                return JsonResponse({
                    'status': 'success',
                    'response': response.text,
                    'products_found': bool(products)
                })
            
        except Exception as e:
            logger.error(f"Gemini chat error: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=405)

@never_cache
def delivery_dashboard(request):
    if not request.session.get('is_delivery_boy'):
        messages.error(request, 'Please login as a delivery partner.')
        return redirect('delivery_login')
        
    try:
        customer = Customer.objects.get(customer_id=request.session.get('customer_id'))
        delivery_boy = DeliveryBoy.objects.get(user=customer)
        
        if delivery_boy.status != 'approved':
            messages.error(request, 'Your account is not approved yet.')
            return redirect('delivery_login')
            
        # Get assigned orders (excluding cancelled orders)
        assigned_orders = Order.objects.filter(
            assigned_delivery__delivery_boy=delivery_boy,
            assigned_delivery__delivery_status__in=['pending', 'picked_up', 'in_transit'],
            status__in=['assigned', 'picked_up', 'in_transit']  # Only include active orders
        )
        
        # Get cancelled orders
        cancelled_orders = Order.objects.filter(
            assigned_delivery__delivery_boy=delivery_boy,
            status='cancelled'
        )
        
        # Get completed deliveries
        completed_deliveries = OrderAssigned.objects.filter(
            delivery_boy=delivery_boy,
            delivery_status='delivered'
        ).order_by('-assigned_date')
        
        # Calculate total deliveries based on actual completed deliveries
        total_deliveries = completed_deliveries.count()
        
        # Update the delivery boy's total_deliveries to match actual completed deliveries
        if delivery_boy.total_deliveries != total_deliveries:
            delivery_boy.total_deliveries = total_deliveries
            delivery_boy.save()
        
        # Calculate total amount received (₹50 per delivery) only for paid deliveries
        total_amount_received = OrderAssigned.objects.filter(
            delivery_boy=delivery_boy,
            delivery_status='delivered',
            payment_processed=True
        ).count() * 50
        
        context = {
            'delivery_boy': delivery_boy,
            'assigned_orders': assigned_orders,
            'cancelled_orders': cancelled_orders,
            'completed_deliveries': completed_deliveries,
            'total_amount_received': total_amount_received
        }
        return render(request, 'delivery_dashboard.html', context)
    except (Customer.DoesNotExist, DeliveryBoy.DoesNotExist):
        messages.error(request, 'Delivery account not found.')
        return redirect('delivery_login')



@require_POST
def update_availability(request):
    available = request.POST.get('available') == 'true'
    try:
        delivery_boy = DeliveryBoy.objects.get(user=request.user)
        delivery_boy.is_available = available
        delivery_boy.save()
        return JsonResponse({'status': 'success'})
    except DeliveryBoy.DoesNotExist:
        return JsonResponse({'status': 'error'}, status=404)

def delivery_register(request):
    if request.method == 'POST':
        try:
            # Get form data
            name = request.POST.get('name')
            email = request.POST.get('email')
            phone = request.POST.get('phone')
            address = request.POST.get('address')
            pincode = request.POST.get('pincode')
            vehicle_number = request.POST.get('vehicle_number')
            license_number = request.POST.get('license_number')
            password = request.POST.get('password')
            
            # Validate pincode
            if not pincode.isdigit() or len(pincode) != 6:
                messages.error(request, 'Pincode must be exactly 6 digits')
                return redirect('delivery_register')
            
            # Create customer
            customer = Customer.objects.create(
                name=name,
                email=email,
                phone=phone,
                address=address,
                user_type='delivery_boy'
            )
            customer.set_password(password)
            customer.save()
            
            # Create delivery boy with validated pincode
            delivery_boy = DeliveryBoy.objects.create(
                user=customer,
                vehicle_number=vehicle_number,
                license_number=license_number,
                pincode=pincode
            )
            
            messages.success(request, 'Registration successful! Please wait for admin approval.')
            return redirect('delivery_login')
            
        except Exception as e:
            messages.error(request, f'Registration failed: {str(e)}')
            return redirect('delivery_register')
            
    return render(request, 'delivery_register.html')

@require_POST
def approve_delivery_boy(request, delivery_boy_id):
    try:
        delivery_boy = DeliveryBoy.objects.get(id=delivery_boy_id)
        action = request.POST.get('action')
        
        if action == 'approve':
            delivery_boy.status = 'approved'
        elif action == 'reject':
            delivery_boy.status = 'rejected'
        
        delivery_boy.save()
        
        # Send email notification to delivery boy
        subject = f'Your delivery partner application has been {action}d'
        message = f'Hello {delivery_boy.user.name},\n\nYour application to be a delivery partner has been {action}d.'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [delivery_boy.user.email]
        
        try:
            send_mail(subject, message, from_email, recipient_list)
        except Exception as e:
            # Log the error but don't stop the process
            print(f"Error sending email: {str(e)}")
        
        return JsonResponse({'status': 'success'})
    except DeliveryBoy.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Delivery boy not found'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@never_cache
def delivery_applications(request):
    if not request.session.get('customer_id'):
        return redirect('login')
        
    try:
        admin_user = Customer.objects.get(customer_id=request.session.get('customer_id'))
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access')
            return redirect('home')
            
        pending_applications = DeliveryBoy.objects.filter(status='pending').select_related('user')
        approved_applications = DeliveryBoy.objects.filter(status='approved').select_related('user')
        
        context = {
            'pending_applications': pending_applications,
            'approved_applications': approved_applications
        }
        return render(request, 'manage_application.html', context)
    except Customer.DoesNotExist:
        return redirect('login')
    except Exception as e:
        messages.error(request, f'Error loading applications: {str(e)}')
        return redirect('admin_dashboard')

@never_cache
def delivery_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            customer = Customer.objects.get(email=email)
            
            # Check if the customer has a delivery boy profile
            try:
                delivery_boy = DeliveryBoy.objects.get(user=customer)
            except DeliveryBoy.DoesNotExist:
                messages.error(request, 'No delivery account found for this email.')
                return redirect('delivery_login')
            
            # Verify password using check_password method
            if check_password(password, customer.password):
                # Check delivery boy status
                if delivery_boy.status == 'pending':
                    messages.error(request, 'Your account is pending approval.')
                    return redirect('delivery_login')
                elif delivery_boy.status == 'rejected':
                    messages.error(request, 'Your account has been rejected.')
                    return redirect('delivery_login')
                
                # Set session data
                request.session['customer_id'] = customer.customer_id
                request.session['is_authenticated'] = True
                request.session['is_delivery_boy'] = True
                request.session['customer_email'] = customer.email
                request.session['customer_name'] = customer.name
                
                messages.success(request, f'Welcome back, {customer.name}!')
                return redirect('delivery_dashboard')
            else:
                messages.error(request, 'Invalid email or password.')
        except Customer.DoesNotExist:
            messages.error(request, 'Invalid email or password.')
    
    return render(request, 'delivery_login.html')

@never_cache
def delivery_profile(request):
    if not request.session.get('is_delivery_boy'):
        messages.error(request, 'Please login as a delivery partner.')
        return redirect('delivery_login')
        
    try:
        customer = Customer.objects.get(customer_id=request.session.get('customer_id'))
        delivery_boy = DeliveryBoy.objects.get(user=customer)
        
        context = {
            'delivery_boy': delivery_boy,
            'customer': customer
        }
        return render(request, 'delivery_profile.html', context)
    except (Customer.DoesNotExist, DeliveryBoy.DoesNotExist):
        messages.error(request, 'Profile not found.')
        return redirect('delivery_login')

@never_cache
def delivery_profile_edit(request):
    if not request.session.get('is_delivery_boy'):
        messages.error(request, 'Please login as a delivery partner.')
        return redirect('delivery_login')
        
    try:
        customer = Customer.objects.get(customer_id=request.session.get('customer_id'))
        delivery_boy = DeliveryBoy.objects.get(user=customer)
        
        if request.method == 'POST':
            # Update customer info
            customer.name = request.POST.get('name')
            customer.phone = request.POST.get('phone')
            customer.address = request.POST.get('address')
            
            # Update delivery boy info
            delivery_boy.vehicle_number = request.POST.get('vehicle_number')
            delivery_boy.license_number = request.POST.get('license_number')
            delivery_boy.pincode = request.POST.get('pincode')
            
            # Handle password change
            new_password = request.POST.get('new_password')
            if new_password:
                customer.password = make_password(new_password)
            
            customer.save()
            delivery_boy.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('delivery_profile')
            
        context = {
            'delivery_boy': delivery_boy,
            'customer': customer
        }
        return render(request, 'delivery_profile_edit.html', context)
    except (Customer.DoesNotExist, DeliveryBoy.DoesNotExist):
        messages.error(request, 'Profile not found.')
        return redirect('delivery_login')

def get_best_delivery_boy(order, delivery_boys):
    """
    Get the best delivery boy based on total deliveries.
    Returns the delivery boy with matching pincode, least total deliveries and who is available.
    """
    # First filter by matching pincode
    matching_boys = [boy for boy in delivery_boys if boy.pincode == order.customer.pincode]
    
    if not matching_boys:
        return None
        
    # Then filter available boys
    available_boys = [boy for boy in matching_boys if boy.is_available]
    
    if not available_boys:
        return None
        
    # Sort available boys by total deliveries (ascending)
    # Sort available boys by total deliveries (ascending)
    available_boys.sort(key=lambda x: x.total_deliveries)
    
    # Return the boy with least deliveries
    return available_boys[0] if available_boys else None

@never_cache
def work_assign(request):
    # Check if user is logged in
    customer_id = request.session.get('customer_id')
    if not customer_id:
        messages.error(request, 'Please login to access this page')
        return redirect('login')
    
    try:
        # Get the user and verify they are an admin
        customer = Customer.objects.get(customer_id=customer_id)
        
        # Strict admin check
        if customer.user_type != 'admin':
            messages.error(request, 'Access denied. Admin privileges required.')
            return redirect('home')
        
        # Get all approved delivery boys with their current assignments
        delivery_boys = DeliveryBoy.objects.filter(
            status='approved'
        ).select_related(
            'user'
        ).annotate(
            current_assignments=Count(
                'orderassigned',
                filter=Q(orderassigned__delivery_status__in=['pending', 'picked_up', 'in_transit'])
            )
        )
        
        # Mark delivery boys as available if they have no current assignments
        for boy in delivery_boys:
            boy.is_available = boy.current_assignments == 0
            boy.save()

        # Get failed orders
        failed_orders = Order.objects.filter(
            Q(status='failed') |  
            Q(assigned_delivery__delivery_status='failed')
        ).select_related('customer').prefetch_related('items')

        # Get new orders that need assignment
        new_orders = Order.objects.filter(
            status='paid'
        ).exclude(
            id__in=OrderAssigned.objects.values('order_id')
        ).select_related('customer').prefetch_related('items')

        # Get list of failed order IDs
        failed_order_ids = list(OrderAssigned.objects.filter(
            delivery_status='failed'
        ).values_list('order_id', flat=True))
        
        # Get currently assigned orders
        assigned_orders = OrderAssigned.objects.filter(
            delivery_status__in=['pending', 'picked_up', 'in_transit']
        ).select_related(
            'order',
            'order__customer',
            'delivery_boy',
            'delivery_boy__user'
        ).order_by('-assigned_date')

        # Get delivered orders
        delivered_orders = OrderAssigned.objects.filter(
            delivery_status='delivered'
        ).select_related(
            'order',
            'order__customer',
            'delivery_boy',
            'delivery_boy__user'
        ).order_by('-assigned_date')
        
        # For each order, find matching delivery boys and best delivery boy
        for order in new_orders:
            # Filter delivery boys by pincode
            matching_boys = [boy for boy in delivery_boys if boy.pincode == order.customer.pincode]
            order.matching_delivery_boys = matching_boys
            order.available_delivery_boys = [boy for boy in matching_boys if boy.is_available]
            
            # Find best delivery boy (available, matching pincode, least deliveries)
            available_matching_boys = [boy for boy in matching_boys if boy.is_available]
            if available_matching_boys:
                order.best_delivery_boy = min(available_matching_boys, key=lambda x: x.total_deliveries)
            else:
                order.best_delivery_boy = None
        
        # Do the same for failed orders
        for order in failed_orders:
            matching_boys = [boy for boy in delivery_boys if boy.pincode == order.customer.pincode]
            order.matching_delivery_boys = matching_boys
            order.available_delivery_boys = [boy for boy in matching_boys if boy.is_available]
            
            available_matching_boys = [boy for boy in matching_boys if boy.is_available]
            if available_matching_boys:
                order.best_delivery_boy = min(available_matching_boys, key=lambda x: x.total_deliveries)
            else:
                order.best_delivery_boy = None
        
        context = {
            'failed_orders': failed_orders,
            'new_orders': new_orders,
            'delivery_boys': delivery_boys,
            'assigned_orders': assigned_orders,
            'delivered_orders': delivered_orders,
            'is_admin': True,
            'current_customer': customer,
            'failed_order_ids': failed_order_ids
        }
        
        return render(request, 'Work_assign.html', context)
        
    except Customer.DoesNotExist:
        messages.error(request, 'User account not found')
        return redirect('login')
    except Exception as e:
        logger.error(f"Error in work assign view: {str(e)}")
        messages.error(request, 'An error occurred while loading the page')
        return redirect('admin_dashboard')

@csrf_exempt
def assign_delivery_boy(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
        
    # Check if user is admin
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return JsonResponse({'status': 'error', 'message': 'Please login first'})
        
    try:
        # Verify admin access
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            return JsonResponse({'status': 'error', 'message': 'Unauthorized access'})
            
        order_id = request.POST.get('order_id')
        delivery_boy_id = request.POST.get('delivery_boy_id')
        
        if not order_id or not delivery_boy_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Missing required parameters'
            })
            
        # Get the order and delivery boy
        order = Order.objects.get(id=order_id)
        delivery_boy = DeliveryBoy.objects.get(id=delivery_boy_id)
        
        # Verify pincode match
        if order.customer.pincode != delivery_boy.pincode:
            return JsonResponse({
                'status': 'error',
                'message': 'Delivery partner pincode does not match order location'
            })
            
        # Verify delivery boy is available
        if not delivery_boy.is_available:
            return JsonResponse({
                'status': 'error',
                'message': 'Selected delivery partner is not available'
            })
        
        # Check if this is a reassignment (previous failed delivery)
        previous_assignment = OrderAssigned.objects.filter(
            order=order,
            delivery_status='failed'
        ).first()
        
        if previous_assignment:
            # Delete the previous failed assignment
            previous_assignment.delete()
        
        # Create new assignment
        assignment = OrderAssigned.objects.create(
            order=order,
            delivery_boy=delivery_boy,
            delivery_status='pending',
            assigned_date=timezone.now()
        )
        
        # Update delivery boy availability and stats
        delivery_boy.is_available = False
        delivery_boy.total_deliveries += 1
        delivery_boy.save()
        
        # Update order status
        order.status = 'assigned'
        order.save()
        
        return JsonResponse({
            'status': 'success',
            'message': f'Order #{order_id} assigned to {delivery_boy.user.name}'
        })
        
    except Customer.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'User not found'
        })
    except Order.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Order not found'
        })
    except DeliveryBoy.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Delivery boy not found'
        })
    except Exception as e:
        logger.error(f"Error assigning delivery boy: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@never_cache
def view_assigned_history(request):
    # Check if delivery boy is logged in
    customer_id = request.session.get('customer_id')
    if not customer_id:
        messages.error(request, 'Please login first')
        return redirect('delivery_login')
        
    try:
        # Get the delivery boy's details
        customer = Customer.objects.get(customer_id=customer_id)
        delivery_boy = DeliveryBoy.objects.get(user=customer)
        
        # Get all orders assigned to this delivery boy
        assigned_orders = OrderAssigned.objects.filter(
            delivery_boy=delivery_boy
        ).select_related(
            'order',
            'order__customer'
        ).prefetch_related(
            'order__items'
        ).order_by('-assigned_date')
        
        context = {
            'delivery_boy': delivery_boy,
            'assigned_orders': assigned_orders,
            'customer': customer
        }
        
        return render(request, 'view_assigned_History.html', context)
        
    except Customer.DoesNotExist:
        messages.error(request, 'Customer account not found')
        return redirect('delivery_login')
    except DeliveryBoy.DoesNotExist:
        messages.error(request, 'Delivery boy account not found')
        return redirect('delivery_login')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('delivery_login')

@never_cache
def assign_deliveries(request):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('login')
        
    try:
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access.')
            return redirect('login')
        
        # Get pending orders that need assignment
        pending_orders = Order.objects.filter(status='paid').select_related('customer')
        
        # Get all available delivery boys
        delivery_boys = DeliveryBoy.objects.filter(is_available=True).select_related('user')
        
        # Get assigned orders
        assigned_orders = OrderAssigned.objects.filter(
            delivery_status__in=['pending', 'picked', 'delivered']
        ).select_related('order', 'delivery_boy', 'order__customer', 'delivery_boy__user')
        
        context = {
            'pending_orders': pending_orders,
            'delivery_boys': delivery_boys,
            'assigned_orders': assigned_orders,
            'current_customer': admin_user
        }
        
        return render(request, 'Work_assign.html', context)
        
    except Customer.DoesNotExist:
        return redirect('login')
    except Exception as e:
        logger.error(f"Error in assign deliveries page: {str(e)}")
        messages.error(request, "An error occurred while loading the assign deliveries page")
        return redirect('admin_dashboard')
    
@require_POST
def update_delivery_status(request):
    try:
        order_id = request.POST.get('order_id')
        new_status = request.POST.get('status')
        
        order = Order.objects.get(id=order_id)
        order_assignment = OrderAssigned.objects.get(order=order)
        delivery_boy = order_assignment.delivery_boy
        
        # Update OrderAssigned status
        order_assignment.delivery_status = new_status
        order_assignment.save()
        
        # Update Order status and delivery boy availability based on delivery status
        if new_status == 'pending':
            order.status = 'assigned'
        elif new_status == 'picked_up':
            order.status = 'picked_up'
        elif new_status == 'in_transit':
            order.status = 'in_transit'
        elif new_status == 'delivered':
            order.status = 'delivered'
            # Make delivery boy available again after successful delivery
            delivery_boy.is_available = True
            delivery_boy.save()
        elif new_status == 'failed':
            # When delivery fails, set order status to 'failed'
            order.status = 'failed'
            # Make delivery boy available again
            delivery_boy.is_available = True
            # Decrement total deliveries since this one failed
            delivery_boy.total_deliveries = max(0, delivery_boy.total_deliveries - 1)
            delivery_boy.save()
        
        order.save()
        
        return JsonResponse({
            'status': 'success',
            'message': f'Order status updated to {new_status}'
        })
    except Order.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Order not found'
        }, status=404)
    except OrderAssigned.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Order assignment not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error updating delivery status: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@require_POST
def delete_delivery_boy(request, delivery_boy_id):
    try:
        delivery_boy = DeliveryBoy.objects.get(id=delivery_boy_id)
        
        # Delete the associated user account
        user = delivery_boy.user
        
        # Delete the delivery boy record
        delivery_boy.delete()
        
        # Delete the user account
        user.delete()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Application deleted successfully'
        })
    except DeliveryBoy.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Delivery boy not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@require_http_methods(["POST"])
@never_cache
def add_to_cart(request):
    logger.info("Add to cart endpoint accessed")
    
    # Get customer from session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        logger.error("Customer not found in session")
        return JsonResponse({'status': 'error', 'message': 'Please login to add items to cart'}, status=401)
    
    try:
        # Get the product ID from POST data
        product_id = request.POST.get('product_id')
        if not product_id:
            return JsonResponse({'status': 'error', 'message': 'Product ID not provided'}, status=400)
        
        # Get the customer and product
        customer = Customer.objects.get(customer_id=customer_id)
        product = Product.objects.get(id=product_id)
        
        # Get or create cart for the customer
        cart, _ = Cart.objects.get_or_create(user=customer)
        
        # Get or create cart item
        cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)
        
        # If item already exists, increment quantity
        if not created:
            cart_item.quantity += 1
        else:
            cart_item.quantity = 1
            
        # Check stock availability
        if cart_item.quantity <= product.stock:
            cart_item.save()
            message = f"{product.name} has been added to your cart."
            status = 'success'
        else:
            message = f"Sorry, we only have {product.stock} of {product.name} in stock."
            status = 'error'
            
        # Calculate cart totals
        cart_total = sum(item.product.price * item.quantity for item in cart.items.all())
        tax = Decimal('0.10') * cart_total
        total_with_tax = cart_total + tax
        
        return JsonResponse({
            'status': status,
            'message': message,
            'cart_total': str(cart_total),
            'tax': str(tax),
            'total_with_tax': str(total_with_tax),
            'cart_count': cart.items.count()
        })
        
    except Customer.DoesNotExist:
        logger.error(f"Customer with ID {customer_id} not found")
        return JsonResponse({'status': 'error', 'message': 'Customer not found'}, status=404)
    except Product.DoesNotExist:
        logger.error(f"Product with ID {product_id} not found")
        return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)
    except Exception as e:
        logger.error(f"Error adding to cart: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'An error occurred while adding to cart'}, status=500)
  
@csrf_exempt
def predict_category_ajax(request):
    if request.method == 'POST' and request.FILES.get('image'):
        image = request.FILES['image']
        image_data = image.read()
        
        # Predict category
        prediction = predict_image_category(image_data)
        
        if prediction:
            return JsonResponse({
                'success': True,
                'category': prediction['category'],
                'confidence': prediction['confidence'],
                'all_scores': prediction['all_scores']
            })
        else:
            return JsonResponse({'success': False, 'message': 'Could not predict category'})
    
    return JsonResponse({'success': False, 'message': 'Invalid request'})

@require_POST
def create_delivery_payment_intent(request):
    try:
        data = json.loads(request.body)
        order_id = data.get('order_id')
        
        # Verify the order exists and is eligible for payment
        order = get_object_or_404(Order, id=order_id)
        order_assignment = get_object_or_404(OrderAssigned, order=order)
        
        # Check if payment is already processed
        if order_assignment.payment_processed:
            return JsonResponse({'error': 'Payment has already been processed for this delivery'})
        
        # Create a payment intent for ₹50 (5000 paise)
        payment_intent = stripe.PaymentIntent.create(
            amount=5000,  # Amount in paise (₹50)
            currency='inr',
            metadata={
                'order_id': order_id,
                'delivery_boy_id': order_assignment.delivery_boy.id,
            },
            description=f"Delivery payment for Order #{order_id}"
        )
        
        return JsonResponse({
            'clientSecret': payment_intent.client_secret
        })
        
    except Exception as e:
        logger.error(f"Error creating payment intent: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@never_cache
def process_delivery_payment(request):
    try:
        order_id = request.GET.get('order_id')
        if not order_id:
            messages.error(request, "Order ID is missing")
            return redirect('admin_order_history')
            
        # Get the order and its assigned delivery
        order = Order.objects.get(id=order_id)
        order_assignment = OrderAssigned.objects.get(order=order)
        
        # Mark the payment as processed
        order_assignment.payment_processed = True
        order_assignment.payment_date = timezone.now()
        order_assignment.save()
        
        # Update the success message to include the delivery boy's name
        delivery_boy_name = order_assignment.delivery_boy.user.name
        messages.success(request, f"Payment of ₹50 successfully processed for {delivery_boy_name} for delivery of Order #{order_id}")
        
        return redirect('admin_order_history')
    except Exception as e:
        logger.error(f"Error processing delivery payment: {str(e)}")
        messages.error(request, f"Error processing payment: {str(e)}")
        return redirect('admin_order_history')

@require_POST
@never_cache
def cancel_order(request, order_id):
    try:
        # Get the order and verify it belongs to the current user
        order = Order.objects.get(
            id=order_id,
            customer__customer_id=request.session.get('customer_id')
        )
        
        # Check if order can be cancelled (not delivered)
        if order.assigned_delivery and order.assigned_delivery.delivery_status == 'delivered':
            messages.error(request, 'Cannot cancel an order that has been delivered')
            return redirect('purchase_history')
            
        # Update order status to cancelled
        order.status = 'cancelled'
        order.save()
        
        # If there's an assigned delivery, update delivery boy status
        if order.assigned_delivery:
            delivery_boy = order.assigned_delivery.delivery_boy
            if delivery_boy:
                delivery_boy.is_available = True
                delivery_boy.save()
        
        messages.success(request, f'Order #{order_id} has been cancelled successfully')
        return redirect(f"{reverse('purchase_history')}?cancelled={order_id}&amount={order.total_amount}")
        
    except Order.DoesNotExist:
        messages.error(request, 'Order not found or unauthorized access')
        return redirect('purchase_history')
    except Exception as e:
        logger.error(f"Error cancelling order: {str(e)}")
        messages.error(request, 'An error occurred while cancelling the order')
        return redirect('purchase_history')