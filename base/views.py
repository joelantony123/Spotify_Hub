from django.forms import ValidationError
from django.shortcuts import render, redirect
from django.http import HttpResponse,request
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from .models import Customer,Product,Cart,CartItem
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST,require_http_methods
from django.contrib.auth.decorators import user_passes_test
from decimal import Decimal
import logging
from django.core.mail import send_mail
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
# views.py

@never_cache
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        try:
            customer = Customer.objects.get(email=email)

            if check_password(password, customer.password):
                request.session['customer_id'] = customer.customer_id
                request.session['is_authenticated'] = True  # Add this line

                if customer.user_type == 'admin':
                    return redirect('admin_dashboard')
                else:
                    return redirect('home')
            else:
                return render(request, 'login.html', {
                    'error_message': "Invalid email or password.",
                    'email': email  # Preserve the email input
                })
        except Customer.DoesNotExist:
            return render(request, 'login.html', {
                'error_message': "Invalid email or password.",
                'email': email  # Preserve the email input
            })
    
    # If it's a GET request or any other method, just render the login page
    return render(request, 'login.html')


@never_cache
def home(request):
    customer_id = request.session.get('customer_id')
    if customer_id:
        try:
            customer = Customer.objects.get(customer_id=customer_id)
            products = Product.objects.all()
            
            # Debug logging
            logger.info(f"Customer authenticated: {customer.email}")
            logger.info(f"Number of products: {products.count()}")
            
            return render(request, 'home.html', {
                'customer': customer, 
                'products': products
            })
        except Customer.DoesNotExist:
            logger.error(f"Customer ID {customer_id} not found in database")
            request.session.flush()
            return redirect('login')
    else:
        logger.info("No customer_id in session")
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

def admin_dashboard(request):
    return render(request,'admin.html')

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

@never_cache
def add_product(request):
    if request.method == 'POST':
        name = request.POST.get('product_name')
        description = request.POST.get('product_description')
        price = request.POST.get('product_price')
        category = request.POST.get('product_category')
        image = request.FILES.get('product_image')
        stock = request.POST.get('product_stock')

        try:
            product = Product(
                name=name,
                description=description,
                price=price,
                category=category,
                image=image,
                stock=stock
            )
            product.full_clean()  # This will raise a ValidationError if any field is invalid
            product.save()
            messages.success(request, f'Product "{name}" has been added successfully.')
            return redirect('admin_dashboard')
        except ValidationError as e:
            messages.error(request, f'Validation error: {e}')
        except Exception as e:
            messages.error(request, f'An error occurred while adding the product: {str(e)}')
            print(f"Exception details: {e}")  # This will print the full exception details

    return render(request, 'admin.html')

@login_required
@never_cache
def product_admin(request):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('login')
    try:
        customer = Customer.objects.get(customer_id=customer_id)
        products = Product.objects.all()
        
        if not request.session.get('customer_email'):
            request.session['customer_email'] = customer.email
        
        return render(request, 'product.html', {'customer': customer, 'products': products})
    except Customer.DoesNotExist:
        return redirect('login')

@never_cache
def edit_profile(request):
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('login')

    try:
        customer = Customer.objects.get(customer_id=customer_id)
    except Customer.DoesNotExist:
        messages.error(request, "Customer not found.")
        return redirect('home')

    if request.method == 'POST':
        # Handle form submission
        customer.name = request.POST.get('name')
        customer.email = request.POST.get('email')
        customer.phone = request.POST.get('phone')
        customer.address = request.POST.get('address')

        try:
            customer.save()
            messages.success(request, "Profile updated successfully.")
            return redirect('home')  # or wherever you want to redirect after successful update
        except Exception as e:
            messages.error(request, f"An error occurred while updating your profile: {str(e)}")

    # If it's a GET request or if there was an error in POST, render the form with existing data
    context = {
        'customer': customer
    }
    return render(request, 'edit_profile.html', context)

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
    # Check if user is admin (you might want to add proper authentication)
    customer_id = request.session.get('customer_id')
    try:
        customer = Customer.objects.get(customer_id=customer_id)
        if customer.user_type != 'admin':
            return redirect('login')
    except Customer.DoesNotExist:
        return redirect('login')

    customers = Customer.objects.all()
    return render(request, 'customer_table.html', {'customers': customers})

from django.contrib import messages
from django.shortcuts import redirect

def toggle_user_status(request, user_id):
    if request.method == 'POST':
        try:
            user = User.objects.get(id=user_id)
            user.is_active = not user.is_active
            user.save()
            status = "activated" if user.is_active else "deactivated"
            messages.success(request, f"User {user.email} has been {status}")
        except User.DoesNotExist:
            messages.error(request, "User not found")
    return redirect('customer_table')