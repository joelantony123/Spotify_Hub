from django.forms import ValidationError
from django.shortcuts import render, redirect
from django.http import HttpResponse,request
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from .models import Customer,Product,Cart,CartItem,Order,OrderItem
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
from django.views.decorators.csrf import csrf_protect
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
from django.template.loader import get_template
from django.template.exceptions import TemplateDoesNotExist

stripe.api_key = settings.STRIPE_SECRET_KEY

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
    if request.method == 'POST':
        try:
            name = request.POST.get('product_name')
            description = request.POST.get('product_description')
            price = request.POST.get('product_price')
            category = request.POST.get('product_category')
            image = request.FILES.get('product_image')
            stock = request.POST.get('product_stock')

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
    return render(request, 'admin.html', {'products': products})

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
            
            customer = Customer.objects.get(customer_id=customer_id)
            cart = Cart.objects.get(user=customer)
            
            # Calculate total amount
            total_amount = sum(item.quantity * item.product.price for item in cart.items.all())
            
            # Create order with correct customer field
            order = Order.objects.create(
                customer=customer,  # Changed from user to customer
                total_amount=total_amount,
                status='completed',
                payment_id=session.payment_intent
            )
            
            # Create order items
            for cart_item in cart.items.all():
                OrderItem.objects.create(
                    order=order,
                    product=cart_item.product,  # Add this line
                    product_name=cart_item.product.name,
                    quantity=cart_item.quantity,
                    price=cart_item.product.price
                )
            
            # Clear cart
            cart.items.all().delete()
            
            messages.success(request, 'Payment successful! Your order has been placed.')
            return render(request, 'payment_success.html')
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

        if event['type'] == 'checkout.session.completed':
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
        # Get the order and verify it belongs to the current customer
        customer_id = request.session.get('customer_id')
        order = Order.objects.get(id=order_id, customer__customer_id=customer_id)
        
        # Create a file-like buffer to receive PDF data
        buffer = BytesIO()
        
        # Create the PDF object, using the buffer as its "file."
        p = canvas.Canvas(buffer, pagesize=letter)
        
        # Draw things on the PDF
        # Header
        p.setFont("Helvetica-Bold", 24)
        p.drawString(50, 750, "Invoice")
        
        # Company info
        p.setFont("Helvetica", 12)
        p.drawString(50, 720, "Sports Hub")
        p.drawString(50, 705, "123 Sports Street")
        p.drawString(50, 690, "Phone: (123) 456-7890")
        
        # Customer info
        p.drawString(50, 650, f"Bill To:")
        p.drawString(50, 635, f"Name: {order.customer.name}")
        p.drawString(50, 620, f"Email: {order.customer.email}")
        p.drawString(50, 605, f"Address: {order.customer.address}")
        
        # Order info
        p.drawString(50, 575, f"Order ID: #{order.id}")
        p.drawString(50, 560, f"Order Date: {order.order_date.strftime('%B %d, %Y')}")
        p.drawString(50, 545, f"Payment ID: {order.payment_id}")
        
        # Table header
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, 500, "Item")
        p.drawString(300, 500, "Quantity")
        p.drawString(400, 500, "Price")
        p.drawString(500, 500, "Total")
        
        # Table content
        y = 480
        p.setFont("Helvetica", 12)
        for item in order.items.all():
            p.drawString(50, y, item.product_name)
            p.drawString(300, y, str(item.quantity))
            p.drawString(400, y, f"Rs.{item.price}")
            item_total = item.price * Decimal(str(item.quantity))
            p.drawString(500, y, f"Rs.{item_total}")
            y -= 20
        
        # Calculate totals using Decimal
        subtotal = order.total_amount
        tax_rate = Decimal('0.10')
        tax_amount = subtotal * tax_rate
        total = subtotal + tax_amount
        
        # Draw totals
        p.line(50, y-10, 550, y-10)
        p.setFont("Helvetica-Bold", 12)
        p.drawString(400, y-30, "Subtotal:")
        p.drawString(500, y-30, f"Rs.{subtotal:.2f}")
        p.drawString(400, y-50, "Tax (10%):")
        p.drawString(500, y-50, f"Rs.{tax_amount:.2f}")
        p.drawString(400, y-70, "Total:")
        p.drawString(500, y-70, f"Rs.{total:.2f}")
        
        # Footer
        p.setFont("Helvetica", 10)
        p.drawString(50, 50, "Thank you for your purchase!")
        
        # Close the PDF object cleanly
        p.showPage()
        p.save()
        
        # FileResponse sets the Content-Disposition header so that browsers
        # present the option to save the file.
        buffer.seek(0)
        return FileResponse(buffer, as_attachment=True, filename=f'invoice_{order.id}.pdf')
    
    except Order.DoesNotExist:
        messages.error(request, "Order not found or unauthorized access")
        return redirect('purchase_history')
    except Exception as e:
        logger.error(f"Error generating invoice: {str(e)}")
        messages.error(request, "Error generating invoice")
        return redirect('purchase_history')

@never_cache
def admin_order_history(request):
    # Check if user is admin
    customer_id = request.session.get('customer_id')
    try:
        admin_user = Customer.objects.get(customer_id=customer_id)
        if admin_user.user_type != 'admin':
            messages.error(request, 'Unauthorized access.')
            return redirect('login')
    except Customer.DoesNotExist:
        return redirect('login')

    # Get all orders with related customer information
    orders = Order.objects.select_related('customer').prefetch_related('items').order_by('-order_date')

    # Group orders by date for better organization
    orders_by_date = {}
    for order in orders:
        date = order.order_date.date()
        if date not in orders_by_date:
            orders_by_date[date] = []
        orders_by_date[date].append(order)

    context = {
        'orders_by_date': orders_by_date,
    }
    return render(request, 'admin_order_history.html', context)

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
                order__status='completed'
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
            order__status='completed'
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

        # Get current chat user from query params
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
                
                # Mark messages as read
                messages_list.filter(receiver=current_customer, is_read=False).update(is_read=True)
            except Customer.DoesNotExist:
                pass

        # Handle new message submission
        if request.method == 'POST' and current_chat_user:
            message_text = request.POST.get('message')
            if message_text:
                message = ChatMessage.objects.create(
                    sender=current_customer,
                    receiver=current_chat_user,
                    message=message_text
                )
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'success',
                        'message': message_text,
                        'timestamp': message.timestamp.strftime("%b %d, %Y %H:%M")
                    })

        # Get unread message counts
        unread_counts = {}
        for user in chat_users:
            unread_counts[user.customer_id] = ChatMessage.objects.filter(
                sender=user,
                receiver=current_customer,
                is_read=False
            ).count()

        # Calculate total unread messages for navbar badge
        total_unread = sum(unread_counts.values())

        context = {
            'chat_users': chat_users,
            'current_chat_user': current_chat_user,
            'messages': messages_list,
            'unread_counts': unread_counts,
            'total_unread': total_unread,
            'current_customer': current_customer,  # Add this for the template
        }
        
        logger.info(f"Chat view loaded for customer {current_customer.name}")
        logger.info(f"Number of chat users: {chat_users.count()}")
        
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
        return JsonResponse({'messages': []})
    
    try:
        current_customer = Customer.objects.get(customer_id=customer_id)
        other_user = Customer.objects.get(customer_id=user_id)
        
        # Get unread messages from the other user
        new_messages = ChatMessage.objects.filter(
            sender=other_user,
            receiver=current_customer,
            is_read=False
        ).order_by('timestamp')
        
        # Mark messages as read
        new_messages.update(is_read=True)
        
        # Format messages for JSON response
        messages_data = [{
            'message': msg.message,
            'timestamp': msg.timestamp.strftime("%b %d, %Y %H:%M"),
            'is_sender': False
        } for msg in new_messages]
        
        return JsonResponse({'messages': messages_data})
    except Customer.DoesNotExist:
        return JsonResponse({'messages': []})