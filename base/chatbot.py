import google.generativeai as genai
from django.conf import settings
import os
from dotenv import load_dotenv
import logging

logger = logging.getLogger('base')
load_dotenv()

def initialize_gemini():
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment variables")
        
        genai.configure(api_key=api_key)
        return genai.GenerativeModel('gemini-pro')
    except Exception as e:
        logger.error(f"Error configuring Gemini: {str(e)}")
        return None

model = initialize_gemini()

# Create a context about your website
SYSTEM_CONTEXT = """
You are a helpful customer service chatbot for Sports Hub, an online sports equipment store. 
Key information about the website:

- We sell various sports equipment including cricket, football, basketball, and other sports gear
- Customers can browse products by category
- We offer secure payment processing through Stripe
- Customers can track their order history
- We have a customer support system through chat
- Users can leave reviews for products they've purchased
- We offer both customer and admin interfaces
- Products can be added to cart and purchased online
- We have a return and refund policy
- We ship across India

Please help customers with:
- Product information and recommendations
- Order status and tracking
- Payment and shipping questions
- Return and refund policies
- Account-related issues
- General sports equipment advice

Always be polite, professional, and helpful. If you don't know something specific, direct them to customer service.
"""

def get_chatbot_response(user_message):
    try:
        if not model:
            return {
                'status': 'error',
                'message': 'Chatbot is not properly configured. Please contact support.'
            }
            
        # Combine system context with user message
        prompt = f"{SYSTEM_CONTEXT}\n\nCustomer: {user_message}\nChatbot:"
        
        # Generate response with timeout
        response = model.generate_content(prompt)
        
        if not response or not response.text:
            return {
                'status': 'error',
                'message': 'Sorry, I could not generate a response. Please try again.'
            }
        
        return {
            'status': 'success',
            'message': response.text
        }
        
    except Exception as e:
        logger.error(f"Chatbot error: {str(e)}")
        return {
            'status': 'error',
            'message': 'Sorry, I encountered an error. Please try again later.'
        }