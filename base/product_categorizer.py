import os
import numpy as np
from PIL import Image
import io
import tensorflow as tf
from tensorflow.keras.applications import MobileNetV2
from tensorflow.keras.applications.mobilenet_v2 import preprocess_input
from tensorflow.keras.preprocessing import image
from django.conf import settings
import cv2

# Define your categories based on your Product model
CATEGORIES = ['cricket', 'football', 'badminton', 'table_games']
CATEGORY_TO_INDEX = {cat: idx for idx, cat in enumerate(CATEGORIES)}
INDEX_TO_CATEGORY = {idx: cat for idx, cat in enumerate(CATEGORIES)}

# Path to save model weights if needed
MODEL_DIR = os.path.join(settings.BASE_DIR, 'base', 'ml_models')
os.makedirs(MODEL_DIR, exist_ok=True)

class ProductCategorizer:
    def __init__(self):
        # Load pre-trained MobileNetV2 model (smaller and faster than other models)
        self.base_model = MobileNetV2(weights='imagenet', include_top=True, input_shape=(224, 224, 3))
        
    def preprocess_image(self, img_data):
        """Preprocess image data for model input"""
        try:
            # Convert bytes to image if needed
            if isinstance(img_data, bytes):
                img = Image.open(io.BytesIO(img_data))
            elif isinstance(img_data, str) and os.path.exists(img_data):
                # It's a file path
                img = Image.open(img_data)
            else:
                # Assume it's already a PIL Image
                img = img_data
                
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            # Resize to expected size
            img = img.resize((224, 224))
            
            # Convert to array and preprocess
            img_array = image.img_to_array(img)
            img_array = np.expand_dims(img_array, axis=0)
            return preprocess_input(img_array)
        except Exception as e:
            print(f"Error preprocessing image: {e}")
            return None
    
    def predict_category(self, img_data):
        """
        Use pre-trained model to predict sports equipment category
        """
        try:
            processed_img = self.preprocess_image(img_data)
            if processed_img is None:
                return None
            
            # Get ImageNet predictions
            predictions = self.base_model.predict(processed_img)
            
            # Map ImageNet classes to our sports categories
            # These mappings are based on common ImageNet classes that correspond to sports equipment
            sports_mappings = {
                # Cricket related ImageNet classes - expanded with more specific terms
                'cricket_bat': 'cricket',
                'cricket_ball': 'cricket',
                'jersey': 'cricket',
                'cricket_helmet': 'cricket',
                'sporting_equipment': 'cricket',
                'batsman': 'cricket',
                'wicket': 'cricket',
                'stumps': 'cricket',
                'cricket_glove': 'cricket',
                'cricket_pad': 'cricket',
                'small_ball': 'cricket',  # Added for cricket ball detection
                'red_ball': 'cricket',    # Added for cricket ball detection
                'leather_ball': 'cricket', # Added for cricket ball detection
                'hard_ball': 'cricket',   # Added for cricket ball detection
                
                # Football related classes - refined to be more specific
                'soccer_ball': 'football',
                'football_helmet': 'football',
                'jersey': 'football',
                'soccer_field': 'football',
                'football_field': 'football',
                'goal': 'football',
                'goalkeeper': 'football',
                'soccer_player': 'football',
                'football_player': 'football',
                'cleat': 'football',
                'soccer_cleat': 'football',
                
                # Badminton related classes
                'racket': 'badminton',
                'shuttle_cock': 'badminton',
                'tennis_racket': 'badminton',
                'badminton_racket': 'badminton',
                'badminton_court': 'badminton',
                'badminton_net': 'badminton',
                'badminton_player': 'badminton',
                
                # Table games related classes
                'table': 'table_games',
                'chess_board': 'table_games',
                'carrom_board': 'table_games',
                'pool_table': 'table_games',
                'ping-pong_ball': 'table_games',
                'ping-pong_racket': 'table_games',
                'chess_piece': 'table_games',
                'chess_king': 'table_games',
                'chess_queen': 'table_games',
                'billiard_ball': 'table_games',
                'billiard_table': 'table_games',
                'foosball_table': 'table_games',
                'board_game': 'table_games',
                'playing_card': 'table_games',
                'dice': 'table_games'
            }
            
            # Get top 10 predictions from ImageNet
            top_preds = tf.keras.applications.mobilenet_v2.decode_predictions(predictions, top=10)[0]
            
            # Score each category based on ImageNet predictions
            category_scores = {cat: 0.0 for cat in CATEGORIES}
            
            # Enhanced keywords associated with each category for more robust matching
            category_keywords = {
                'cricket': ['cricket', 'bat', 'wicket', 'stump', 'pad', 'glove', 'helmet', 'red ball', 'small ball', 
                           'leather ball', 'pitch', 'bowler', 'batsman', 'fielder', 'crease', 'innings', 'test match', 
                           'odi', 't20', 'ball', 'willow', 'wooden bat', 'cricket field', 'oval', 'cricket ground', 
                           'cricket stadium', 'cricket gear', 'cricket equipment', 'bails', 'cricket whites'],
                           
                'football': ['football', 'soccer', 'goal', 'boot', 'cleat', 'jersey', 'large ball', 'black and white', 
                            'pitch', 'field', 'goalkeeper', 'striker', 'defender', 'midfielder', 'penalty', 'corner', 
                            'free kick', 'soccer ball', 'football boot', 'soccer boot', 'soccer field', 'football field', 
                            'soccer goal', 'football goal', 'soccer net', 'football net', 'soccer uniform', 'football uniform',
                            'stadium', 'grass field', 'soccer pitch', 'football pitch', 'soccer stadium', 'football stadium'],
                            
                'badminton': ['racket', 'shuttle cock', 'shuttlecock', 'net', 'court', 'birdie', 'white feather', 'smash', 
                             'serve', 'rally', 'backhand', 'forehand', 'singles', 'doubles', 'badminton', 'yellow', 
                             'feather shuttlecock', 'plastic shuttlecock', 'badminton shoes', 'badminton uniform', 
                             'indoor court', 'badminton racket', 'badminton net', 'badminton court', 'badminton player',
                             'racquet', 'badminton racquet', 'indoor sport', 'badminton gear', 'badminton equipment', 'yonex'],
                             
                'table_games': ['table', 'board', 'chess', 'carrom board', 'pool', 'billiard', 'ping-pong', 'indoor', 
                               'piece', 'pawn', 'king', 'queen', 'rook', 'knight', 'bishop', 'cue', 'pocket', 'dice', 
                               'card', 'foosball', 'table tennis', 'ping pong', 'table tennis paddle', 'ping pong paddle', 
                               'table tennis ball', 'ping pong ball', 'chess piece', 'chess board', 'billiard ball', 
                               'billiard table', 'foosball table', 'board game', 'playing card', 'poker chip', 'game board', 
                               'indoor game', 'carrom striker', 'carrom coin', 'snooker table', 'snooker ball', 'cue stick',
                               'checkers', 'domino', 'mahjong', 'poker', 'rummy', 'ludo', 'monopoly']
            }
            
            # Process ImageNet predictions with weighted scoring
            for idx, (_, class_name, score) in enumerate(top_preds):
                class_name = class_name.lower()
                # Apply position-based weighting (higher ranks get more weight)
                position_weight = 1.0 - (idx * 0.05)  # Decreases weight for lower positions
                
                # Direct mapping if available
                if class_name in sports_mappings:
                    mapped_category = sports_mappings[class_name]
                    category_scores[mapped_category] += score * position_weight * 1.2  # Higher weight for direct matches
                
                # Keyword-based mapping with improved weighting
                for category, keywords in category_keywords.items():
                    # Check for exact keyword matches
                    exact_matches = [keyword for keyword in keywords if keyword == class_name]
                    if exact_matches:
                        category_scores[category] += score * position_weight * 1.0
                        continue
                        
                    # Check for partial keyword matches
                    partial_matches = [keyword for keyword in keywords if keyword in class_name]
                    if partial_matches:
                        # Weight by how specific the match is (longer keywords are more specific)
                        specificity = max([len(keyword)/len(class_name) for keyword in partial_matches])
                        category_scores[category] += score * position_weight * 0.8 * specificity
            
            # Enhanced color analysis as additional feature - with improved cricket ball detection
            try:
                if isinstance(img_data, bytes):
                    img = Image.open(io.BytesIO(img_data))
                elif isinstance(img_data, str) and os.path.exists(img_data):
                    img = Image.open(img_data)
                else:
                    img = img_data
                
                img = img.convert('RGB').resize((100, 100))  # Increased resolution for better analysis
                pixels = np.array(img)
                
                # Calculate average color
                avg_color = np.mean(pixels, axis=(0, 1))
                
                # Calculate color histograms for more detailed analysis
                r_hist = np.histogram(pixels[:,:,0], bins=8, range=(0,256))[0] / 10000
                g_hist = np.histogram(pixels[:,:,1], bins=8, range=(0,256))[0] / 10000
                b_hist = np.histogram(pixels[:,:,2], bins=8, range=(0,256))[0] / 10000
                
                # Calculate size and shape features
                # Detect circular objects (balls)
                try:
                    # Convert to grayscale for shape detection
                    gray = np.mean(pixels, axis=2).astype(np.uint8)
                    
                    # Simple circle detection based on color distribution
                    is_small_object = False
                    is_circular = False
                    
                    # Check if the image has a dominant circular shape
                    # This is a simplified approach - for better results use proper circle detection
                    
                    # Check if the object is relatively small in the frame
                    # Get object mask by simple thresholding
                    _, binary = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
                    contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    
                    if contours:
                        largest_contour = max(contours, key=cv2.contourArea)
                        area = cv2.contourArea(largest_contour)
                        perimeter = cv2.arcLength(largest_contour, True)
                        
                        # Circularity measure: 4*pi*area/perimeter^2 (1.0 for perfect circle)
                        if perimeter > 0:
                            circularity = 4 * np.pi * area / (perimeter * perimeter)
                            is_circular = circularity > 0.7  # Threshold for circular objects
                        
                        # Size relative to image
                        relative_size = area / (100 * 100)
                        is_small_object = relative_size < 0.5  # Small objects like cricket balls
                except Exception as shape_error:
                    print(f"Shape analysis error: {shape_error}")
                    is_circular = False
                    is_small_object = False
                
                # Red dominant - likely cricket ball
                if avg_color[0] > 120 and avg_color[0] > avg_color[1] * 1.5 and avg_color[0] > avg_color[2] * 1.5:
                    # Strong boost for cricket if it's red and circular (cricket ball)
                    if is_circular and is_small_object:
                        category_scores['cricket'] += 0.5
                    else:
                        category_scores['cricket'] += 0.25
                
                # Black and white pattern - likely football
                if (r_hist[7] + g_hist[7] + b_hist[7] > 0.2) and (r_hist[0] + g_hist[0] + b_hist[0] > 0.2):
                    if is_circular and not is_small_object:  # Larger circular object
                        category_scores['football'] += 0.4
                    else:
                        category_scores['football'] += 0.2
                
                # Green dominant - likely cricket or football field
                elif avg_color[1] > avg_color[0] and avg_color[1] > avg_color[2]:
                    if avg_color[1] > 120:  # Brighter green
                        category_scores['cricket'] += 0.25
                    else:
                        category_scores['football'] += 0.25
                
                # Brown/wood tones - likely table games
                elif avg_color[0] > 100 and avg_color[1] > 60 and avg_color[2] < 80:
                    category_scores['table_games'] += 0.25
                
                # White/blue dominant - likely badminton
                elif avg_color[2] > avg_color[0] and avg_color[2] > avg_color[1]:
                    category_scores['badminton'] += 0.25
                
                # Check for specific color patterns
                # High green with white lines - football field
                if g_hist[5] + g_hist[6] > 0.3 and r_hist[7] + b_hist[7] > 0.1:
                    category_scores['football'] += 0.2
                
                # Indoor wood colors - table games
                if r_hist[4] + r_hist[5] > 0.3 and g_hist[3] + g_hist[4] > 0.2:
                    category_scores['table_games'] += 0.2
                
                # Blue court colors - badminton
                if b_hist[5] + b_hist[6] > 0.3:
                    category_scores['badminton'] += 0.2
                
                # Cricket-specific: red leather ball detection
                if r_hist[4] + r_hist[5] > 0.3 and g_hist[2] + g_hist[3] < 0.2 and b_hist[2] + b_hist[3] < 0.2:
                    if is_circular and is_small_object:
                        category_scores['cricket'] += 0.4  # Stronger boost for cricket balls
            except Exception as e:
                # If color analysis fails, continue without it
                print(f"Color analysis error: {e}")
                pass
            
            # Apply confidence threshold and boost dominant category
            max_score = max(category_scores.values())
            if max_score > 0:
                # Boost the highest scoring category to increase precision
                predicted_category = max(category_scores, key=category_scores.get)
                category_scores[predicted_category] *= 1.2
            
            # Get the highest scoring category
            predicted_category = max(category_scores, key=category_scores.get)
            confidence = category_scores[predicted_category]
            
            # Normalize confidence score
            total_score = sum(category_scores.values())
            if total_score > 0:
                normalized_scores = {cat: score/total_score for cat, score in category_scores.items()}
            else:
                normalized_scores = category_scores
            
            # Apply confidence threshold for "unknown" category
            if normalized_scores[predicted_category] < 0.4:
                return {
                    'category': 'unknown',
                    'confidence': 0.0,
                    'all_scores': {cat: float(score) for cat, score in normalized_scores.items()}
                }
                
            return {
                'category': predicted_category,
                'confidence': float(normalized_scores[predicted_category]),
                'all_scores': {cat: float(score) for cat, score in normalized_scores.items()}
            }
            
        except Exception as e:
            print(f"Error predicting category: {e}")
            return None

# Create a singleton instance
categorizer = ProductCategorizer()

def predict_image_category(image_data):
    """Utility function to predict category from image data"""
    return categorizer.predict_category(image_data)