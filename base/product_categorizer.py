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
                img = Image.open(img_data)
            else:
                img = img_data
                
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Store original size for aspect ratio calculations
            original_size = img.size
            
            # Resize while maintaining aspect ratio
            if original_size[0] > original_size[1]:
                new_width = 224
                new_height = int(224 * original_size[1] / original_size[0])
            else:
                new_height = 224
                new_width = int(224 * original_size[0] / original_size[1])
            
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # Create new image with padding to get to 224x224
            new_img = Image.new('RGB', (224, 224), (255, 255, 255))
            paste_x = (224 - new_width) // 2
            paste_y = (224 - new_height) // 2
            new_img.paste(img, (paste_x, paste_y))
            
            # Convert to array and preprocess
            img_array = image.img_to_array(new_img)
            img_array = np.expand_dims(img_array, axis=0)
            return preprocess_input(img_array), new_img
        except Exception as e:
            print(f"Error preprocessing image: {e}")
            return None, None
    
    def predict_category(self, img_data):
        """
        Use pre-trained model to predict sports equipment category
        """
        try:
            processed_img, pil_img = self.preprocess_image(img_data)
            if processed_img is None or pil_img is None:
                return None
            
            # Get ImageNet predictions
            predictions = self.base_model.predict(processed_img)
            
            # Map ImageNet classes to our sports categories
            # These mappings are based on common ImageNet classes that correspond to sports equipment
            sports_mappings = {
                # Cricket related classes
                'cricket_bat': 'cricket',
                'cricket_ball': 'cricket',
                'cricket_helmet': 'cricket',
                'cricket_glove': 'cricket',
                'cricket_pad': 'cricket',
                'cricket_stump': 'cricket',
                'cricket_wicket': 'cricket',
                'cricket_gear': 'cricket',
                'cricket_equipment': 'cricket',
                'cricket_protection': 'cricket',
                'batting_helmet': 'cricket',
                'protective_helmet': 'cricket',
                'sports_helmet': 'cricket',
                'face_guard': 'cricket',
                'helmet_grill': 'cricket',
                
                # Football related classes
                'soccer_ball': 'football',
                'football': 'football',
                'soccer_boot': 'football',
                'football_boot': 'football',
                'soccer_shoe': 'football',
                'football_shoe': 'football',
                'soccer_cleat': 'football',
                'football_cleat': 'football',
                'soccer_goal': 'football',
                'football_goal': 'football',
                'soccer_net': 'football',
                'football_net': 'football',
                'soccer_glove': 'football',
                'goalkeeper_glove': 'football',
                'shin_guard': 'football',
                'soccer_uniform': 'football',
                'football_uniform': 'football',
                
                # Badminton related classes
                'badminton_racket': 'badminton',
                'badminton_racquet': 'badminton',
                'shuttlecock': 'badminton',
                'shuttle_cock': 'badminton',
                'badminton_net': 'badminton',
                'badminton_court': 'badminton',
                'badminton_shoe': 'badminton',
                'badminton_gear': 'badminton',
                'badminton_equipment': 'badminton',
                'feather_shuttlecock': 'badminton',
                'plastic_shuttlecock': 'badminton',
                'badminton_string': 'badminton',
                'badminton_grip': 'badminton',
                
                # Table games related classes
                'chess_board': 'table_games',
                'chess_piece': 'table_games',
                'chess_set': 'table_games',
                'carrom_board': 'table_games',
                'carrom_striker': 'table_games',
                'carrom_coin': 'table_games',
                'table_tennis': 'table_games',
                'ping_pong': 'table_games',
                'ping_pong_paddle': 'table_games',
                'table_tennis_paddle': 'table_games',
                'ping_pong_ball': 'table_games',
                'table_tennis_ball': 'table_games',
                'billiard_table': 'table_games',
                'pool_table': 'table_games',
                'snooker_table': 'table_games',
                'cue_stick': 'table_games',
                'billiard_ball': 'table_games',
                'pool_ball': 'table_games',
                'snooker_ball': 'table_games',
                'board_game': 'table_games',
                'playing_card': 'table_games',
                'game_board': 'table_games'
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
                           'cricket stadium', 'cricket gear', 'cricket equipment', 'bails', 'cricket whites',
                           'protective gear', 'face guard', 'visor', 'head protection', 'batting helmet', 'grill',
                           'neck guard', 'impact protection', 'cricket protection', 'cricket helmet', 'sports helmet',
                           'protective helmet', 'helmet grill', 'helmet visor', 'cricket protective', 'cricket safety',
                           'batting protection', 'head gear', 'protective headwear', 'cricket headgear', 'cricket mask',
                           'face protection', 'cricket face guard', 'cricket visor', 'cricket head protection',
                           'cricket protective gear', 'cricket safety equipment', 'cricket protective equipment'],
                           
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
            
            # After shape detection, add specific feature detection for each category
            try:
                # Convert image to grayscale for shape detection
                gray = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2GRAY)
                edges = cv2.Canny(gray, 50, 150)
                contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                
                if contours:
                    largest_contour = max(contours, key=cv2.contourArea)
                    x, y, w, h = cv2.boundingRect(largest_contour)
                    aspect_ratio = float(w)/h
                    area = cv2.contourArea(largest_contour)
                    perimeter = cv2.arcLength(largest_contour, True)
                    
                    # Calculate shape features
                    circularity = 4 * np.pi * area / (perimeter * perimeter) if perimeter > 0 else 0
                    relative_size = area / (pil_img.size[0] * pil_img.size[1])
                    
                    # Enhanced helmet detection
                    # 1. Check for red color (cricket helmets are often red)
                    hsv = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2HSV)
                    lower_red1 = np.array([0, 70, 50])
                    upper_red1 = np.array([10, 255, 255])
                    lower_red2 = np.array([170, 70, 50])
                    upper_red2 = np.array([180, 255, 255])
                    
                    red_mask1 = cv2.inRange(hsv, lower_red1, upper_red1)
                    red_mask2 = cv2.inRange(hsv, lower_red2, upper_red2)
                    red_mask = cv2.bitwise_or(red_mask1, red_mask2)
                    
                    red_ratio = np.sum(red_mask > 0) / (red_mask.shape[0] * red_mask.shape[1])
                    
                    # 2. Detect grill pattern
                    edges = cv2.Canny(gray, 50, 150)
                    lines = cv2.HoughLinesP(edges, 1, np.pi/180, threshold=30,
                                          minLineLength=20, maxLineGap=10)
                    
                    vertical_lines = 0
                    if lines is not None:
                        for line in lines:
                            x1, y1, x2, y2 = line[0]
                            angle = np.abs(np.arctan2(y2-y1, x2-x1) * 180.0 / np.pi)
                            if 75 <= angle <= 105:  # Near vertical lines
                                vertical_lines += 1
                    
                    # 3. Shape detection
                    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    if contours:
                        largest_contour = max(contours, key=cv2.contourArea)
                        x, y, w, h = cv2.boundingRect(largest_contour)
                        aspect_ratio = float(w)/h
                        
                        # Typical cricket helmet aspect ratio
                        is_helmet_ratio = 1.1 <= aspect_ratio <= 1.8
                        
                        # Calculate shape regularity
                        hull = cv2.convexHull(largest_contour)
                        hull_area = cv2.contourArea(hull)
                        contour_area = cv2.contourArea(largest_contour)
                        solidity = contour_area/hull_area if hull_area > 0 else 0
                        
                        # Strong indicators of cricket helmet
                        if (red_ratio > 0.15 and  # Significant red color
                            vertical_lines >= 3 and  # Grill pattern
                            is_helmet_ratio and  # Correct shape
                            solidity > 0.7):  # Solid shape
                            
                            category_scores['cricket'] += 1.5  # Very strong boost
                            return {
                                'category': 'cricket',
                                'confidence': 0.9,
                                'all_scores': {cat: float(score) for cat, score in category_scores.items()}
                            }
            
            except Exception as feature_error:
                print(f"Feature detection error: {feature_error}")
                pass
            
            # Balance confidence thresholds for all categories
            min_confidence_thresholds = {
                'cricket': 0.4,    # Slightly lower threshold for cricket
                'football': 0.5,   # Higher threshold for football to avoid false positives
                'badminton': 0.45,
                'table_games': 0.45
            }

            # Normalize scores
            total_score = sum(category_scores.values())
            if total_score > 0:
                normalized_scores = {cat: score/total_score for cat, score in category_scores.items()}
            else:
                normalized_scores = category_scores
            
            # Get predicted category
            predicted_category = max(normalized_scores, key=normalized_scores.get)
            
            # Apply category-specific confidence thresholds
            if normalized_scores[predicted_category] < min_confidence_thresholds[predicted_category]:
                return {
                    'category': 'unknown',
                    'confidence': 0.0,
                    'all_scores': {cat: float(score) for cat, score in normalized_scores.items()}
                }
                
            # Before final category selection, add additional verification
            if predicted_category == 'football':
                # If there are any helmet-like features, require higher confidence
                if aspect_ratio >= 1.1 and aspect_ratio <= 1.6:
                    min_confidence_thresholds['football'] = 0.7  # Much higher threshold
                    
                # Check if cricket is second highest with decent confidence
                scores_list = sorted([(score, cat) for cat, score in normalized_scores.items()], reverse=True)
                if len(scores_list) > 1 and scores_list[1][1] == 'cricket' and scores_list[1][0] > 0.3:
                    if normalized_scores['football'] < 0.7:  # If football confidence isn't very high
                        predicted_category = 'cricket'
                        normalized_scores['cricket'] = normalized_scores['football']
                        normalized_scores['football'] *= 0.3

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