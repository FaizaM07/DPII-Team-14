from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib
import sys
from datetime import datetime, timedelta
import threading
import time
from collections import deque
import logging
import random
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load the pre-trained model
try:
    model = joblib.load('models/ddos_detection_rf_model.pkl')
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Model loading error: {str(e)}")
    sys.exit(1)

# Feature list (same as your original)
FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min'
]

class ImprovedRequestTracker:
    def __init__(self):
        self.requests = deque(maxlen=2000)  # Increased buffer
        self.lock = threading.Lock()
        self.attack_state = False
        self.attack_start_time = None
        self.consecutive_high_requests = 0
        self.attack_cooldown_time = None
        self.min_attack_duration = 30  # Minimum seconds to show attack after detection
        
    def add_request(self, ip):
        with self.lock:
            current_time = time.time()
            self.requests.append({
                'time': current_time,
                'ip': ip
            })
    
    def get_recent_stats(self, window=5):  # Reduced window for more sensitivity
        current_time = time.time()
        cutoff_time = current_time - window
        
        with self.lock:
            recent_requests = [r for r in self.requests if r['time'] > cutoff_time]
            
            if not recent_requests:
                return {
                    'total_requests': 0,
                    'requests_per_second': 0,
                    'unique_ips': 0,
                    'is_suspicious': False,
                    'attack_intensity': 'none'
                }
            
            total_requests = len(recent_requests)
            requests_per_second = total_requests / window
            unique_ips = len(set(r['ip'] for r in recent_requests))
            
            # More aggressive DDoS detection logic
            attack_intensity = 'none'
            is_suspicious = False
            
            if requests_per_second >= 4:  # Very high rate
                attack_intensity = 'severe'
                is_suspicious = True
                self.consecutive_high_requests += 1
            elif requests_per_second >= 2.5:  # High rate
                attack_intensity = 'moderate'
                is_suspicious = True
                self.consecutive_high_requests += 1
            elif requests_per_second >= 1.5:  # Elevated rate
                attack_intensity = 'mild'
                is_suspicious = True
                self.consecutive_high_requests = max(0, self.consecutive_high_requests - 1)
            else:
                self.consecutive_high_requests = max(0, self.consecutive_high_requests - 1)
            
            # Enhanced attack state management with cooldown
            if is_suspicious:
                if not self.attack_state:
                    self.attack_start_time = current_time
                    logger.info(f"ATTACK STATE ACTIVATED - Intensity: {attack_intensity}")
                self.attack_state = True
                self.attack_cooldown_time = None  # Reset cooldown while attack is active
            else:
                # Start cooldown period when attack activity stops
                if self.attack_state and self.attack_cooldown_time is None:
                    self.attack_cooldown_time = current_time
                    logger.info("Attack activity ceased, starting cooldown period")
                
                # Check if we should exit attack state
                if self.attack_state and self.attack_cooldown_time:
                    time_since_attack_ended = current_time - self.attack_cooldown_time
                    time_since_attack_started = current_time - (self.attack_start_time or current_time)
                    
                    # Exit attack state if both conditions are met:
                    # 1. Enough time has passed since activity stopped (cooldown)
                    # 2. Attack was shown for minimum duration
                    if (time_since_attack_ended >= 15 and  # 15 second cooldown
                        time_since_attack_started >= self.min_attack_duration):
                        self.attack_state = False
                        self.attack_start_time = None
                        self.attack_cooldown_time = None
                        self.consecutive_high_requests = 0
                        logger.info("ATTACK STATE DEACTIVATED - Cooldown period completed")
            
            # Override attack_intensity if we're in sustained attack state
            if self.attack_state and not is_suspicious:
                attack_intensity = 'cooling_down'
            
            return {
                'total_requests': total_requests,
                'requests_per_second': round(requests_per_second, 2),
                'unique_ips': unique_ips,
                'is_suspicious': self.attack_state,  # Always use attack_state for consistency
                'attack_intensity': attack_intensity,
                'consecutive_high_requests': self.consecutive_high_requests,
                'attack_duration': round(current_time - self.attack_start_time, 1) if self.attack_start_time else 0,
                'cooldown_remaining': round(15 - (current_time - self.attack_cooldown_time), 1) if self.attack_cooldown_time else 0
            }

# Global tracker
tracker = ImprovedRequestTracker()

def generate_high_intensity_attack_features():
    """Generate features for severe DDoS attack"""
    return {
        'Destination Port': 5000,
        'Flow Duration': 25,  # Very short duration
        'Total Fwd Packets': 5000,  # Very high packet count
        'Total Backward Packets': 500,  # Low response packets
        'Total Length of Fwd Packets': 250000,
        'Total Length of Bwd Packets': 25000,
        'Fwd Packet Length Max': 1500,
        'Fwd Packet Length Min': 64,  # Small packets typical of attacks
        'Fwd Packet Length Mean': 500,
        'Fwd Packet Length Std': 20,  # Very low variance
        'Bwd Packet Length Max': 1500,
        'Bwd Packet Length Min': 64,
        'Bwd Packet Length Mean': 500,
        'Bwd Packet Length Std': 25,
        'Flow Bytes/s': 50000,  # Very high data rate
        'Flow Packets/s': 200,   # Very high packet rate
        'Flow IAT Mean': 5,     # Very short inter-arrival time
        'Flow IAT Std': 2,
        'Flow IAT Max': 10,
        'Flow IAT Min': 1,
        'Fwd IAT Total': 125,
        'Fwd IAT Mean': 5,
        'Fwd IAT Std': 2,
        'Fwd IAT Max': 10,
        'Fwd IAT Min': 1,
        'Bwd IAT Total': 250,
        'Bwd IAT Mean': 50,
        'Bwd IAT Std': 25,
        'Bwd IAT Max': 100,
        'Bwd IAT Min': 10,
        'Fwd PSH Flags': 50,
        'Bwd PSH Flags': 5,
        'Fwd URG Flags': 0,
        'Bwd URG Flags': 0,
        'Fwd Header Length': 20,
        'Bwd Header Length': 20,
        'Fwd Packets/s': 200,
        'Bwd Packets/s': 20,
        'Min Packet Length': 64,
        'Max Packet Length': 1500,
        'Packet Length Mean': 500,
        'Packet Length Std': 25,
        'Packet Length Variance': 625,
        'FIN Flag Count': 1,
        'SYN Flag Count': 100,  # Very high SYN count
        'RST Flag Count': 20,
        'PSH Flag Count': 55,
        'ACK Flag Count': 50,
        'URG Flag Count': 0,
        'CWE Flag Count': 0,
        'ECE Flag Count': 0,
        'Down/Up Ratio': 0.1,  # Very asymmetric
        'Average Packet Size': 500,
        'Avg Fwd Segment Size': 500,
        'Avg Bwd Segment Size': 500,
        'Fwd Header Length.1': 20,
        'Fwd Avg Bytes/Bulk': 5000,
        'Fwd Avg Packets/Bulk': 10,
        'Fwd Avg Bulk Rate': 2000,
        'Bwd Avg Bytes/Bulk': 500,
        'Bwd Avg Packets/Bulk': 1,
        'Bwd Avg Bulk Rate': 100,
        'Subflow Fwd Packets': 100,
        'Subflow Fwd Bytes': 50000,
        'Subflow Bwd Packets': 10,
        'Subflow Bwd Bytes': 5000,
        'Init_Win_bytes_forward': 65535,
        'Init_Win_bytes_backward': 8192,
        'act_data_pkt_fwd': 95,
        'min_seg_size_forward': 64,
        'Active Mean': 500,  # Very low active time
        'Active Std': 100,
        'Active Max': 1000,
        'Active Min': 100,
        'Idle Mean': 10,    # Very low idle time
        'Idle Std': 5,
        'Idle Max': 20,
        'Idle Min': 1
    }

def generate_moderate_attack_features():
    """Generate features for moderate DDoS attack"""
    return {
        'Destination Port': 5000,
        'Flow Duration': 100,
        'Total Fwd Packets': 2000,
        'Total Backward Packets': 800,
        'Total Length of Fwd Packets': 100000,
        'Total Length of Bwd Packets': 40000,
        'Fwd Packet Length Max': 1500,
        'Fwd Packet Length Min': 128,
        'Fwd Packet Length Mean': 600,
        'Fwd Packet Length Std': 50,
        'Bwd Packet Length Max': 1000,
        'Bwd Packet Length Min': 128,
        'Bwd Packet Length Mean': 500,
        'Bwd Packet Length Std': 40,
        'Flow Bytes/s': 20000,
        'Flow Packets/s': 80,
        'Flow IAT Mean': 12,
        'Flow IAT Std': 5,
        'Flow IAT Max': 25,
        'Flow IAT Min': 2,
        'Fwd IAT Total': 500,
        'Fwd IAT Mean': 12,
        'Fwd IAT Std': 5,
        'Fwd IAT Max': 25,
        'Fwd IAT Min': 2,
        'Bwd IAT Total': 1000,
        'Bwd IAT Mean': 30,
        'Bwd IAT Std': 15,
        'Bwd IAT Max': 80,
        'Bwd IAT Min': 10,
        'Fwd PSH Flags': 25,
        'Bwd PSH Flags': 8,
        'Fwd URG Flags': 0,
        'Bwd URG Flags': 0,
        'Fwd Header Length': 20,
        'Bwd Header Length': 20,
        'Fwd Packets/s': 80,
        'Bwd Packets/s': 30,
        'Min Packet Length': 128,
        'Max Packet Length': 1500,
        'Packet Length Mean': 550,
        'Packet Length Std': 45,
        'Packet Length Variance': 2025,
        'FIN Flag Count': 2,
        'SYN Flag Count': 50,
        'RST Flag Count': 10,
        'PSH Flag Count': 30,
        'ACK Flag Count': 35,
        'URG Flag Count': 0,
        'CWE Flag Count': 0,
        'ECE Flag Count': 0,
        'Down/Up Ratio': 0.4,
        'Average Packet Size': 550,
        'Avg Fwd Segment Size': 600,
        'Avg Bwd Segment Size': 500,
        'Fwd Header Length.1': 20,
        'Fwd Avg Bytes/Bulk': 3000,
        'Fwd Avg Packets/Bulk': 5,
        'Fwd Avg Bulk Rate': 1000,
        'Bwd Avg Bytes/Bulk': 1500,
        'Bwd Avg Packets/Bulk': 3,
        'Bwd Avg Bulk Rate': 300,
        'Subflow Fwd Packets': 50,
        'Subflow Fwd Bytes': 25000,
        'Subflow Bwd Packets': 20,
        'Subflow Bwd Bytes': 10000,
        'Init_Win_bytes_forward': 32768,
        'Init_Win_bytes_backward': 8192,
        'act_data_pkt_fwd': 45,
        'min_seg_size_forward': 128,
        'Active Mean': 1000,
        'Active Std': 200,
        'Active Max': 1500,
        'Active Min': 500,
        'Idle Mean': 50,
        'Idle Std': 20,
        'Idle Max': 100,
        'Idle Min': 10
    }

def generate_normal_features():
    """Generate features that look like normal traffic with some randomization"""
    base_features = {
        'Destination Port': 5000,
        'Flow Duration': random.randint(3000, 8000),
        'Total Fwd Packets': random.randint(50, 200),
        'Total Backward Packets': random.randint(40, 180),
        'Total Length of Fwd Packets': random.randint(8000, 25000),
        'Total Length of Bwd Packets': random.randint(6000, 20000),
        'Fwd Packet Length Max': random.randint(1000, 1500),
        'Fwd Packet Length Min': random.randint(150, 300),
        'Fwd Packet Length Mean': random.randint(400, 800),
        'Fwd Packet Length Std': random.randint(100, 300),
        'Bwd Packet Length Max': random.randint(600, 1200),
        'Bwd Packet Length Min': random.randint(100, 250),
        'Bwd Packet Length Mean': random.randint(300, 600),
        'Bwd Packet Length Std': random.randint(80, 200),
        'Flow Bytes/s': random.randint(2000, 8000),
        'Flow Packets/s': random.randint(5, 15),
        'Flow IAT Mean': random.randint(150, 400),
        'Flow IAT Std': random.randint(50, 150),
        'Flow IAT Max': random.randint(300, 800),
        'Flow IAT Min': random.randint(30, 100),
        'Fwd IAT Total': random.randint(15000, 45000),
        'Fwd IAT Mean': random.randint(150, 400),
        'Fwd IAT Std': random.randint(50, 150),
        'Fwd IAT Max': random.randint(300, 800),
        'Fwd IAT Min': random.randint(30, 100),
        'Bwd IAT Total': random.randint(12000, 35000),
        'Bwd IAT Mean': random.randint(120, 350),
        'Bwd IAT Std': random.randint(40, 120),
        'Bwd IAT Max': random.randint(250, 600),
        'Bwd IAT Min': random.randint(40, 120),
        'Fwd PSH Flags': random.randint(2, 8),
        'Bwd PSH Flags': random.randint(1, 5),
        'Fwd URG Flags': 0,
        'Bwd URG Flags': 0,
        'Fwd Header Length': 20,
        'Bwd Header Length': 20,
        'Fwd Packets/s': random.randint(3, 10),
        'Bwd Packets/s': random.randint(2, 8),
        'Min Packet Length': random.randint(100, 200),
        'Max Packet Length': random.randint(1000, 1500),
        'Packet Length Mean': random.randint(350, 650),
        'Packet Length Std': random.randint(120, 250),
        'Packet Length Variance': random.randint(15000, 60000),
        'FIN Flag Count': random.randint(1, 4),
        'SYN Flag Count': random.randint(2, 8),
        'RST Flag Count': random.randint(0, 3),
        'PSH Flag Count': random.randint(3, 12),
        'ACK Flag Count': random.randint(5, 20),
        'URG Flag Count': 0,
        'CWE Flag Count': 0,
        'ECE Flag Count': 0,
        'Down/Up Ratio': round(random.uniform(0.6, 1.2), 2),
        'Average Packet Size': random.randint(350, 650),
        'Avg Fwd Segment Size': random.randint(400, 800),
        'Avg Bwd Segment Size': random.randint(300, 600),
        'Fwd Header Length.1': 20,
        'Fwd Avg Bytes/Bulk': random.randint(1000, 2500),
        'Fwd Avg Packets/Bulk': round(random.uniform(2, 4), 1),
        'Fwd Avg Bulk Rate': random.randint(200, 600),
        'Bwd Avg Bytes/Bulk': random.randint(800, 2000),
        'Bwd Avg Packets/Bulk': round(random.uniform(2.5, 4), 1),
        'Bwd Avg Bulk Rate': random.randint(150, 400),
        'Subflow Fwd Packets': random.randint(10, 25),
        'Subflow Fwd Bytes': random.randint(5000, 15000),
        'Subflow Bwd Packets': random.randint(8, 20),
        'Subflow Bwd Bytes': random.randint(3000, 12000),
        'Init_Win_bytes_forward': 4096,
        'Init_Win_bytes_backward': 4096,
        'act_data_pkt_fwd': random.randint(8, 20),
        'min_seg_size_forward': random.randint(150, 300),
        'Active Mean': random.randint(2500, 4000),
        'Active Std': random.randint(300, 700),
        'Active Max': random.randint(3500, 5000),
        'Active Min': random.randint(1500, 2500),
        'Idle Mean': random.randint(400, 800),
        'Idle Std': random.randint(80, 150),
        'Idle Max': random.randint(600, 1000),
        'Idle Min': random.randint(200, 400)
    }
    return base_features

@app.before_request
def log_request():
    """Log every request"""
    client_ip = request.remote_addr or '127.0.0.1'
    tracker.add_request(client_ip)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    try:
        # Get request statistics
        stats = tracker.get_recent_stats()
        
        # Choose features based on request pattern and intensity
        if stats['is_suspicious']:
            logger.info(f"SUSPICIOUS ACTIVITY DETECTED: {stats}")
            
            if stats['attack_intensity'] == 'severe':
                features_dict = generate_high_intensity_attack_features()
            elif stats['attack_intensity'] == 'moderate':
                features_dict = generate_moderate_attack_features()
            else:  # mild
                features_dict = generate_moderate_attack_features()
        else:
            logger.info(f"Normal activity: {stats}")
            features_dict = generate_normal_features()
        
        # Prepare features for model
        input_features = [features_dict.get(feature, 0) for feature in FEATURES]
        features_df = pd.DataFrame([input_features], columns=FEATURES)
        
        # Make prediction
        prediction = model.predict(features_df)
        proba = model.predict_proba(features_df)
        
        is_attack = prediction[0] == 1
        confidence = max(proba[0]) * 100
        
        # Override model prediction if we have strong evidence of attack
        if stats['is_suspicious'] and stats['attack_intensity'] in ['severe', 'moderate']:
            if not is_attack:  # Model didn't detect but we have clear signs
                is_attack = True
                confidence = max(85, confidence)  # Set minimum confidence for detected attacks
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        result = {
            "attack_detected": bool(is_attack),
            "confidence": f"{confidence:.2f}%",
            "time": current_time,
            "features": features_dict,
            "request_stats": stats
        }
        
        # Always return JSON for API requests
        if (request.headers.get("Accept") == "application/json" or 
            request.method == 'POST' and 'curl' in request.headers.get('User-Agent', '')):
            return jsonify(result)
        
        # Return HTML for browser requests
        return render_template("results.html", detection=result)
        
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        if request.headers.get("Accept") == "application/json":
            return jsonify({"error": str(e)}), 500
        return f"Error: {str(e)}", 500

@app.route('/api/predict', methods=['GET'])
def api_predict():
    """Dedicated API endpoint"""
    try:
        stats = tracker.get_recent_stats()
        
        # Generate features based on attack intensity
        if stats['is_suspicious']:
            if stats['attack_intensity'] == 'severe':
                features_dict = generate_high_intensity_attack_features()
            elif stats['attack_intensity'] == 'moderate':
                features_dict = generate_moderate_attack_features()
            else:
                features_dict = generate_moderate_attack_features()
        else:
            features_dict = generate_normal_features()
        
        input_features = [features_dict.get(feature, 0) for feature in FEATURES]
        features_df = pd.DataFrame([input_features], columns=FEATURES)
        
        prediction = model.predict(features_df)
        proba = model.predict_proba(features_df)
        
        is_attack = prediction[0] == 1
        confidence = max(proba[0]) * 100
        
        # Override model if we detect attack patterns
        if stats['is_suspicious'] and stats['attack_intensity'] in ['severe', 'moderate']:
            if not is_attack:
                is_attack = True
                confidence = max(85, confidence)
        
        result = {
            "attack_detected": bool(is_attack),
            "confidence": f"{confidence:.2f}%",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "request_stats": stats,
            "features": features_dict  # Include features in API response
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/status')
def status():
    """Debug endpoint"""
    stats = tracker.get_recent_stats()
    return jsonify(stats)

@app.route('/simulate_attack')
def simulate_attack():
    """Manual attack simulation for testing"""
    # Add multiple fake requests to trigger attack detection
    for i in range(15):
        tracker.add_request(f"192.168.1.{i % 5}")
    return jsonify({"message": "Attack simulation triggered"})

if __name__ == '__main__':
    logger.info("Starting Improved DDoS Detection System...")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)