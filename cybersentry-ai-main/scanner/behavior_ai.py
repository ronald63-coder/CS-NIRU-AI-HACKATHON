# scanner/behavior_ai.py
import numpy as np
from tensorflow.keras import layers, models

class BehaviorAI:
    def __init__(self):
        self.model = self.build_lstm_model()
    
    def build_lstm_model(self):
        """LSTM for sequential user behavior analysis"""
        model = models.Sequential([
            layers.LSTM(64, return_sequences=True, input_shape=(10, 8)),
            layers.LSTM(32),
            layers.Dense(16, activation='relu'),
            layers.Dense(1, activation='sigmoid')  # Anomaly score
        ])
        
        model.compile(
            optimizer='adam',
            loss='mse',
            metrics=['mae']
        )
        
        return model
    
    def analyze_sequence(self, user_actions):
        """Analyze sequence of user actions for anomalies"""
        # Convert actions to features
        features = self.extract_behavior_features(user_actions)
        
        # Predict anomaly
        anomaly_score = self.model.predict(features, verbose=0)[0][0]
        
        return anomaly_score
    
    def extract_behavior_features(self, actions):
        """Convert user actions to numerical features"""
        # Time of day (0-23)
        # Action type (encoded)
        # Resource accessed
        # Department
        # Location risk
        # etc.
        pass