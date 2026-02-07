# scanner/deep_learning.py
import tensorflow as tf
from tensorflow.keras import layers, models
import numpy as np

class DeepMalwareClassifier:
    def __init__(self):
        self.model = self.build_cnn_model()
        self.load_pretrained_weights()
    
    def build_cnn_model(self):
        """CNN for malware classification from byte sequences"""
        model = models.Sequential([
            layers.Embedding(input_dim=256, output_dim=64, input_length=10000),
            layers.Conv1D(128, 3, activation='relu'),
            layers.MaxPooling1D(2),
            layers.Conv1D(256, 3, activation='relu'),
            layers.GlobalMaxPooling1D(),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.5),
            layers.Dense(64, activation='relu'),
            layers.Dense(1, activation='sigmoid')  # Binary: malware or not
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC()]
        )
        
        return model
    
    def preprocess_bytes(self, file_bytes, max_length=10000):
        """Convert bytes to CNN input"""
        # Truncate or pad to fixed length
        if len(file_bytes) > max_length:
            processed = list(file_bytes[:max_length])
        else:
            processed = list(file_bytes) + [0] * (max_length - len(file_bytes))
        
        return np.array(processed).reshape(1, max_length)
    
    def predict(self, file_bytes):
        """Deep learning prediction"""
        processed = self.preprocess_bytes(file_bytes)
        prediction = self.model.predict(processed, verbose=0)[0][0]
        
        verdict = "malicious" if prediction > 0.7 else "benign"
        confidence = float(prediction) if prediction > 0.5 else float(1 - prediction)
        
        return verdict, confidence