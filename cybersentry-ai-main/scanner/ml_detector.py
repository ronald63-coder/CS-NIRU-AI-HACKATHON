# scanner/ml_detector.py
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
import lightgbm as lgb

class AIMalwareDetector:
    def __init__(self):
        self.models = {
            'random_forest': None,
            'xgboost': None,
            'anomaly_detector': None
        }
        self.load_or_train_models()
    
    def extract_ml_features(self, file_bytes, pe_features):
        """Extract features for ML models"""
        features = []
        
        # 1. Basic file features
        features.append(len(file_bytes))  # File size
        features.append(self.calculate_entropy(file_bytes))  # Entropy
        
        # 2. PE-specific features (if applicable)
        if pe_features.get('is_pe', False):
            features.append(pe_features.get('sections', 0))
            features.append(pe_features.get('imports', 0))
            features.append(pe_features.get('suspicious_sections', 0))
        else:
            features.extend([0, 0, 0])  # Padding
        
        # 3. Statistical features
        if len(file_bytes) > 0:
            byte_array = np.frombuffer(file_bytes[:10000], dtype=np.uint8)
            features.append(np.mean(byte_array))
            features.append(np.std(byte_array))
            features.append(np.percentile(byte_array, 90))
        else:
            features.extend([0, 0, 0])
        
        # 4. N-gram features (simplified)
        if len(file_bytes) >= 4:
            first_bytes = file_bytes[:4]
            features.append(int.from_bytes(first_bytes, 'big'))
        else:
            features.append(0)
        
        return np.array(features).reshape(1, -1)
    
    def predict_with_ensemble(self, features):
        """Use ensemble of ML models for prediction"""
        predictions = []
        confidences = []
        
        for model_name, model in self.models.items():
            if model:
                try:
                    pred = model.predict(features)[0]
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(features)[0]
                        confidence = max(proba)
                    else:
                        confidence = 0.8
                    
                    predictions.append(pred)
                    confidences.append(confidence)
                except:
                    continue
        
        # Ensemble voting
        if predictions:
            final_pred = max(set(predictions), key=predictions.count)
            avg_confidence = np.mean(confidences)
            return final_pred, avg_confidence
        
        return 0, 0.5  # Default: benign with medium confidence
    
    def detect_anomalies(self, features):
        """Use Isolation Forest for zero-day detection"""
        if self.models['anomaly_detector']:
            anomaly_score = self.models['anomaly_detector'].score_samples(features)[0]
            return anomaly_score < -0.5  # Custom threshold
        
        return False