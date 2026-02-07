from sklearn.ensemble import IsolationForest
import numpy as np
import joblib
from pathlib import Path

class AnomalyDetector:
    """Anomaly detection for zero-day threats"""
    
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model_path = Path("data/models/anomaly_detector.pkl")
        self.load_model()
    
    def load_model(self):
        """Load or create anomaly detection model"""
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)
        else:
            # Train on normal data distribution
            self.train_demo_model()
    
    def train_demo_model(self):
        """Train on normal file features"""
        # Generate normal file features
        np.random.seed(42)
        X_normal = np.column_stack([
            np.random.normal(50000, 20000, 500),    # file_size
            np.random.uniform(4, 6, 500),           # entropy
            np.random.randint(3, 8, 500),           # sections
            np.random.randint(20, 100, 500)         # imports
        ])
        
        self.model.fit(X_normal)
        
        # Save model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        
        print(f"✅ Anomaly detector trained and saved to {self.model_path}")
    
    def detect(self, features):
        """Detect if features are anomalous"""
        features_array = np.array(features).reshape(1, -1)
        
        try:
            prediction = self.model.predict(features_array)[0]
            # Returns 1 for normal, -1 for anomaly
            return prediction == -1
        except:
            return False