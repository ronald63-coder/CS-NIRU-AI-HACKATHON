import hashlib
import magic
import numpy as np
from typing import Dict, Any

class FileFeatureExtractor:
    """Extract features from files for AI analysis"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0.0
        
        # Use first 10KB for efficiency
        sample = data[:10000]
        counts = np.bincount(np.frombuffer(sample, dtype=np.uint8))
        probabilities = counts / len(sample)
        probabilities = probabilities[probabilities > 0]
        
        if len(probabilities) == 0:
            return 0.0
        
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)
    
    def extract_basic_features(self, file_bytes: bytes) -> Dict[str, Any]:
        """Extract basic file features"""
        features = {
            "file_size": len(file_bytes),
            "entropy": self.calculate_entropy(file_bytes),
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest()
        }
        
        # Try to get file type
        try:
            features["file_type"] = magic.from_buffer(file_bytes)
        except:
            features["file_type"] = "Unknown"
        
        return features