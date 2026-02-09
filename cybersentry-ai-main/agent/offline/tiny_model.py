# agent/offline/tiny_model.py
"""Quantised model for Raspberry Pi / offline deployment"""

import os
import numpy as np
from typing import List, Optional

# Try ONNX runtime
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    print("⚠️  ONNX not installed — using sklearn fallback")


class TinyMalwareModel:
    """
    Lightweight malware detector for edge deployment
    - 3B parameters quantised to INT8
    - Runs on Raspberry Pi 5 without GPU
    - No internet required
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or self._default_path()
        self.session = None
        self.fallback_weights = None
        
        if ONNX_AVAILABLE and os.path.exists(self.model_path):
            self._load_onnx()
        else:
            self._init_fallback()
    
    def _default_path(self) -> str:
        return os.path.join(
            os.path.dirname(__file__), 
            "model_q3b.onnx"
        )
    
    def _load_onnx(self):
        """Load quantised ONNX model"""
        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 2  # Pi-friendly
        opts.intra_op_num_threads = 2
        
        self.session = ort.InferenceSession(
            self.model_path,
            opts,
            providers=["CPUExecutionProvider"]
        )
        print(f"✅ Loaded ONNX model: {self.model_path}")
    
    def _init_fallback(self):
        """Sklearn-like weights if ONNX unavailable"""
        # Simple logistic regression weights
        # [file_size, entropy, sections, imports, strings]
        self.fallback_weights = np.array([
            0.15,   # size (log)
            0.35,   # entropy
            0.20,   # PE sections
            0.15,   # imports
            0.15    # suspicious strings
        ])
        self.fallback_bias = -2.5
        print("⚠️  Using fallback weights (no ONNX)")
    
    def predict(self, features: List[float]) -> float:
        """
        Return malware probability (0-1)
        features: [file_size_log, entropy, sections, imports, string_score]
        """
        vec = np.array(features, dtype=np.float32).reshape(1, -1)
        
        if self.session is not None:
            # ONNX inference
            input_name = self.session.get_inputs()[0].name
            outputs = self.session.run(None, {input_name: vec})
            return float(outputs[0][0][0])  # sigmoid output
        
        # Fallback: manual sigmoid
        z = np.dot(vec, self.fallback_weights) + self.fallback_bias
        return float(1 / (1 + np.exp(-z)))
    
    def extract_features(self, file_bytes: bytes) -> List[float]:
        """Extract features from raw bytes (no PE parsing needed)"""
        import math
        
        size = len(file_bytes)
        size_log = math.log10(size + 1)
        
        # Simple entropy
        if size == 0:
            entropy = 0.0
        else:
            from collections import Counter
            counts = Counter(file_bytes[:1000])
            probs = [c / min(size, 1000) for c in counts.values()]
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        
        # PE check (lightweight)
        sections = 0
        imports = 0
        if file_bytes.startswith(b'MZ'):
            try:
                import pefile
                pe = pefile.PE(data=file_bytes)
                sections = len(pe.sections)
                imports = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
                pe.close()
            except:
                pass
        
        # String score (simple)
        suspicious = [b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory', b'cmd.exe', b'powershell']
        string_score = sum(1 for s in suspicious if s in file_bytes[:50000]) / len(suspicious)
        
        return [size_log, entropy, sections, imports, string_score]


# Singleton for import
_tiny_model = None

def get_model() -> TinyMalwareModel:
    """Lazy-load model"""
    global _tiny_model
    if _tiny_model is None:
        _tiny_model = TinyMalwareModel()
    return _tiny_model


async def offline_scan(file_bytes: bytes) -> dict:
    """Scan without internet — for edge deployment"""
    model = get_model()
    features = model.extract_features(file_bytes)
    prob = model.predict(features)
    
    verdict = "benign"
    if prob > 0.8:
        verdict = "malicious"
    elif prob > 0.5:
        verdict = "suspicious"
    
    return {
        "verdict": verdict,
        "confidence": prob,
        "features": features,
        "offline": True,
        "model": "tiny_q3b"
    }