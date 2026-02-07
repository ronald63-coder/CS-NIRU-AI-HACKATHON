import math

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy"""
    if not data:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy

def is_high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """Check if data has high entropy (possible encryption)"""
    return calculate_shannon_entropy(data) > threshold