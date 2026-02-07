# scanner/threat_intelligence.py
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

class ThreatIntelligenceAI:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            "distilbert-base-uncased",
            num_labels=2  # malicious/benign
        )
    
    def analyze_file_metadata(self, filename, file_info):
        """Use NLP to analyze file names and metadata"""
        text = f"{filename} {file_info}"
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
        malware_prob = predictions[0][1].item()
        
        return malware_prob