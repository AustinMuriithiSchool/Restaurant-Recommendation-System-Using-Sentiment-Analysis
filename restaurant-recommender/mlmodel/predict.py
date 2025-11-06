
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np
import json
import os

# Use absolute paths for model directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sentiment_dir = os.path.join(BASE_DIR, "outputs_distilroberta_base_restaurant", "sentiment")
aspect_dir = os.path.join(BASE_DIR, "outputs_distilroberta_base_restaurant", "aspects")

# Load sentiment model and tokenizer
tokenizer = AutoTokenizer.from_pretrained(sentiment_dir, local_files_only=True)
sentiment_model = AutoModelForSequenceClassification.from_pretrained(sentiment_dir, local_files_only=True)

# Load aspect model
aspect_model = AutoModelForSequenceClassification.from_pretrained(aspect_dir, local_files_only=True)

# Load aspect and sentiment labels
label_info_path = os.path.join(BASE_DIR, "outputs_distilroberta_base_restaurant", "label_info.json")
with open(label_info_path, 'r') as f:
    label_info = json.load(f)
sentiment_labels = label_info['sentiment_labels']
aspect_labels = label_info['aspect_labels']

# Prediction function for sentiment
def predict_sentiment(text):
    inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=256)
    with torch.no_grad():
        outputs = sentiment_model(**inputs)
        logits = outputs.logits
        pred = torch.argmax(logits, dim=-1).item()
    return sentiment_labels[pred]

# Prediction function for aspects
def predict_aspects(text):
    inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=256)
    with torch.no_grad():
        outputs = aspect_model(**inputs)
        logits = outputs.logits
        probs = torch.sigmoid(logits).cpu().numpy()[0]
        pred = (probs >= 0.5).astype(int)
    return [aspect_labels[i] for i, v in enumerate(pred) if v == 1]

if __name__ == '__main__':
    pass
