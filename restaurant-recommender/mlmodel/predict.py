import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np
import json

# Load sentiment model and tokenizer
sentiment_dir = './outputs_distilroberta_base_restaurant/sentiment'
tokenizer = AutoTokenizer.from_pretrained(sentiment_dir)
sentiment_model = AutoModelForSequenceClassification.from_pretrained(sentiment_dir)

# Load aspect model
aspect_dir = './outputs_distilroberta_base_restaurant/aspects'
aspect_model = AutoModelForSequenceClassification.from_pretrained(aspect_dir)

# Load aspect and sentiment labels
with open('./outputs_distilroberta_base_restaurant/label_info.json', 'r') as f:
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
    print('Type a restaurant review and press Enter. Press Ctrl+C to exit.')
    try:
        while True:
            review = input('\nEnter review: ')
            sentiment = predict_sentiment(review)
            aspects = predict_aspects(review)
            print(f'Predicted Sentiment: {sentiment}')
            print('Predicted Aspects:', ', '.join(aspects) if aspects else 'None')
    except KeyboardInterrupt:
        print('\nExiting...')
