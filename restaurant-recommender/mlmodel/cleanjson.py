import json

# Input and output file paths
input_path = "C:\\Users\\amwen\\Desktop\\PROJECT\\Restaurant-Recommendation-System-Using-Sentiment-Analysis\\restaurant-recommender\\json files\\dataset_tripadvisor-reviews_2025-11-24_17-24-54-136.json"
output_path = "C:\\Users\\amwen\\Desktop\\PROJECT\\Restaurant-Recommendation-System-Using-Sentiment-Analysis\\restaurant-recommender\\json files\\cleaned_reviews_koinange.json"

# Load original data
with open(input_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# Constants for Tin Roof Cafe
PLACE_ADDRESS = "Dagoretti Road Opposite The Hub Karen. Approx 200m from Karen Roundabout"
PLACE_NAME = "Tin Roof Cafe"
LOCATION = "Nairobi"

# Convert structure
cleaned = []
for review in data:
    cleaned.append({
        "authorName": review.get("user", {}).get("name", ""),
        "placeAddress": PLACE_ADDRESS,
        "placeName": PLACE_NAME,
        "reviewUrl": review.get("url", ""),
        "reviewTitle": review.get("title", ""),
        "reviewText": review.get("text", ""),
        "reviewRating": review.get("rating", ""),
        "Location": LOCATION
    })

# Save cleaned JSON
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(cleaned, f, ensure_ascii=False, indent=2)

output_path
