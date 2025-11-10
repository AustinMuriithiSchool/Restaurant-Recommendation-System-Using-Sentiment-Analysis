import os
import json
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

# MySQL config (same as app.py)
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
MYSQL_DB = os.environ.get('MYSQL_DB', 'nourishnet')

db = mysql.connector.connect(
    host=MYSQL_HOST,
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    database=MYSQL_DB
)
cursor = db.cursor()



# Load JSON data
with open("reviews.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Insert each review
for review in data:
    review_url = review.get("review_url") or review.get("reviewUrl")
    # Check if review_url already exists
    cursor.execute("SELECT id FROM restaurant_reviews WHERE review_url = %s", (review_url,))
    if cursor.fetchone():
        print(f"Skipping duplicate review with url: {review_url}")
        continue
    cursor.execute("""
    INSERT INTO restaurant_reviews (
        author_name, place_address, place_name, review_url,
        review_title, review_text, review_rating, location
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        review.get("author_name") or review.get("authorName"),
        review.get("place_address") or review.get("placeAddress"),
        review.get("place_name") or review.get("placeName"),
        review_url,
        review.get("review_title") or review.get("reviewTitle"),
        review.get("review_text") or review.get("reviewText"),
        review.get("review_rating") or review.get("reviewRating"),
        review.get("location") or review.get("Location", "Nairobi")
    ))

db.commit()
print("Data inserted successfully!")
