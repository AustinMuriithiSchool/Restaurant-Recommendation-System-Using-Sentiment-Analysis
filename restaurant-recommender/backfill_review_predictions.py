import os
import mysql.connector
from dotenv import load_dotenv
from mlmodel.predict import predict_sentiment, predict_aspects
import json

load_dotenv()

MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
MYSQL_DB = os.environ.get('MYSQL_DB', 'nourishnet')

def get_db_connection():
    return mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB
    )

def backfill_predictions():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, review_text FROM restaurant_reviews WHERE predicted_sentiment IS NULL OR predicted_aspects IS NULL OR predicted_sentiment = '' OR predicted_aspects = ''")
    reviews = cur.fetchall()
    print(f"[INFO] Found {len(reviews)} reviews to backfill.")
    for review in reviews:
        review_id = review['id']
        text = review['review_text']
        sentiment = predict_sentiment(text)
        aspects = predict_aspects(text)
        aspects_json = json.dumps(aspects)
        cur.execute(
            "UPDATE restaurant_reviews SET predicted_sentiment = %s, predicted_aspects = %s WHERE id = %s",
            (sentiment, aspects_json, review_id)
        )
        print(f"[INFO] Updated review id {review_id} with sentiment '{sentiment}' and aspects {aspects}")
    conn.commit()
    cur.close()
    conn.close()
    print("[INFO] Backfill complete.")

if __name__ == '__main__':
    backfill_predictions()
