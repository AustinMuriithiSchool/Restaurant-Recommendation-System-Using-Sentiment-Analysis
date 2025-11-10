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

def backfill_predictions(conn):
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, review_text FROM restaurant_reviews WHERE predicted_sentiment IS NULL OR predicted_aspects IS NULL OR predicted_sentiment = '' OR predicted_aspects = ''")
    reviews = cur.fetchall()
    updated = 0
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
        updated += 1
    conn.commit()
    cur.close()
    return updated, len(reviews)
