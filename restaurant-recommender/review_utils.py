import mysql.connector

def insert_reviews_from_list(data, db_conn):
    """
    Insert reviews from a list of dicts into the restaurant_reviews table, skipping duplicates by review_url.
    Returns a tuple: (inserted_count, skipped_count)
    """
    cursor = db_conn.cursor()
    inserted = 0
    skipped = 0
    for review in data:
        review_url = review.get("review_url") or review.get("reviewUrl")
        if not review_url:
            skipped += 1
            continue
        cursor.execute("SELECT id FROM restaurant_reviews WHERE review_url = %s", (review_url,))
        if cursor.fetchone():
            skipped += 1
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
        inserted += 1
    db_conn.commit()
    cursor.close()
    return inserted, skipped
