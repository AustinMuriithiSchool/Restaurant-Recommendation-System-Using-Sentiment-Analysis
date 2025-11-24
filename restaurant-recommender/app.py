import os
import json
import json
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, g, send_file
import mysql.connector
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import auth as fb_auth, credentials
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from review_utils import insert_reviews_from_list
from review_prediction_utils import backfill_predictions

from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev')
app.config['SESSION_COOKIE_NAME'] = os.environ.get('SESSION_COOKIE_NAME', '__session')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Check if user exists endpoint for Google Sign-In
@app.route('/check_user', methods=['POST'])
def check_user():
    try:
        data = request.get_json(force=True)
        firebase_uid = data.get('firebase_uid')
        if not firebase_uid:
            return jsonify({'exists': False, 'error': 'No firebase_uid provided'}), 400
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id FROM users WHERE firebase_uid = %s', (firebase_uid,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify({'exists': bool(result)})
    except Exception as e:
        print('[DEBUG] /check_user error:', e)
        import traceback; traceback.print_exc()
        return jsonify({'exists': False, 'error': str(e)}), 500

def get_user_info(firebase_uid):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute('SELECT username, role, status FROM users WHERE firebase_uid = %s', (firebase_uid,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    if result:
        # result is a dict if dictionary=True, else tuple
        if isinstance(result, dict):
            return {'username': result.get('username'), 'role': result.get('role'), 'status': result.get('status')}
        else:
            return {'username': result[0], 'role': result[1], 'status': result[2]}
    return None

# MySQL config (update with your credentials)
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
def get_user_role(firebase_uid):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute('SELECT role FROM users WHERE firebase_uid = %s', (firebase_uid,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    if result:
        if isinstance(result, dict):
            return result.get('role')
        else:
            return result[0]
    return None
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    print("[DEBUG] Entered /register route. Method:", request.method)
    if request.method == 'POST':
        print("[DEBUG] Received POST request to /register")
        try:
            username = request.form['username']
            email = request.form['email']
            role = request.form['role']
            firebase_uid = request.form.get('firebase_uid')
            print(f"[DEBUG] Form data - username: {username}, email: {email}, role: {role}, firebase_uid: {firebase_uid}")
        except Exception as e:
            print("[DEBUG] Error reading form data:", e)
            error = f'Error reading form data: {e}'
            return render_template('register.html', user=g.user, error=error)

        if not firebase_uid:
            error = 'Registration failed: No Firebase UID received.'
            print("[DEBUG] No Firebase UID received from frontend.")
            return render_template('register.html', user=g.user, error=error)

        try:
            print("[DEBUG] Attempting to insert user into MySQL...")
            conn = get_db_connection()
            cur = conn.cursor()
            # If registering as admin, set status to 'pending', else 'active'
            status = 'pending' if role == 'admin' else 'active'
            cur.execute('INSERT INTO users (firebase_uid, username, email, role, status) VALUES (%s, %s, %s, %s, %s)',
                        (firebase_uid, username, email, role, status))
            conn.commit()
            print(f"[DEBUG] Inserted user into MySQL: {firebase_uid}, {email}, {username}, {role}, {status}")
            cur.close()
            conn.close()
        except Exception as e:
            print('[DEBUG] MySQL insert error:', e)
            error = f'MySQL insert error: {e}'
            return render_template('register.html', user=g.user, error=error)

        print("[DEBUG] Registration successful, redirecting to login.")
        return redirect(url_for('login'))

    print(f"[DEBUG] Rendering register.html. Error: {error}")
    return render_template('register.html', user=g.user, error=error)



# Initialize Firebase Admin
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred, {
        'projectId': os.environ.get('FIREBASE_PROJECT_ID')
    })

SESSION_COOKIE_NAME = app.config['SESSION_COOKIE_NAME']
SESSION_COOKIE_SECURE = app.config['SESSION_COOKIE_SECURE']

# Helper: verify session cookie
def verify_session():
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_cookie:
        return None
    try:
        decoded = fb_auth.verify_session_cookie(session_cookie, check_revoked=True)
        return decoded
    except Exception:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_user = verify_session()
        if not session_user:
            return redirect(url_for('login'))
        # Fetch username and role from MySQL using Firebase UID
        firebase_uid = session_user.get('uid') or session_user.get('user_id') or session_user.get('sub')
        user_info = get_user_info(firebase_uid) if firebase_uid else None
        if user_info:
            g.user = {
                'uid': firebase_uid,
                'username': user_info['username'],
                'role': user_info['role'],
                'status': user_info.get('status'),
                'email': session_user.get('email')
            }
        else:
            g.user = {'uid': firebase_uid, 'email': session_user.get('email')}
        return f(*args, **kwargs)
    return decorated

@app.before_request
def load_user():
    session_user = verify_session()
    if not session_user:
        g.user = None
        return
    firebase_uid = session_user.get('uid') or session_user.get('user_id') or session_user.get('sub')
    user_info = get_user_info(firebase_uid) if firebase_uid else None
    if user_info:
        g.user = {
            'uid': firebase_uid,
            'username': user_info['username'],
            'role': user_info['role'],
            'status': user_info.get('status'),
            'email': session_user.get('email')
        }
    else:
        g.user = {'uid': firebase_uid, 'email': session_user.get('email')}

@app.route('/')
def index():
    if g.user:
        # Redirect to correct dashboard based on role
        if g.user.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif g.user.get('role') == 'user':
            return redirect(url_for('user_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        firebase_uid = request.form['firebase_uid']  # Get from client after Firebase login
        user_info = get_user_info(firebase_uid)
        if user_info:
            g.user = {'uid': firebase_uid, 'username': user_info['username'], 'role': user_info['role']}
            if user_info['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user_info['role'] == 'user':
                return redirect(url_for('user_dashboard'))
        return 'User not found or role not set', 404
    return render_template('login.html', user=g.user)
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Show pending admins for approval
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email FROM users WHERE role='admin' AND status='pending'")
    pending_admins = cur.fetchall()
    # Fetch all users for display
    cur.execute("SELECT username, email, role FROM users")
    all_users = cur.fetchall()

    # --- Analytics: Aggregate sentiment and aspect data per restaurant ---
    analytics_data = []
    cur2 = conn.cursor(dictionary=True)
    cur2.execute("""
        SELECT place_name,
               COUNT(*) as total_reviews,
               SUM(CASE WHEN predicted_sentiment = 'positive' THEN 1 ELSE 0 END) as positive_reviews,
               SUM(CASE WHEN predicted_sentiment = 'negative' THEN 1 ELSE 0 END) as negative_reviews,
               SUM(CASE WHEN predicted_sentiment = 'neutral' THEN 1 ELSE 0 END) as neutral_reviews
        FROM restaurant_reviews
        GROUP BY place_name
        ORDER BY total_reviews DESC
    """)
    sentiment_rows = cur2.fetchall()
    # For aspects, count occurrences in predicted_aspects JSON array
    cur2.execute("SELECT place_name, predicted_aspects FROM restaurant_reviews")
    aspect_map = {}
    import json
    for row in cur2.fetchall():
        name = row['place_name']
        aspects = []
        try:
            aspects = json.loads(row['predicted_aspects']) if row['predicted_aspects'] else []
        except Exception:
            pass
        if name not in aspect_map:
            aspect_map[name] = {}
        for asp in aspects:
            aspect_map[name][asp] = aspect_map[name].get(asp, 0) + 1
    # Merge sentiment and aspect data
    for srow in sentiment_rows:
        name = srow['place_name']
        analytics_data.append({
            'place_name': name,
            'total_reviews': srow['total_reviews'],
            'positive_reviews': srow['positive_reviews'],
            'negative_reviews': srow['negative_reviews'],
            'neutral_reviews': srow['neutral_reviews'],
            'aspects': aspect_map.get(name, {})
        })
    cur2.close()
    cur.close()
    conn.close()
    return render_template('admin_dashboard.html', user=g.user, pending_admins=pending_admins, all_users=all_users, analytics_data=analytics_data)
# Approve admin route
@app.route('/approve_admin/<int:user_id>', methods=['POST'])
@login_required
def approve_admin(user_id):
    # Only allow active admins to approve
    if not g.user or g.user.get('role') != 'admin' or g.user.get('status') != 'active':
        return "Unauthorized", 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET status='active' WHERE id=%s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html', user=g.user)


# New route to process restaurant queries
@app.route('/query-restaurants', methods=['POST'])
@login_required
def query_restaurants():
    query = request.form.get('restaurant_query')
    restaurants = []
    if query:
        query_lower = query.lower()
        from mlmodel.train_distilroberta import ASPECT_SYNONYMS
        # Improved aspect extraction: match any query word to aspect synonyms
        aspect_keywords = []
        query_words = set(query_lower.split())
        # Extract sentiment from query (default to 'positive' if not found)
        sentiment_words = {'positive', 'good', 'great', 'excellent', 'amazing', 'nice', 'happy', 'love', 'best', 'awesome', 'delicious', 'friendly', 'clean', 'recommend', 'satisfied', 'enjoyed', 'pleasant', 'wonderful', 'tasty', 'fantastic', 'favorite', 'perfect', 'outstanding', 'superb', 'top', 'like'}
        negative_words = {'negative', 'bad', 'poor', 'terrible', 'awful', 'worst', 'disappointing', 'unhappy', 'hate', 'dirty', 'rude', 'unpleasant', 'slow', 'cold', 'bland', 'mediocre', 'dislike', 'horrible', 'unfriendly', 'unprofessional', 'unimpressed', 'unacceptable', 'disgusting', 'overpriced', 'noisy', 'uncomfortable'}
        query_sentiment = 'positive'
        for word in query_words:
            if word in negative_words:
                query_sentiment = 'negative'
                break
        # Map: aspect -> set of query words that matched it
        aspect_to_querywords = {}
        for aspect, synonyms in ASPECT_SYNONYMS.items():
            for syn in synonyms:
                if syn.lower() in query_words:
                    aspect_keywords.append(aspect)
                    aspect_to_querywords.setdefault(aspect, set()).add(syn.lower())
        print(f"[DEBUG] aspect_to_querywords: {aspect_to_querywords}")
        print(f"[DEBUG] Extracted aspect keywords from query (using synonyms): {aspect_keywords}")
        print(f"[DEBUG] Query: {query}")
        print(f"[DEBUG] Query sentiment: {query_sentiment}")

        # Detect location from query
        locations = ["nairobi", "mombasa", "kisumu", "eldoret", "nakuru"]
        detected_location = None
        for loc in locations:
            if loc in query_lower:
                detected_location = loc.capitalize()
                break
        print(f"[DEBUG] Detected location from query: {detected_location}")

        # Fetch reviews from restaurant_reviews table
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        sql = "SELECT * FROM restaurant_reviews"
        params = []
        if detected_location:
            sql += " WHERE location = %s"
            params.append(detected_location)
        cur.execute(sql, params)
        db_results = cur.fetchall()
        cur.close()
        conn.close()
        print(f"[DEBUG] Number of reviews fetched from DB: {len(db_results)}")

        # Use cached predictions for filtering
        import json
        from collections import defaultdict
        restaurant_map = defaultdict(list)
        for r in db_results:
            # Support both dict and tuple row types
            if isinstance(r, dict):
                key = r.get('place_name', 'Unknown')
            else:
                key = r[3] if len(r) > 3 else 'Unknown'
            restaurant_map[key].append(r)

        restaurant_list = []
        print(f"[DEBUG] Number of restaurants after grouping: {len(restaurant_map)}")
        for name, reviews in restaurant_map.items():
            from collections import Counter
            aspects_counter = Counter()
            aspect_sentiments = {}
            sentiments = []
            sample_reviews = []
            address = reviews[0]['place_address'] if isinstance(reviews[0], dict) and 'place_address' in reviews[0] else (reviews[0][4] if len(reviews[0]) > 4 else '')
            ratings = [r['review_rating'] if isinstance(r, dict) else r[7] for r in reviews if (r['review_rating'] if isinstance(r, dict) else r[7]) is not None]
            avg_rating = round(sum(ratings) / len(ratings), 2) if ratings else None
            # Build reverse synonym map for aspect matching
            synonym_to_aspect = {}
            for aspect, synonyms in ASPECT_SYNONYMS.items():
                for syn in synonyms:
                    synonym_to_aspect[syn.lower()] = aspect
            # Filter reviews strictly by aspect and sentiment using cached predictions
            filtered_reviews = []
            match_score = 0
            for r in reviews:
                if isinstance(r, dict):
                    review_text = r.get('review_text', '')
                    sentiment = r.get('predicted_sentiment', 'neutral')
                    aspects = json.loads(r.get('predicted_aspects', '[]')) if r.get('predicted_aspects') else []
                else:
                    review_text = r[6] if len(r) > 6 else ''
                    sentiment = r[9] if len(r) > 9 else 'neutral'
                    aspects = json.loads(r[10]) if len(r) > 10 and r[10] else []
                # Map predicted aspects to canonical aspect labels using synonyms
                mapped_aspects = set()
                for asp in aspects:
                    asp_lower = asp.lower()
                    if asp_lower in synonym_to_aspect:
                        mapped_aspects.add(synonym_to_aspect[asp_lower])
                    else:
                        mapped_aspects.add(asp_lower)
                sentiments.append(sentiment)
                for aspect in mapped_aspects:
                    aspects_counter[aspect] += 1
                    aspect_sentiments[aspect] = sentiment
                import re
                review_text_lower = review_text.lower()
                if aspect_keywords:
                    # Require all aspects to match
                    all_aspects_match = True
                    for ak in aspect_keywords:
                        if ak not in mapped_aspects:
                            all_aspects_match = False
                            break
                        querywords_for_aspect = aspect_to_querywords.get(ak, set())
                        if not any(re.search(r'\b' + re.escape(qw) + r'\b', review_text_lower) for qw in querywords_for_aspect):
                            all_aspects_match = False
                            break
                    if all_aspects_match:
                        print(f"[DEBUG] Including review: '{review_text}' | matched all aspects: {aspect_keywords}")
                        filtered_reviews.append((review_text, sentiment, mapped_aspects))
                else:
                    # No aspect filter, just sentiment
                    if sentiment == query_sentiment:
                        print(f"[DEBUG] Including review: '{review_text}' | no aspect filter, sentiment matched")
                        filtered_reviews.append((review_text, sentiment, mapped_aspects))
                if sentiment == 'positive' and mapped_aspects:
                    match_score += 1
            # Use filtered reviews for sample_reviews (show only aspects and sentiment that match the query)
            sample_reviews = []
            for review_text, sentiment, mapped_aspects in filtered_reviews:
                relevant_aspects = [ak for ak in aspect_keywords if ak in mapped_aspects]
                # If there are aspects in the query, require relevant_aspects; otherwise, allow all
                if len(sample_reviews) < 3 and review_text and sentiment == query_sentiment:
                    if aspect_keywords:
                        if relevant_aspects:
                            sample_reviews.append({
                                'text': review_text,
                                'sentiment': sentiment,
                                'aspect': ', '.join(relevant_aspects) if relevant_aspects else 'none'
                            })
                    else:
                        sample_reviews.append({
                            'text': review_text,
                            'sentiment': sentiment,
                            'aspect': 'none'
                        })
            # Calculate overall sentiment
            from collections import Counter
            overall_sentiment = Counter(sentiments).most_common(1)[0][0] if sentiments else 'neutral'
            # Only show restaurants with at least one matching review
            if sample_reviews:
                restaurant_list.append({
                    'name': name,
                    'rating': avg_rating,
                    'address': address,
                    'match_score': match_score,
                    'overall_sentiment': overall_sentiment,
                    'aspect_sentiments': aspect_sentiments,
                    'sample_reviews': sample_reviews
                })
        # Sort restaurants by rating
        if query_sentiment == 'negative':
            # For negative queries (e.g., 'worst'), show lowest rated first
            restaurants = sorted(restaurant_list, key=lambda x: (x['rating'] is not None, x['rating']))
        else:
            # For positive/neutral queries, show highest rated first
            restaurants = sorted(restaurant_list, key=lambda x: (x['rating'] is not None, x['rating']), reverse=True)
        print(f"[DEBUG] Number of restaurants to display: {len(restaurants)}")

    return render_template('user_dashboard.html', user=g.user, restaurants=restaurants)


@app.route('/dashboard')
@login_required
def dashboard():
    # If user has a role, redirect to their dashboard
    if g.user:
        if g.user.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif g.user.get('role') == 'user':
            return redirect(url_for('user_dashboard'))
    return render_template('dashboard.html', user=g.user)

@app.route('/sessionLogin', methods=['POST'])
def session_login():
    print("[DEBUG] /sessionLogin endpoint called")
    data = request.get_json()
    id_token = data.get('idToken')
    print(f"[DEBUG] Received idToken: {bool(id_token)}")
    if not id_token:
        print("[DEBUG] No idToken received in /sessionLogin")
        return jsonify({'error': 'Missing idToken'}), 400
    expires_in = 60 * 60 * 24 * 5  # 5 days
    try:
        session_cookie = fb_auth.create_session_cookie(id_token, expires_in=expires_in)
        print("[DEBUG] Session cookie created successfully")
        resp = make_response('', 204)
        resp.set_cookie(
            SESSION_COOKIE_NAME,
            session_cookie,
            max_age=expires_in,
            httponly=True,
            secure=SESSION_COOKIE_SECURE,
            samesite='Lax',
            path='/'
        )
        print("[DEBUG] Session cookie set in response")
        return resp
    except Exception as e:
        print("[DEBUG] Session cookie creation error:", e)
        import traceback; traceback.print_exc()
        return jsonify({'error': 'Failed to create session cookie', 'details': str(e)}), 401
    
# Admin upload reviews route (moved after login_required definition)
@app.route('/admin/upload_reviews', methods=['POST'])
@login_required
def upload_reviews():
    # Only allow active admins
    if not g.user or g.user.get('role') != 'admin' or g.user.get('status') != 'active':
        return "Unauthorized", 403
    if 'reviews_json' not in request.files:
        return "No file part", 400
    file = request.files['reviews_json']
    if file.filename == '':
        return "No selected file", 400
    if not file.filename.lower().endswith('.json'):
        return "Invalid file type. Please upload a JSON file.", 400
    try:
        data = json.load(file)
        if not isinstance(data, list):
            return "JSON must be a list of reviews", 400
        conn = get_db_connection()
        inserted, skipped = insert_reviews_from_list(data, conn)
        conn.close()
        msg = f"Upload complete: {inserted} reviews added, {skipped} skipped (duplicates or invalid)."
        # Fetch updated data for dashboard
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, email FROM users WHERE role='admin' AND status='pending'")
        pending_admins = cur.fetchall()
        cur.execute("SELECT username, email, role FROM users")
        all_users = cur.fetchall()
        cur.close()
        conn.close()
        return render_template('admin_dashboard.html', user=g.user, pending_admins=pending_admins, all_users=all_users, upload_message=msg)
    except Exception as e:
        print('[DEBUG] Error processing uploaded reviews:', e)
        import traceback; traceback.print_exc()
        return f"Error processing file: {e}", 500    

# Admin update predictions route
@app.route('/admin/update_predictions', methods=['POST'])
@login_required
def update_predictions():
    # Only allow active admins
    if not g.user or g.user.get('role') != 'admin' or g.user.get('status') != 'active':
        return "Unauthorized", 403
    try:
        conn = get_db_connection()
        updated, total = backfill_predictions(conn)
        conn.close()
        msg = f"Prediction update complete: {updated} reviews updated out of {total} found needing predictions."
        # Fetch updated data for dashboard
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, email FROM users WHERE role='admin' AND status='pending'")
        pending_admins = cur.fetchall()
        cur.execute("SELECT username, email, role FROM users")
        all_users = cur.fetchall()
        cur.close()
        conn.close()
        return render_template('admin_dashboard.html', user=g.user, pending_admins=pending_admins, all_users=all_users, prediction_message=msg)
    except Exception as e:
        print('[DEBUG] Error updating predictions:', e)
        import traceback; traceback.print_exc()
        return f"Error updating predictions: {e}", 500

# Admin analytics page route
@app.route('/admin/analytics')
@login_required
def admin_analytics():
    conn = get_db_connection()
    cur2 = conn.cursor(dictionary=True)
    cur2.execute("""
        SELECT place_name,
               COUNT(*) as total_reviews,
               SUM(CASE WHEN predicted_sentiment = 'positive' THEN 1 ELSE 0 END) as positive_reviews,
               SUM(CASE WHEN predicted_sentiment = 'negative' THEN 1 ELSE 0 END) as negative_reviews,
               SUM(CASE WHEN predicted_sentiment = 'neutral' THEN 1 ELSE 0 END) as neutral_reviews
        FROM restaurant_reviews
        GROUP BY place_name
        ORDER BY total_reviews DESC
    """)
    sentiment_rows = cur2.fetchall()
    cur2.execute("SELECT place_name, predicted_aspects FROM restaurant_reviews")
    aspect_map = {}
    import json
    for row in cur2.fetchall():
        name = row['place_name']
        aspects = []
        try:
            aspects = json.loads(row['predicted_aspects']) if row['predicted_aspects'] else []
        except Exception:
            pass
        if name not in aspect_map:
            aspect_map[name] = {}
        for asp in aspects:
            aspect_map[name][asp] = aspect_map[name].get(asp, 0) + 1
    analytics_data = []
    for srow in sentiment_rows:
        name = srow['place_name']
        analytics_data.append({
            'place_name': name,
            'total_reviews': srow['total_reviews'],
            'positive_reviews': srow['positive_reviews'],
            'negative_reviews': srow['negative_reviews'],
            'neutral_reviews': srow['neutral_reviews'],
            'aspects': aspect_map.get(name, {})
        })
    cur2.close()
    conn.close()
    return render_template('admin_analytics.html', user=g.user, analytics_data=analytics_data)

@app.route('/user/download_recommendations', methods=['POST'])
def download_recommendations():
    # Only allow if user is logged in and has recommendations
    if not g.user:
        return redirect(url_for('login'))

    # Get restaurants and query from form
    restaurants = None
    query = request.form.get('restaurant_query', '')
    if 'restaurants' in request.form:
        try:
            restaurants = json.loads(request.form['restaurants'])
        except Exception:
            restaurants = None
    if not restaurants:
        return redirect(url_for('user_dashboard'))

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 40
    # Title
    p.setFont("Helvetica-Bold", 20)
    p.setFillColor(colors.HexColor("#667eea"))
    p.drawString(40, y, f"Recommended Restaurants for {g.user.get('username', 'User')}")
    p.setFillColor(colors.black)
    y -= 28
    if query:
        p.setFont("Helvetica-Oblique", 12)
        p.drawString(40, y, f"Search Query: {query}")
        y -= 18
    p.setFont("Helvetica", 12)
    for idx, r in enumerate(restaurants, 1):
        # --- Estimate space needed for this restaurant entry ---
        entry_height = 0
        entry_height += 18  # Restaurant name
        entry_height += 16  # Rating/Address
        entry_height += 16  # Match Score/Sentiment
        aspects = r.get('aspect_sentiments', {})
        if aspects:
            entry_height += 14  # Key Aspects label
            entry_height += 12 * len(aspects)  # Each aspect
        sample_reviews = r.get('sample_reviews', [])
        if sample_reviews:
            entry_height += 14  # Sample Reviews label
            # For each review, estimate wrapped lines
            for review in sample_reviews[:2]:
                review_text = review.get('text', '')
                max_width = width - 120
                words = review_text.split()
                lines = []
                current_line = ''
                for word in words:
                    test_line = (current_line + ' ' + word).strip()
                    if p.stringWidth(test_line, "Helvetica", 12) <= max_width:
                        current_line = test_line
                    else:
                        lines.append(current_line)
                        current_line = word
                if current_line:
                    lines.append(current_line)
                entry_height += 12 * len(lines)
        entry_height += 8  # Space before line
        entry_height += 18  # Space after line

        if y < entry_height + 40:  # 40 is bottom margin
            p.showPage()
            y = height - 40
            p.setFont("Helvetica", 12)

        # Restaurant name bold
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, y, f"{idx}. {r.get('name', 'N/A')}")
        p.setFont("Helvetica", 12)
        y -= 18
        p.drawString(70, y, f"Rating: {r.get('rating', 'N/A')}  |  Address: {r.get('address', 'N/A')}")
        y -= 16
        p.drawString(70, y, f"Match Score: {r.get('match_score', 'N/A')}  |  Sentiment: {r.get('overall_sentiment', 'N/A')}")
        y -= 16
        if aspects:
            p.setFont("Helvetica-Bold", 12)
            p.drawString(70, y, "Key Aspects:")
            p.setFont("Helvetica", 12)
            y -= 14
            for aspect, sentiment in aspects.items():
                p.drawString(90, y, f"- {aspect}: {sentiment}")
                y -= 12
        if sample_reviews:
            p.setFont("Helvetica-Bold", 12)
            p.drawString(70, y, "Sample Reviews:")
            p.setFont("Helvetica", 12)
            y -= 14
            for review in sample_reviews[:2]:
                review_text = review.get('text', '')
                max_width = width - 120
                aspects = review.get('aspect', '')
                # Prepare aspect words for matching
                if isinstance(aspects, list):
                    aspect_words = [a.lower() for a in aspects]
                else:
                    aspect_words = [a.strip().lower() for a in str(aspects).split(',') if a.strip()]
                # Prepare synonyms for aspects
                aspect_synonyms = {}
                try:
                    from mlmodel.train_distilroberta import ASPECT_SYNONYMS
                    aspect_synonyms = ASPECT_SYNONYMS
                except Exception:
                    aspect_synonyms = {}
                all_synonyms = set()
                for aspect in aspect_words:
                    syns = aspect_synonyms.get(aspect, [])
                    all_synonyms.update([s.lower() for s in syns])
                # Prepare query keywords, filter stopwords
                stopwords = set([
                    'the', 'and', 'a', 'an', 'of', 'for', 'to', 'in', 'on', 'at', 'with', 'is', 'are', 'was', 'were', 'be', 'by', 'as', 'it', 'this', 'that', 'from', 'or', 'but', 'so', 'if', 'then', 'than', 'which', 'who', 'what', 'where', 'when', 'how', 'has', 'have', 'had', 'do', 'does', 'did', 'can', 'could', 'should', 'would', 'will', 'just', 'about', 'into', 'out', 'up', 'down', 'over', 'under', 'again', 'more', 'most', 'some', 'such', 'no', 'not', 'only', 'own', 'same', 'too', 'very', 's', 't', 'd', 'll', 'm', 'o', 're', 've', 'y'
                ])
                query_words = [w.lower() for w in query.split() if w.lower() not in stopwords]
                positive_words = set([
                    'good','great','excellent','amazing','delicious','tasty','yummy','wonderful','awesome','perfect','outstanding','fantastic','superb','love','loved','enjoy','enjoyed','pleasant','satisfying','impressive','favorite','best','nice','fresh','friendly','welcoming','happy','recommend','recommended','memorable','top','positive','beautiful','clean','neat','affordable','reasonable','quick','fast','prompt','cozy','peaceful','spacious','helpful','attentive','professional','polite','courteous','responsive','filling','hearty','generous','adequate','enough','well','smooth','fun','funny','entertaining','safe','secure','convenient','accessible','organized','tidy','spotless','sanitary','hygienic','special','unique','creative','modern','stylish','romantic','intimate','lively','calm','bright','cheerful','efficient','value','worth','deal','bargain','discount','offer','special','happy hour','live music','family','kid','play','outdoor','wifi','power','charging','socket','plug','rest area','wash area','handwash','kids area','play area','outdoor seating','non-smoking','first aid','recommendation','will return','come back','regular','expectation','exceeded','met expectations','feedback','review','opinion'
                ])
                negative_words = set([
                    'bad','poor','terrible','awful','disappointing','unpleasant','unhappy','unfriendly','rude','impolite','unhelpful','slow','late','dirty','filthy','messy','crowded','cramped','noisy','loud','expensive','pricey','overpriced','underwhelming','bland','stale','burnt','raw','greasy','oily','dry','overcooked','undercooked','cold','soggy','small','tiny','insufficient','not enough','unorganized','confusing','difficult','problem','issue','complaint','wait','waiting','queue','delay','lag','rush','missing','out of stock','unavailable','broken','unsafe','dangerous','harassment','robbery','lost','forgot','forgotten','wrong','incorrect','mistake','error','negative','dislike','hate','disliked','disappoint','disappointed','disappointing','not recommend','never return','never come back','waste','money','uncomfortable','unpleasant','smell','odor','garbage','trash','waste','leak','spilled','poorly packed','no wifi','no power','no charging','no socket','no plug','no rest area','no wash area','no handwash','no kids area','no play area','no outdoor seating','smoking','no first aid','did not meet','not met','not exceeded','not satisfied','not happy','not impressed','not memorable','not favorite','not best','not top','not positive','not beautiful','not clean','not neat','not affordable','not reasonable','not quick','not fast','not prompt','not cozy','not peaceful','not spacious','not helpful','not attentive','not professional','not polite','not courteous','not responsive','not filling','not hearty','not generous','not adequate','not enough','not well','not smooth','not fun','not funny','not entertaining','not safe','not secure','not convenient','not accessible','not organized','not tidy','not spotless','not sanitary','not hygienic','not special','not unique','not creative','not modern','not stylish','not romantic','not intimate','not lively','not calm','not bright','not cheerful','not efficient','not value','not worth','not deal','not bargain','not discount','not offer','not special','not happy hour','not live music','not family','not kid','not play','not outdoor','not wifi','not power','not charging','not socket','not plug','not rest area','not wash area','not handwash','not kids area','not play area','not outdoor seating','not non-smoking','not first aid','not recommendation','not will return','not come back','not regular','not expectation','not exceeded','not met expectations','not feedback','not review','not opinion'
                ])
                words = review_text.split()
                lines = []
                current_line = ''
                for word in words:
                    test_line = (current_line + ' ' + word).strip()
                    if p.stringWidth(test_line, "Helvetica", 12) <= max_width:
                        current_line = test_line
                    else:
                        lines.append(current_line)
                        current_line = word
                if current_line:
                    lines.append(current_line)
                for i, line in enumerate(lines):
                    x_pos = 90 if i == 0 else 110
                    curr_x = x_pos
                    for w in line.split(' '):
                        w_clean = w.lower().strip('.,!?')
                        is_bold = False
                        if (
                            (w_clean in aspect_words or w_clean in all_synonyms or w_clean in query_words or w_clean in positive_words or w_clean in negative_words)
                            and len(w) == len(w_clean)
                        ):
                            is_bold = True
                        if is_bold:
                            p.setFont("Helvetica-Bold", 12)
                        else:
                            p.setFont("Helvetica", 12)
                        p.drawString(curr_x, y, w)
                        curr_x += p.stringWidth(w + ' ', "Helvetica", 12)
                    y -= 12
                # Bold sentiment and aspects in metadata line
                sentiment = review.get('sentiment', '')
                aspects = review.get('aspect', '')
                meta_x = 110
                meta_line = "Sentiment: "
                p.setFont("Helvetica", 12)
                p.drawString(meta_x, y, meta_line)
                meta_x += p.stringWidth(meta_line, "Helvetica", 12)
                if sentiment:
                    p.setFont("Helvetica-Bold", 12)
                    p.drawString(meta_x, y, sentiment)
                    meta_x += p.stringWidth(sentiment, "Helvetica-Bold", 12)
                p.setFont("Helvetica", 12)
                aspects_label = " | Aspects: "
                p.drawString(meta_x, y, aspects_label)
                meta_x += p.stringWidth(aspects_label, "Helvetica", 12)
                if aspects:
                    # If aspects is a list, join; if string, split by comma
                    if isinstance(aspects, list):
                        aspect_list = aspects
                    else:
                        aspect_list = [a.strip() for a in str(aspects).split(",") if a.strip()]
                    for idx, aspect in enumerate(aspect_list):
                        p.setFont("Helvetica-Bold", 12)
                        p.drawString(meta_x, y, aspect)
                        meta_x += p.stringWidth(aspect, "Helvetica-Bold", 12)
                        if idx < len(aspect_list) - 1:
                            p.setFont("Helvetica", 12)
                            p.drawString(meta_x, y, ", ")
                            meta_x += p.stringWidth(", ", "Helvetica", 12)
                y -= 12
        # Draw a line between restaurants
        y -= 8
        p.setStrokeColor(colors.HexColor("#667eea"))
        p.setLineWidth(0.7)
        p.line(50, y, width - 50, y)
        y -= 18
        p.setStrokeColor(colors.black)
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="recommendations.pdf", mimetype='application/pdf')

@app.route('/sessionLogout', methods=['POST'])
@app.route('/logout', methods=['GET'])
def session_logout():
    resp = make_response(redirect(url_for('login')) if request.method == 'GET' else ('', 204))
    resp.set_cookie(SESSION_COOKIE_NAME, '', expires=0, path='/')
    return resp

if __name__ == '__main__':
    app.run(debug=True)
