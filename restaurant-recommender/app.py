import os
import json
import json
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, g
import mysql.connector
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import auth as fb_auth, credentials
from itsdangerous import URLSafeTimedSerializer

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
    cur.close()
    conn.close()
    return render_template('admin_dashboard.html', user=g.user, pending_admins=pending_admins, all_users=all_users)
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
    
    
    
@app.route('/sessionLogout', methods=['POST'])
@app.route('/logout', methods=['GET'])
def session_logout():
    resp = make_response(redirect(url_for('login')) if request.method == 'GET' else ('', 204))
    resp.set_cookie(SESSION_COOKIE_NAME, '', expires=0, path='/')
    return resp

if __name__ == '__main__':
    app.run(debug=True)
