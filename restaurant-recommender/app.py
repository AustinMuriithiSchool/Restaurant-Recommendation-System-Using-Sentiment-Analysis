"""
Restaurant Recommender - Minimal Flask + Firebase Auth Example

How to run:

python -m venv .venv && source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env  # then edit values and place service account json
flask --app app.py --debug run

firebase_service_account.json is downloaded from Firebase Console > Project Settings > Service Accounts.
"""
import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, g
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import auth as fb_auth, credentials
from itsdangerous import URLSafeTimedSerializer

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev')
app.config['SESSION_COOKIE_NAME'] = os.environ.get('SESSION_COOKIE_NAME', '__session')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
        user = verify_session()
        if not user:
            return redirect(url_for('login'))
        g.user = user
        return f(*args, **kwargs)
    return decorated

@app.before_request
def load_user():
    g.user = verify_session()

@app.route('/')
def index():
    if g.user:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html', user=g.user)

@app.route('/register')
def register():
    return render_template('register.html', user=g.user)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=g.user)

@app.route('/sessionLogin', methods=['POST'])
def session_login():
    data = request.get_json()
    id_token = data.get('idToken')
    if not id_token:
        return jsonify({'error': 'Missing idToken'}), 400
    expires_in = 60 * 60 * 24 * 5  # 5 days
    try:
        session_cookie = fb_auth.create_session_cookie(id_token, expires_in=expires_in)
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
        return resp
    except Exception as e:
        print("Session cookie creation error:", e)
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
