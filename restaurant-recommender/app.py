import os
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
    cur = conn.cursor()
    cur.execute('SELECT username, role, status FROM users WHERE firebase_uid = %s', (firebase_uid,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    if result:
        return {'username': result[0], 'role': result[1], 'status': result[2]}
    return None

# MySQL config (update with your credentials)
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
MYSQL_DB = os.environ.get('MYSQL_DB', 'restaurant_db')

def get_db_connection():
    return mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB
    )
def get_user_role(firebase_uid):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT role FROM users WHERE firebase_uid = %s', (firebase_uid,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    if result:
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
    cur.close()
    conn.close()
    return render_template('admin_dashboard.html', user=g.user, pending_admins=pending_admins)
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
