from flask import Flask, render_template, session, redirect, url_for, request, flash
import MySQLdb  # mysqlclient
from logInFunctions.auth import authenticate
from emailScripts import welcomeEmail
from emailScripts.logInEmail import send_login_email
from emailScripts import applicationEmail
from emailScripts import driverAddPointsEmail
from emailScripts.driverRemovePointsEmail import send_points_removed_email
from createUser import _create_user_in_table
from emailScripts.resetEmail import send_reset_email
from emailScripts.decisionEmail import send_decision_email
from emailScripts.lockEmail import send_lock_email
from emailScripts.driverDroppedEmail import send_driver_dropped_email
from emailScripts.lowBalanceEmail import send_low_balance_email
from emailScripts.spendPointsEmail import send_spent_points_email
from emailScripts.sponsorLockedEmail import send_sponsor_locked_email
import secrets
import os
import csv
from io import StringIO
from flask import Response
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from flask import jsonify
import os, time, json, base64
import hashlib
import hmac
from urllib import request as urlreq
from urllib import parse as urlparse


app = Flask(__name__)
#maybe make this more secret somehow?
app.secret_key = os.urandom(24)

# --- Database configuration ---
db_config = {
    'host': 'cpsc4910-f25.cobd8enwsupz.us-east-1.rds.amazonaws.com',
    'user': 'Team16',
    'passwd': 'Tlaw16',  
    'db': 'Team16_DB',
    'charset': 'utf8'
}

# --- Upload configuration ---
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pics'
app.config['LOGO_UPLOAD_FOLDER'] = 'static/uploads/company_logos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Auto-promotion helper: Processing -> Shipped after 60s ---
def _promote_processing_to_shipped(db):
    cur = db.cursor()
    cur.execute("""
        UPDATE orders
        SET status='Shipped'
        WHERE status='Processing'
          AND TIMESTAMPDIFF(MINUTE, order_date, NOW()) >= 5
    """)
    db.commit()
    cur.close()

def _promote_shipped_to_delivered(db):
    cur = db.cursor()
    cur.execute("""
        UPDATE orders
        SET status='Delivered'
        WHERE status='Shipped'
          AND DATE(NOW()) >= DATE(order_date + INTERVAL 7 DAY)
    """)
    db.commit()
    cur.close()

EBAY_ENV = os.getenv("EBAY_ENV", "sandbox").lower()
EBAY_BASE_URL = "https://api.sandbox.ebay.com" if EBAY_ENV == "sandbox" else "https://api.ebay.com"
EBAY_CLIENT_ID = os.getenv("EBAY_CLIENT_ID")
EBAY_CLIENT_SECRET = os.getenv("EBAY_CLIENT_SECRET")
EBAY_MARKETPLACE_ID = os.getenv("EBAY_MARKETPLACE_ID", "EBAY_US")

class EbayClient:
    _token = None
    _token_exp = 0

    def _have_valid_token(self):
        return self._token and time.time() < (self._token_exp - 60)

    def _refresh_token(self):
        if not EBAY_CLIENT_ID or not EBAY_CLIENT_SECRET:
            raise RuntimeError("Missing EBAY_CLIENT_ID/EBAY_CLIENT_SECRET")
        url = f"{EBAY_BASE_URL}/identity/v1/oauth2/token"
        data = urlparse.urlencode({
            "grant_type": "client_credentials",
            "scope": "https://api.ebay.com/oauth/api_scope"
        }).encode("utf-8")

        basic = base64.b64encode(f"{EBAY_CLIENT_ID}:{EBAY_CLIENT_SECRET}".encode()).decode()
        req = urlreq.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Authorization", f"Basic {basic}")

        with urlreq.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        self._token = payload["access_token"]
        self._token_exp = time.time() + int(payload.get("expires_in", 7200))

    def _headers(self):
        if not self._have_valid_token():
            self._refresh_token()
        return {
            "Authorization": f"Bearer {self._token}",
            "X-EBAY-C-MARKETPLACE-ID": EBAY_MARKETPLACE_ID
        }

    def _get_json(self, url):
        req = urlreq.Request(url, method="GET")
        for k, v in self._headers().items():
            req.add_header(k, v)
        with urlreq.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def search(self, q, limit=20, category_ids=None, filters=None, offset=0):
        params = {"q": q, "limit": str(limit), "offset": str(offset)}
        if category_ids:
            params["category_ids"] = category_ids
        if filters:
            params["filter"] = filters  # e.g. price:[50..300],conditions:{NEW},buyingOptions:{FIXED_PRICE}
        url = f"{EBAY_BASE_URL}/buy/browse/v1/item_summary/search?{urlparse.urlencode(params)}"
        return self._get_json(url)

    def item_detail(self, item_id):
        url = f"{EBAY_BASE_URL}/buy/browse/v1/item/{item_id}"
        return self._get_json(url)

ebay = EbayClient()

# --- Route to logout inactive users ---
@app.before_request
def auto_logout_inactive_users():
    """
    Automatically log out users after 15 minutes of inactivity.
    """
    app.permanent_session_lifetime = timedelta(minutes=15)
    session.modified = True

    if 'user' in session and 'role' in session:
        now = datetime.now(timezone.utc)  # always timezone-aware UTC

        last = session.get('last_activity')
        if isinstance(last, str):
            # Convert string back to datetime if Flask serialized it
            try:
                last = datetime.fromisoformat(last)
            except Exception:
                last = None

        # Compare safely (normalize to UTC)
        if isinstance(last, datetime):
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if now - last > timedelta(minutes=15):
                # Remove only user info, keep flash storage alive
                flash("You were logged out due to inactivity.", "warning")
                session.pop('user', None)
                session.pop('role', None)
                session.pop('last_activity', None)
                
                return redirect(url_for('login'))

        # Store as ISO string (portable)
        session['last_activity'] = now.isoformat()

@app.get("/api/sponsor/ebay/search")
def sponsor_ebay_search():
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    q = request.args.get("q")
    if not q:
        return jsonify({"error": "Missing ?q"}), 400

    limit = int(request.args.get("limit", 20))
    offset = int(request.args.get("offset", 0))
    category_ids = request.args.get("category_ids")
    filters = request.args.get("filter")

    try:
        data = ebay.search(q=q, limit=limit, category_ids=category_ids, filters=filters, offset=offset)
    except Exception as e:
        return jsonify({"error": f"eBay search failed: {e}"}), 502

    items = []
    for s in data.get("itemSummaries", []):
        items.append({
            "itemId": s.get("itemId"),
            "title": s.get("title"),
            "price": s.get("price"),
            "image": (s.get("image") or {}).get("imageUrl"),
            "buyingOptions": s.get("buyingOptions"),
            "condition": s.get("condition"),
            "seller": (s.get("seller") or {}).get("username"),
        })
    return jsonify({"total": data.get("total", 0), "items": items})

@app.post("/api/sponsor/catalog/add")
def sponsor_add_to_catalog():
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    body = request.get_json(silent=True) or {}
    item_id = body.get("item_id")
    points_cost = body.get("points_cost")
    quantity = body.get("quantity_limit")  # stored in products.quantity
    sponsor_name = session['user']

    if not item_id or points_cost is None:
        return jsonify({"error": "item_id and points_cost are required"}), 400

    # Fetch detail to cache title/image/price
    try:
        d = ebay.item_detail(item_id)
    except Exception as e:
        return jsonify({"error": f"eBay item lookup failed: {e}"}), 502

    title = (d.get("title") or "Untitled")[:255]
    image_url = (d.get("image") or {}).get("imageUrl")
    price = d.get("price") or {}
    price_value = price.get("value")
    price_currency = price.get("currency")

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO products
                (name, sponsor, points_cost, quantity, source_type, ebay_item_id, image_url, price_value, price_currency)
            VALUES
                (%s,   %s,      %s,          %s,       'ebay',      %s,           %s,        %s,           %s)
            """,
            (title, sponsor_name, int(points_cost), int(quantity) if quantity is not None else 0,
             d.get("itemId"), image_url, price_value, price_currency)
        )
        db.commit()
        cursor.execute("SELECT LAST_INSERT_ID() AS id;")
        new_id = cursor.fetchone()[0]
        cursor.close(); db.close()
    except Exception as e:
        return jsonify({"error": f"Database error inserting product: {e}"}), 500

    return jsonify({
        "ok": True,
        "product": {
            "product_id": new_id,
            "name": title,
            "sponsor": sponsor_name,
            "points_cost": int(points_cost),
            "quantity": int(quantity) if quantity is not None else 0,
            "source_type": "ebay",
            "image_url": image_url,
            "price": {"value": price_value, "currency": price_currency},
            "ebay_item_id": d.get("itemId")
        }
    })


@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about')
def about():
    try:
        # Connect to database
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Fetch all rows from 'about' table
        cursor.execute("SELECT * FROM about;")
        rows = cursor.fetchall()

        cursor.close()
        db.close()
    except Exception as e:
        return f"<h1>Database Error:</h1><p>{e}</p>"

    # Render template dynamically
    return render_template('about.html', rows=rows)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        MAX_ATTEMPTS = 5  # lock after 5 failed attempts

        # Hashing Password
        password = sha256_of_string(password)
        
        # Try to authenticate
        role, user_row = authenticate(username, password)

        # If login is successful starts session & redirects and sends email
        if role:
            session['user'] = username
            session['role'] = role

            # --- Check if user is disabled ---
            db = MySQLdb.connect(**db_config)
            cursor = db.cursor(MySQLdb.cursors.DictCursor)

            if role == 'driver':
                cursor.execute("SELECT disabled, disabled_by_admin FROM drivers WHERE username=%s", (username,))
            elif role == 'sponsor':
                cursor.execute("SELECT disabled, disabled_by_admin FROM sponsor WHERE username=%s", (username,))
            elif role == 'admin':
                cursor.execute("SELECT disabled, disabled_by_admin FROM admins WHERE username=%s", (username,))
            else:
                cursor.close()
                db.close()
                return redirect(url_for('login'))

            status = cursor.fetchone()
            cursor.close()
            db.close()

            if status and status['disabled']:
                session['disabled'] = True
                if status['disabled_by_admin']:
                    return redirect('/disabled_account?reason=admin')
                else:
                    return redirect('/disabled_account?reason=self')
            else:
                session['disabled'] = False

            # --- Send login email ---
            db = MySQLdb.connect(**db_config)
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("""
                SELECT email, 'driver' AS role FROM drivers WHERE username=%s
                UNION ALL
                SELECT email, 'sponsor' AS role FROM sponsor WHERE username=%s
                UNION ALL
                SELECT email, 'admin' AS role FROM admins WHERE username=%s
                LIMIT 1
            """, (username, username, username))
            r = cursor.fetchone()
            cursor.close(); db.close()

            if r and r.get('email'):
                send_login_email(r['email'], username)

            # --- Redirect based on role ---
            if role == 'driver':
                session['show_feedback_modal'] = True
                return redirect(url_for('driver_profile'))
            elif role == 'admin':
                return redirect(url_for('admin_profile'))
            elif role == 'sponsor':
                session['show_feedback_modal'] = True
                return redirect(url_for('sponsor_profile'))

        # ❌ Failed login
        try:
            db = MySQLdb.connect(**db_config)
            cursor = db.cursor(MySQLdb.cursors.DictCursor)

            # Increment failed_attempts for sponsor accounts
            cursor.execute("SELECT failed_attempts, locked_until FROM sponsor WHERE username=%s", (username,))
            sponsor = cursor.fetchone()

            if sponsor:
                failed_attempts = int(sponsor.get('failed_attempts') or 0) + 1
                cursor.execute("UPDATE sponsor SET failed_attempts=%s WHERE username=%s", (failed_attempts, username))
                db.commit()

                # Lock sponsor after too many attempts
                if failed_attempts >= MAX_ATTEMPTS:
                    locked_until = datetime.now() + timedelta(minutes=15)
                    cursor.execute("""
                        UPDATE sponsor
                        SET locked_until=%s, disabled=TRUE
                        WHERE username=%s
                    """, (locked_until, username))
                    db.commit()

                    # Get admin emails
                    cursor.execute("SELECT email FROM admins")
                    admins = cursor.fetchall()
                    locked_str = locked_until.strftime('%b %d, %Y %I:%M:%S %p')

                    # Send admin alert
                    for admin in admins:
                        send_sponsor_locked_email(admin['email'], username, locked_str)

                    flash("Your account has been locked due to too many failed login attempts.", "danger")
                    cursor.close(); db.close()
                    return render_template("login.html", error="Account locked.", last_username=username)
                else:
                    remaining = MAX_ATTEMPTS - failed_attempts
                    flash(f"Incorrect password. {remaining} attempts remaining before lockout.", "warning")

            cursor.close(); db.close()
        except Exception as e:
            print(f"[Error] Login failure tracking: {e}")

        # --- Check if already locked ---
        locked_until = None
        try:
            db = MySQLdb.connect(**db_config)
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT locked_until FROM sponsor WHERE username=%s", (username,))
            row = cursor.fetchone()
            if row and row.get('locked_until') and row['locked_until'] > datetime.now():
                locked_until = row['locked_until']
            cursor.close(); db.close()
        except Exception:
            pass

        if locked_until:
            # Send lock email to sponsor (optional)
            locked_str = locked_until.strftime('%b %d, %Y %I:%M:%S %p')
            try:
                db = MySQLdb.connect(**db_config)
                cursor = db.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("SELECT email FROM sponsor WHERE username=%s", (username,))
                r = cursor.fetchone()
                if r and r.get('email'):
                    send_lock_email(r['email'], username, 'sponsor', locked_str)
                cursor.close(); db.close()
            except Exception as e:
                print(f"[Warning] Failed to send sponsor lock email: {e}")

            msg = f"Your account is locked until {locked_str}. Please try again later."
        else:
            msg = "Invalid username or password."

        return render_template("login.html", error=msg, last_username=username)

    # GET request → render blank login form
    return render_template("login.html")

@app.route('/disabled_account')
def disabled_account():
    reason = request.args.get('reason', 'self')  # either 'admin' or 'self'
    return render_template('disabled_account.html', reason=reason)

@app.route('/reactivate_account', methods=['POST'])
def reactivate_account():
    role = session.get('role')
    username = session.get('user')
    if not role or not username:
        flash("Session expired. Please log in again.")
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # check who disabled
    if role == 'driver':
        cursor.execute("SELECT disabled_by_admin FROM drivers WHERE username=%s", (username,))
    elif role == 'sponsor':
        cursor.execute("SELECT disabled_by_admin FROM sponsor WHERE username=%s", (username,))
    elif role == 'admin':
        cursor.execute("SELECT disabled_by_admin FROM admins WHERE username=%s", (username,))
    else:
        cursor.close(); db.close()

    result = cursor.fetchone()
    if result and result['disabled_by_admin']:
        cursor.close(); db.close()
        flash("Your account was disabled by an administrator. Please contact support.")
        return redirect('/disabled_account?reason=admin')

    # reactivate (self-disabled)
    if role == 'driver':
        cursor.execute("UPDATE drivers SET disabled=FALSE WHERE username=%s", (username,))
    elif role == 'sponsor':
        cursor.execute("UPDATE sponsor SET disabled=FALSE WHERE username=%s", (username,))
    else:  # admin
        cursor.execute("UPDATE admins SET disabled=FALSE WHERE username=%s", (username,))

    db.commit()
    cursor.close(); db.close()

    session['disabled'] = False
    flash("Your account has been reactivated successfully.")
    return redirect(url_for(f'{role}_profile'))

@app.route('/disable_self', methods=['POST'])
def disable_self():
    role = session.get('role')
    username = session.get('user')
    if not role or not username:
        flash("Session expired. Please log in again.")
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    if role == 'driver':
        cursor.execute("UPDATE drivers SET disabled=TRUE, disabled_by_admin=FALSE WHERE username=%s", (username,))
    elif role == 'sponsor':
        cursor.execute("UPDATE sponsor SET disabled=TRUE, disabled_by_admin=FALSE WHERE username=%s", (username,))
    elif role == 'admin':
        cursor.execute("UPDATE admins  SET disabled=TRUE, disabled_by_admin=FALSE WHERE username=%s", (username,))
    else:
        cursor.close(); db.close()

    db.commit()
    cursor.close(); db.close()

    session['disabled'] = True
    flash("Your account has been disabled.")
    return redirect('/disabled_account?reason=self')


@app.route('/toggle_account/<role>/<username>', methods=['POST'])
def toggle_account(role, username):
    action = request.form.get('action')  # 'disable' or 'enable'
    
    value = (action == 'disable')
    admin_flag = (action == 'disable')

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    if role == 'driver':
        cursor.execute("UPDATE drivers SET disabled=%s, disabled_by_admin=%s WHERE username=%s",
                       (value, admin_flag, username))
    elif role == 'sponsor':
        cursor.execute("UPDATE sponsor SET disabled=%s, disabled_by_admin=%s WHERE username=%s",
                       (value, admin_flag, username))
    else:  # admin
        cursor.execute("UPDATE admins  SET disabled=%s, disabled_by_admin=%s WHERE username=%s",
                       (value, admin_flag, username))

    db.commit()
    cursor.close(); db.close()

    flash(f"{role.capitalize()} '{username}' has been {'disabled' if value else 're-enabled'}.")
    return redirect(url_for('admin_profile'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()  # Clear all session data
    flash("You have been logged out.")
    return redirect(url_for('login'))    

# --- PROFILE ROUTES ---

@app.route('/driver/profile', methods=['GET', 'POST'])
def driver_profile():
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        address = request.form['address']
        phone = request.form['phone']

        cursor.execute("""
            UPDATE drivers 
            SET first_name=%s, last_name=%s, address=%s, phone=%s
            WHERE username=%s
        """, (first_name, last_name, address, phone, username))
        db.commit()

    cursor.execute("SELECT * FROM drivers WHERE username=%s", (username,))
    user_info = cursor.fetchone()

    cursor.close()
    db.close()

    return render_template("driver_profile.html", user=user_info)


@app.route('/sponsor/profile', methods=['GET', 'POST'])
def sponsor_profile():
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # --- Get sponsor information ---
    cursor.execute("SELECT * FROM sponsor WHERE username=%s", (username,))
    user_info = cursor.fetchone()

    # --- Sponsorship stats ---
    cursor.execute("""
        SELECT COUNT(*) AS driver_count
        FROM driverApplications
        WHERE sponsor=%s AND status='accepted'
    """, (username,))
    driver_count = cursor.fetchone()['driver_count']

    cursor.execute("""
        SELECT COALESCE(SUM(points),0) AS total_points
        FROM driver_sponsor_points
        WHERE sponsor=%s
    """, (username,))
    total_points = cursor.fetchone()['total_points'] or 0

    # --- Driver list for sponsor (per-sponsor points) ---
    cursor.execute("""
        SELECT d.username, d.first_name, d.last_name,
            COALESCE(dsp.points,0) AS points
        FROM driverApplications da
        JOIN drivers d ON d.username = da.driverUsername
        LEFT JOIN driver_sponsor_points dsp
        ON dsp.driver_username = da.driverUsername
        AND dsp.sponsor = da.sponsor
        WHERE da.sponsor=%s AND da.status='accepted'
        ORDER BY points DESC
    """, (username,))
    driver_list = cursor.fetchall()


    cursor.close()
    db.close()

    # Only display info, not update
    return render_template(
        "sponsor_profile.html",
        user=user_info,
        driver_count=driver_count,
        total_points=total_points,
        driver_list=driver_list
    )
    


@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # ===================================================================
    # SPRINT 4 CHANGE: FETCH ADMIN DASHBOARD DATA
    # These queries get the summary metrics for the entire system.
    # ===================================================================
    cursor.execute("SELECT COUNT(*) as total_drivers FROM drivers;")
    total_drivers = cursor.fetchone()['total_drivers']
    cursor.execute("SELECT SUM(points) as total_points FROM drivers;")
    total_points_given = cursor.fetchone()['total_points'] or 0
    cursor.execute("SELECT COUNT(*) as total_sponsors FROM sponsor;")
    total_sponsors = cursor.fetchone()['total_sponsors']
    # ===================================================================


    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone = request.form['phone']

        cursor.execute("""
            UPDATE admins
            SET first_name=%s, last_name=%s, phone=%s
            WHERE username=%s
        """, (first_name, last_name, phone, username))
        db.commit()

    cursor.execute("SELECT * FROM admins WHERE username=%s", (username,))
    user_info = cursor.fetchone()

    cursor.close()
    db.close()

    return render_template("admin_profile.html", user=user_info, total_drivers=total_drivers, total_points_given=total_points_given, total_sponsors=total_sponsors)


@app.route('/dashboard')
def dashboard():
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        active = _get_active_sponsor(username)
        points_balance = _get_points(username, active) if active else 0

        # Keep audit log history
        cursor.execute("""
            SELECT timestamp, action, description
            FROM auditLogs
            WHERE (action='add points' OR action='remove points')
            AND (
                    description LIKE %s
                OR description LIKE %s
            )
            ORDER BY timestamp DESC
            LIMIT 50
        """, (f'% to {username}%', f'% from {username}%'))
        history = cursor.fetchall()

        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Database error:</h2><p>{e}</p>"

    return render_template("dashboard.html",
                           points_balance=points_balance,
                           history=history)

@app.get("/cart")
def cart_page():
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']
    active_sponsor = _get_active_sponsor(username)
    if not active_sponsor:
        return render_template("cart.html", items=[], points_balance=0, total_points=0)

    try:
        db = MySQLdb.connect(**db_config)
        cur = db.cursor(MySQLdb.cursors.DictCursor)

        points_balance = _get_points(username, active_sponsor)

        cur.execute("""
            SELECT ci.product_id, ci.quantity,
                   p.name, p.points_cost, p.image_url, p.quantity AS stock
            FROM cart_items ci
            JOIN products p ON p.product_id = ci.product_id
            WHERE ci.driver_username=%s AND ci.sponsor=%s
            ORDER BY p.name ASC
        """, (username, active_sponsor))
        items = cur.fetchall()

        cur.close(); db.close()
    except Exception as e:
        return f"<h3>Database error loading cart: {e}</h3>"

    total_points = sum(int(i['points_cost'] or 0) * int(i['quantity'] or 0) for i in items)
    return render_template("cart.html", items=items, points_balance=points_balance, total_points=total_points)


@app.post("/cart/checkout")
def cart_checkout():
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']
    active_sponsor = _get_active_sponsor(username)
    if not active_sponsor:
        return "<h3>No active sponsor selected.</h3>"

    try:
        db = MySQLdb.connect(**db_config)
        cur = db.cursor(MySQLdb.cursors.DictCursor)

        driver_points = _get_points(username, active_sponsor)

        cur.execute("""
            SELECT ci.product_id, ci.quantity AS qty,
                   p.name, p.points_cost, p.quantity AS stock
            FROM cart_items ci
            JOIN products p ON p.product_id = ci.product_id
            WHERE ci.driver_username=%s AND ci.sponsor=%s
            ORDER BY p.name ASC
        """, (username, active_sponsor))
        cart = cur.fetchall()

        if not cart:
            cur.close(); db.close()
            return redirect(url_for('cart_page'))

        total_points = 0
        for line in cart:
            if int(line['qty']) <= 0 or int(line['stock']) < int(line['qty']):
                cur.close(); db.close()
                return "<h3>Not enough stock for one or more items in your cart.</h3>"
            total_points += int(line['points_cost']) * int(line['qty'])

        if driver_points < total_points:
            cur.close(); db.close()
            return "<h3>You don't have enough points with this sponsor.</h3>"

        db.autocommit(False)
        try:
            # Deduct per-sponsor points
            cur.execute("""
                UPDATE driver_sponsor_points
                SET points = points - %s
                WHERE driver_username=%s AND sponsor=%s
            """, (total_points, username, active_sponsor))

            # Create orders, decrement stock
            for line in cart:
                cur.execute("""
                    INSERT INTO orders (user_id, product_id, sponsor, reward_description, point_cost, quantity, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'Processing')
                """, (
                    username,
                    int(line['product_id']),
                    active_sponsor,
                    line['name'],
                    int(line['points_cost']) * int(line['qty']),
                    int(line['qty']),
                ))

                cur.execute("""
                    UPDATE products
                    SET quantity = quantity - %s
                    WHERE product_id=%s
                """, (int(line['qty']), int(line['product_id'])))

            # Clear only this sponsor's cart lines
            cur.execute("DELETE FROM cart_items WHERE driver_username=%s AND sponsor=%s",
                        (username, active_sponsor))

            db.commit()

            cur.execute("SELECT email, points FROM drivers WHERE username=%s", (username,))
            row = cur.fetchone()
            if row:
                # Send "spent points" email
                send_spent_points_email(row['email'], username, total_points)

                # Send "low balance" email if < 10 points
                pts = int(row['points'])
                if pts < 50:
                    send_low_balance_email(row['email'], username, pts, 50)
        except Exception as e:
            db.rollback()
            cur.close(); db.close()
            return f"<h3>Checkout failed: {e}</h3>"

        cur.close(); db.close()
        return redirect(url_for('orders_page'))

    except Exception as e:
        return f"<h3>Database error during checkout: {e}</h3>"


@app.get("/orders")
def orders_page():
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)

    # Promote statuses
    _promote_processing_to_shipped(db)
    _promote_shipped_to_delivered(db)

    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # Per-sponsor balance for active sponsor
    active_sponsor = _get_active_sponsor(username)
    points_balance = _get_points(username, active_sponsor) if active_sponsor else 0

    # Load orders (all sponsors is fine here)
    cur.execute("""
        SELECT order_id, product_id, reward_description, point_cost, quantity, status,
               DATE(order_date) AS order_date, DATE(order_date + INTERVAL 7 DAY) AS expected_date
        FROM orders
        WHERE user_id=%s
        ORDER BY order_date DESC, order_id DESC
    """, (username,))
    orders = cur.fetchall()

    cur.close(); db.close()
    return render_template("orders.html", orders=orders, points_balance=points_balance)



@app.post("/orders/<int:order_id>/cancel")
def orders_cancel(order_id):
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)

    # ➊ Promote eligible orders before we check status
    _promote_processing_to_shipped(db)

    cur = db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT order_id, user_id, product_id, point_cost, quantity, status
        FROM orders
        WHERE order_id=%s
    """, (order_id,))
    o = cur.fetchone()

    if not o or o['user_id'] != username:
        cur.close(); db.close()
        return "<h3>Order not found.</h3>"

    # ➋ Block refund if no longer Processing (i.e., Shipped or other)
    if o['status'] != 'Processing':
        cur.close(); db.close()
        return "<h3>This order can no longer be cancelled (already shipped).</h3>"

    try:
        db.autocommit(False)

        # 1) Mark as Cancelled
        cur.execute("UPDATE orders SET status='Cancelled' WHERE order_id=%s", (order_id,))

        # 2) Refund points to driver
        cur.execute("UPDATE drivers SET points = points + %s WHERE username=%s",
                    (int(o['point_cost']), username))

        # 3) Restock if product still exists (it may have been deleted at checkout)
        cur.execute("SELECT product_id FROM products WHERE product_id=%s", (o['product_id'],))
        exists = cur.fetchone()
        if exists:
            cur.execute("""
                UPDATE products SET quantity = quantity + %s
                WHERE product_id=%s
            """, (int(o['quantity']), o['product_id']))

        db.commit()
    except Exception as e:
        db.rollback()
        cur.close(); db.close()
        return f"<h3>Cancel failed: {e}</h3>"

    cur.close(); db.close()
    return redirect(url_for('orders_page'))

def _get_driver_accepted_sponsors(username):
    """List of sponsors this driver is accepted with (from driverApplications)."""
    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT sponsor
        FROM driverApplications
        WHERE driverUsername=%s AND status='accepted'
        ORDER BY sponsor ASC
    """, (username,))
    rows = cur.fetchall()
    cur.close(); db.close()
    return [r['sponsor'] for r in rows]

def _get_active_sponsor(username):
    """
    Active sponsor for the driver: ?sponsor=... > session > first accepted.
    Stores the chosen value in session['active_sponsor'].
    """
    sel = request.args.get('sponsor')
    if sel:
        session['active_sponsor'] = sel
        return sel
    if session.get('active_sponsor'):
        return session['active_sponsor']
    accepted = _get_driver_accepted_sponsors(username)
    if accepted:
        session['active_sponsor'] = accepted[0]
        return accepted[0]
    return None

def _get_points(username, sponsor):
    """Per-sponsor balance from driver_sponsor_points."""
    if not sponsor:
        return 0
    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT points FROM driver_sponsor_points
        WHERE driver_username=%s AND sponsor=%s
    """, (username, sponsor))
    row = cur.fetchone()
    cur.close(); db.close()
    return int(row['points']) if row and row['points'] is not None else 0

def _add_points(username, sponsor, delta):
    """Adds (or subtracts) points for (driver, sponsor)."""
    db = MySQLdb.connect(**db_config)
    cur = db.cursor()
    cur.execute("""
        INSERT INTO driver_sponsor_points (driver_username, sponsor, points)
        VALUES (%s,%s,%s)
        ON DUPLICATE KEY UPDATE points = GREATEST(0, points + VALUES(points))
    """, (username, sponsor, int(delta)))
    db.commit()
    cur.close(); db.close()


@app.post("/api/driver/favorites/add")
def fav_add():
    if 'user' not in session or session.get('role') != 'driver':
        return jsonify({"ok": False, "error": "auth"}), 403
    username = session['user']
    pid = (request.get_json(silent=True) or {}).get("product_id")
    if not pid: 
        return jsonify({"ok": False, "error": "product_id required"}), 400

    db = MySQLdb.connect(**db_config)
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO favorites (driver_username, product_id)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE created_at=NOW()
        """, (username, int(pid)))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        cur.close(); db.close()


@app.post("/api/driver/favorites/remove")
def fav_remove():
    if 'user' not in session or session.get('role') != 'driver':
        return jsonify({"ok": False, "error": "auth"}), 403
    username = session['user']
    pid = (request.get_json(silent=True) or {}).get("product_id")
    if not pid: 
        return jsonify({"ok": False, "error": "product_id required"}), 400

    db = MySQLdb.connect(**db_config)
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM favorites WHERE driver_username=%s AND product_id=%s",
                    (username, int(pid)))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        cur.close(); db.close()


@app.post("/api/driver/cart/add")
def driver_cart_add():
    if 'user' not in session or session.get('role') != 'driver':
        return jsonify({"ok": False, "error": "auth"}), 403

    body = request.get_json(silent=True) or {}
    product_id = body.get("product_id")
    qty = int(body.get("quantity", 1))
    if not product_id or qty < 1:
        return jsonify({"ok": False, "error": "product_id and quantity>=1 required"}), 400

    username = session['user']
    active_sponsor = _get_active_sponsor(username)
    if not active_sponsor:
        return jsonify({"ok": False, "error": "You must be accepted by a sponsor first."}), 403

    # Ensure driver is accepted with active sponsor
    if active_sponsor not in _get_driver_accepted_sponsors(username):
        return jsonify({"ok": False, "error": "Not accepted with this sponsor."}), 403

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # Product must belong to the active sponsor
    cur.execute("SELECT product_id, sponsor, quantity FROM products WHERE product_id=%s", (product_id,))
    prod = cur.fetchone()
    if not prod:
        cur.close(); db.close()
        return jsonify({"ok": False, "error": "Product not found"}), 404
    if prod['sponsor'] != active_sponsor:
        cur.close(); db.close()
        return jsonify({"ok": False, "error": "Product is not offered by the active sponsor"}), 403

    available = int(prod['quantity'] or 0)
    if available <= 0:
        cur.close(); db.close()
        return jsonify({"ok": False, "error": "Out of stock"}), 409
    qty = min(qty, available)

    try:
        cur.execute("""
            INSERT INTO cart_items (driver_username, product_id, sponsor, quantity)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE quantity = LEAST(quantity + VALUES(quantity), %s)
        """, (username, int(product_id), active_sponsor, qty, available))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": f"DB error: {e}"}), 500
    finally:
        cur.close(); db.close()


@app.get("/api/products/<int:product_id>/reviews")
def product_reviews(product_id):
    if 'user' not in session or session.get('role') != 'driver':
        return jsonify({"ok": False, "error": "auth"}), 403

    try:
        db = MySQLdb.connect(**db_config)
        cur = db.cursor(MySQLdb.cursors.DictCursor)

        # Reviews list
        cur.execute("""
            SELECT review_id, driver_username, rating, title, body,
                   DATE(created_at) AS created_date
            FROM reviews
            WHERE product_id=%s
            ORDER BY created_at DESC
        """, (product_id,))
        reviews = cur.fetchall()

        # Aggregate
        cur.execute("""
            SELECT AVG(rating) AS avg_rating, COUNT(*) AS review_count
            FROM reviews
            WHERE product_id=%s
        """, (product_id,))
        agg = cur.fetchone() or {"avg_rating": None, "review_count": 0}

        cur.close(); db.close()
        return jsonify({"ok": True, "reviews": reviews, "aggregate": agg})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.post("/api/products/<int:product_id>/reviews")
def create_or_update_review(product_id):
    if 'user' not in session or session.get('role') != 'driver':
        return jsonify({"ok": False, "error": "auth"}), 403

    username = session['user']
    body = request.get_json(silent=True) or {}
    rating = int(body.get("rating", 0))
    title  = (body.get("title") or "").strip()[:120]
    text   = (body.get("body") or "").strip()

    if rating < 1 or rating > 5:
        return jsonify({"ok": False, "error": "Rating must be 1–5"}), 400

    try:
        db = MySQLdb.connect(**db_config)
        cur = db.cursor()

        # (Optional) gate: verify the product exists
        cur.execute("SELECT product_id FROM products WHERE product_id=%s", (product_id,))
        exists = cur.fetchone()
        if not exists:
            cur.close(); db.close()
            return jsonify({"ok": False, "error": "Product not found"}), 404

        # Upsert (update if the driver already reviewed this product)
        cur.execute("""
            INSERT INTO reviews (product_id, driver_username, rating, title, body)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                rating=VALUES(rating),
                title=VALUES(title),
                body=VALUES(body)
        """, (product_id, username, rating, title, text))
        db.commit()
        cur.close(); db.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route('/catalog_manager')
def catalog_manager():
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor_name = session['user']  # your session stores sponsor username

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Fetch products for this sponsor
        cursor.execute("SELECT * FROM products WHERE sponsor=%s", (sponsor_name,))
        products = cursor.fetchall()

        cursor.close()
        db.close()
    except Exception as e:
        flash(f"A database error occurred while loading your catalog: {e}", "danger")

    return render_template("catalog_manager.html", products=products)

@app.route('/add_product', methods=['POST'])
def add_product():
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    name = request.form.get('name')
    points_cost = request.form.get('points_cost')
    quantity = request.form.get('quantity', 0)
    sponsor_name = session['user']

    if not name or not points_cost:
        # If AJAX request, return JSON error
        if request.headers.get('X-Requested-With') == 'fetch' or request.args.get('ajax') == '1':
            return jsonify({"ok": False, "error": "Name and points cost are required."}), 400
        return "<h3>Name and points cost are required.</h3>"

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO products (name, sponsor, points_cost, quantity) VALUES (%s, %s, %s, %s)",
            (name, sponsor_name, points_cost, quantity)
        )
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'fetch' or request.args.get('ajax') == '1':
            return jsonify({"ok": False, "error": str(e)}), 500
        return f"<h2>Database error:</h2><p>{e}</p>"

    # If AJAX/fetch, return JSON success; otherwise keep old redirect flow
    if request.headers.get('X-Requested-With') == 'fetch' or request.args.get('ajax') == '1':
        return jsonify({"ok": True})

    return redirect(url_for('catalog_manager'))


@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor_name = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()

        # Only allow deletion if product belongs to this sponsor
        cursor.execute("DELETE FROM products WHERE product_id=%s AND sponsor=%s", (product_id, sponsor_name))
        db.commit()

        if cursor.rowcount > 0:
            flash("Product deleted successfully.", "success")
        else:
            flash("Could not delete product. It may not belong to you.", "warning")

        cursor.close()
        db.close()
    except Exception as e:
        flash(f"Database error deleting product: {e}", "danger")

    return redirect(url_for('catalog_manager'))

@app.route('/item_catalog', methods=['GET'])
def item_catalog():
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    accepted_sponsors = _get_driver_accepted_sponsors(username)
    active_sponsor = _get_active_sponsor(username)  # may be None

    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'points_cost_asc')
    favorites_only = request.args.get('favorites', '0') == '1'

    items = []
    if active_sponsor:
        query = "SELECT * FROM products WHERE sponsor=%s"
        params = [active_sponsor]

        if search:
            query += " AND (name LIKE %s)"
            params.append(f"%{search}%")

        if favorites_only:
            query += " AND product_id IN (SELECT product_id FROM favorites WHERE driver_username=%s)"
            params.append(username)

        if sort == 'points_cost_desc':
            query += " ORDER BY points_cost DESC"
        elif sort == 'name_asc':
            query += " ORDER BY name ASC"
        elif sort == 'name_desc':
            query += " ORDER BY name DESC"
        else:
            query += " ORDER BY points_cost ASC"

        cursor.execute(query, tuple(params))
        items = cursor.fetchall()

    # Aggregate reviews for listed products
    review_agg = {}
    if items:
        pids = [row['product_id'] for row in items]
        fmt = ",".join(["%s"] * len(pids))
        cursor.execute(f"""
            SELECT product_id, AVG(rating) AS avg_rating, COUNT(*) AS review_count
            FROM reviews
            WHERE product_id IN ({fmt})
            GROUP BY product_id
        """, pids)
        for r in cursor.fetchall():
            review_agg[r['product_id']] = {
                "avg_rating": float(r['avg_rating'] or 0.0),
                "review_count": int(r['review_count'] or 0)
            }

    cursor.execute("SELECT product_id FROM favorites WHERE driver_username=%s", (username,))
    favorite_ids = {row['product_id'] for row in cursor.fetchall()}

    points_balance = _get_points(username, active_sponsor) if active_sponsor else 0

    cursor.close(); db.close()

    return render_template(
        "item_catalog.html",
        items=items,
        points_balance=points_balance,
        search=search,
        sort=sort,
        sponsor=active_sponsor or 'none',
        sponsors=accepted_sponsors,   # only sponsors you’re accepted with
        favorites_only=favorites_only,
        favorite_ids=favorite_ids,
        review_agg=review_agg,
    )


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session or 'role' not in session:
        return redirect(url_for('login'))

    username = session['user']
    role = session['role']

    table = {'driver': 'drivers', 'sponsor': 'sponsor', 'admin': 'admins'}.get(role)
    profile_route = f"{role}_profile"

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        if request.method == 'POST':
            update_fields = []
            update_query = f"UPDATE {table} SET "

            # --- Basic fields ---
            fields = ['first_name', 'last_name', 'phone', 'address']
            for f in fields:
                if f in request.form:
                    update_query += f"{f}=%s, "
                    update_fields.append(request.form[f])

            # --- Driver-specific ---
            if role == 'driver':
                for f in ['vehicle_make', 'vehicle_model', 'vehicle_year']:
                    update_query += f"{f}=%s, "
                    update_fields.append(request.form.get(f))

            # --- Sponsor-specific ---
            if role == 'sponsor':
                for f in ['organization', 'company_link']:
                    update_query += f"{f}=%s, "
                    update_fields.append(request.form.get(f))

                # ✅ Add support for point limits
                min_points = request.form.get('min_points', type=int)
                max_points = request.form.get('max_points', type=int)

                if min_points is not None and max_points is not None:
                    if min_points < 0 or max_points < 0:
                        flash("Points cannot be negative.", "warning")
                    elif min_points > max_points:
                        flash("Minimum points cannot exceed maximum points.", "warning")
                    else:
                        cursor.execute("""
                            UPDATE sponsor
                            SET min_points=%s, max_points=%s
                            WHERE username=%s
                        """, (min_points, max_points, username))
                        db.commit()
                        flash("Point limits updated successfully.", "success")

            # --- Social media ---
            if role in ['driver', 'sponsor']:
                for f in ['twitter', 'facebook', 'instagram']:
                    update_query += f"{f}=%s, "
                    update_fields.append(request.form.get(f))

            # --- Remove trailing comma and add WHERE ---
            update_query = update_query.rstrip(', ') + " WHERE username=%s"
            update_fields.append(username)
            cursor.execute(update_query, tuple(update_fields))

            # --- Password ---
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            if password and confirm_password:
                if password == confirm_password:
                    password = sha256_of_string(password)
                    cursor.execute(f"UPDATE {table} SET password_hash=%s WHERE username=%s",
                                   (password, username))
                    cursor.execute(
                        "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                        ("password reset", f"{username} reset their password successfully while logged in.", username)
                    )
                else:
                    flash('Passwords do not match. Please try again.', 'danger')

            # --- Profile picture ---
            file = request.files.get('profile_picture')
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{username}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                cursor.execute(f"UPDATE {table} SET profile_picture=%s WHERE username=%s",
                               (filename, username))

            # --- Sponsor logo logic (unchanged) ---
            if role == 'sponsor':
                logo_file = request.files.get('company_logo')
                remove_logo_checked = 'remove_logo' in request.form

                if logo_file and allowed_file(logo_file.filename):
                    logo_filename = secure_filename(f"{username}_logo_{logo_file.filename}")
                    logo_folder_path = app.config['LOGO_UPLOAD_FOLDER']
                    os.makedirs(logo_folder_path, exist_ok=True)
                    logo_path = os.path.join(logo_folder_path, logo_filename)
                    logo_file.save(logo_path)
                    cursor.execute("UPDATE sponsor SET company_logo=%s WHERE username=%s", (logo_filename, username))

                elif remove_logo_checked:
                    cursor.execute("SELECT company_logo FROM sponsor WHERE username=%s", (username,))
                    result = cursor.fetchone()
                    if result and result['company_logo']:
                        path_to_delete = os.path.join(app.config['LOGO_UPLOAD_FOLDER'], result['company_logo'])
                        if os.path.exists(path_to_delete):
                            os.remove(path_to_delete)
                    cursor.execute("UPDATE sponsor SET company_logo=NULL WHERE username=%s", (username,))

            db.commit()
            flash('Your profile has been updated successfully!', 'success')
            cursor.close()
            db.close()
            return redirect(url_for(profile_route))

        # GET request
        cursor.execute(f"SELECT * FROM {table} WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

    except Exception as e:
        flash(f"A database error occurred. Please try again. Error: {e}", "danger")
        return f"<h2>Database error:</h2><p>{e}</p>"

    return render_template("settings.html", user=user)



@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    # Only allow sponsors and admins
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    requester_role = session.get('role')
    
    if request.method == 'POST':
        # Get data from the form
        new_username = request.form['username']
        new_email = request.form['email']
        new_password = request.form['password']
        new_role = request.form['role']

        # Only admins can create other admins
        if new_role == 'admins' and requester_role != 'admin':
            # flash is optional; you can render an error page instead
            flash("Only admins can create other admins.", "danger")
            return redirect(url_for('add_user'))
        
        #Hashing Password
        password_hash = new_password;
        password_hash = sha256_of_string(password_hash)
        success, message = _create_user_in_table(new_role, new_username, new_email, password_hash)

        if success:
            welcomeEmail.send_welcome_email(new_email, new_username, new_password)
            return render_template(
                "user_added.html",
                username=new_username,
                email=new_email,
                role=new_role
            )
        else:
            return f"<h2>Error:</h2><p>{message}</p>"

    # GET request – show the form
    return render_template("add_user.html")

@app.route('/drivers')
def drivers():
    # Only sponsors/admins can access
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    if session.get('role') == 'sponsor':
        cur.execute("""
            SELECT d.username, d.email, d.points, d.disabled
            FROM drivers d
            JOIN driverApplications a
              ON a.driverUsername = d.username
             AND a.sponsor = %s
             AND a.status = 'accepted'
            ORDER BY d.username
        """, (session['user'],))
    else:
        cur.execute("SELECT username, email, points, disabled FROM drivers ORDER BY username")

    drivers_list = cur.fetchall()
    cur.close(); db.close()

    return render_template("drivers.html", drivers=drivers_list, role=session.get('role'))

@app.route('/driver/<username>', methods=['GET', 'POST'])
def sponsor_edit_driver(username):
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # Ensure this driver belongs to this sponsor
    cursor.execute("""
        SELECT COUNT(*) AS valid
        FROM driverApplications
        WHERE driverUsername=%s AND sponsor=%s AND status='accepted'
    """, (username, sponsor))
    valid = cursor.fetchone()
    if not valid or valid['valid'] == 0:
        flash("You are not authorized to edit this driver.", "danger")
        return redirect(url_for('drivers'))

    if request.method == 'POST':
        phone = request.form.get('phone')
        address = request.form.get('address')
        cursor.execute("""
            UPDATE drivers
            SET phone=%s, address=%s
            WHERE username=%s
        """, (phone, address, username))
        db.commit()
        flash("Driver information updated.", "success")

    cursor.execute("SELECT * FROM drivers WHERE username=%s", (username,))
    driver = cursor.fetchone()
    cursor.close(); db.close()

    return render_template("sponsor_edit_driver.html", driver=driver)

@app.route('/sponsors')
def sponsors():
    # Only sponsors/admins can access
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT username, email, disabled FROM sponsor;")
        sponsors_list = cursor.fetchall()
        cursor.close()
        db.close()
    except Exception as e:
        flash(f"Database error loading sponsors list: {e}", "danger")

    return render_template("sponsors.html", sponsors=sponsors_list, role=session.get('role'))


@app.route('/remove_driver', methods=['POST'])
def remove_driver():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))

    username = request.form['username']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("DELETE FROM drivers WHERE username = %s;", (username,))
        db.commit()
        cursor.close()
        db.close()
        flash(f'Driver "{username}" has been removed successfully.', 'success')
    except Exception as e:
        return f"<h2>Error removing driver:</h2><p>{e}</p>"
        flash(f'Error removing driver: {e}', 'danger')

    return redirect(url_for('drivers'))

@app.route('/drop_driver', methods=['POST'])
def drop_driver():
    if 'user' not in session or session.get('role') != 'sponsor':
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login'))

    driver_username = request.form.get('username')
    sponsor_username = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # End sponsorship in applications table
        cursor.execute("""
            UPDATE driverApplications
            SET status='dropped'
            WHERE driverUsername=%s AND sponsor=%s AND status='accepted'
        """, (driver_username, sponsor_username))
        db.commit()

        # Get driver’s email
        cursor.execute("SELECT email FROM drivers WHERE username=%s", (driver_username,))
        driver = cursor.fetchone()

        if driver and driver.get('email'):
            send_driver_dropped_email(driver['email'], driver_username, sponsor_username)

        flash(f'Driver "{driver_username}" has been dropped successfully.', 'success')

        cursor.close()
        db.close()
    except Exception as e:
        flash(f'Error dropping driver: {e}', 'danger')

    return redirect(url_for('drivers'))

@app.route('/remove_sponsor', methods=['POST'])
def remove_sponsor():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))

    username = request.form['username']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("DELETE FROM sponsor WHERE username = %s;", (username,))
        db.commit()
        cursor.close()
        db.close()
        flash(f'Sponsor "{username}" has been removed successfully.', 'success')
    except Exception as e:
        #return f"<h2>Error removing sponsor:</h2><p>{e}</p>"
        flash(f'Error removing sponsor: {e}', 'danger')

    return redirect(url_for('sponsors'))


@app.route('/login_as_driver', methods=['POST'])
def login_as_driver():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))

    username = request.form['username']
    session['user'] = username
    session['role'] = 'driver'
    flash(f"You are now logged in as driver '{username}'.", 'info')
    return redirect(url_for('driver_profile'))

@app.route('/login_as_sponsor', methods=['POST'])
def login_as_sponsor():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))

    username = request.form['username']
    session['user'] = username
    session['role'] = 'sponsor'
    flash(f"You are now logged in as sponsor '{username}'.", 'info')
    return redirect(url_for('sponsor_profile'))

@app.route('/add_points', methods=['POST'])
def add_points():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    target_driver = request.form['username']
    points = int(request.form['points_to_add'])
    reason = request.form.get('reason', '(no reason provided)')
    performed_by = session['user']  # sponsor giving points

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT min_points, max_points FROM sponsor WHERE username=%s", (performed_by,))
    sp = cursor.fetchone()
    if not sp:
        flash("Sponsor not found.", "danger");  return redirect(url_for('drivers'))

    cursor.execute("""
        SELECT points FROM driver_sponsor_points
        WHERE driver_username=%s AND sponsor=%s
    """, (target_driver, performed_by))
    row = cursor.fetchone()
    current = int(row['points']) if row and row['points'] is not None else 0
    new_total = current + points

    if new_total > sp['max_points']:
        flash(f"Cannot add points — this would exceed your max of {sp['max_points']} points.", "warning")
    else:
        cursor.execute("""
            INSERT INTO driver_sponsor_points (driver_username, sponsor, points)
            VALUES (%s,%s,%s)
            ON DUPLICATE KEY UPDATE points = points + VALUES(points)
        """, (target_driver, performed_by, points))
        db.commit()
        cursor.execute("INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                       ("add points", f"{performed_by} added {points} points to {target_driver}. Reason: {reason}", performed_by))
        db.commit()
        flash(f'{points} points were successfully added to "{target_driver}".', 'success')

    cursor.close(); db.close()
    driverEmail = get_email_by_username(target_driver)
    if driverEmail:
        driverAddPointsEmail.send_points_added_email(driverEmail, target_driver, points)
    return redirect(url_for('drivers'))


@app.route('/remove_points', methods=['POST'])
def remove_points():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    target_driver = request.form['username']
    points = int(request.form['points_to_remove'])
    reason = request.form.get('reason', '(no reason provided)')
    performed_by = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT min_points, max_points FROM sponsor WHERE username=%s", (performed_by,))
    sp = cursor.fetchone()
    if not sp:
        flash("Sponsor not found.", "danger");  return redirect(url_for('drivers'))

    cursor.execute("""
        SELECT points FROM driver_sponsor_points
        WHERE driver_username=%s AND sponsor=%s
    """, (target_driver, performed_by))
    row = cursor.fetchone()
    current = int(row['points']) if row and row['points'] is not None else 0
    new_total = current - points

    if new_total < sp['min_points']:
        flash(f"Cannot remove points — this would go below your min of {sp['min_points']} points.", "warning")
    else:
        cursor.execute("""
            UPDATE driver_sponsor_points
            SET points = GREATEST(0, points - %s)
            WHERE driver_username=%s AND sponsor=%s
        """, (points, target_driver, performed_by))
        db.commit()
        cursor.execute("INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                       ("remove points", f"{performed_by} removed {points} points from {target_driver}. Reason: {reason}", performed_by))
        db.commit()
        flash(f'{points} points were successfully removed from "{target_driver}".')

    cursor.close(); db.close()

    driverEmail = get_email_by_username(target_driver)
    if driverEmail:
        send_points_removed_email(driverEmail, target_driver, points)

        # Optional: low balance alert (per sponsor)
        db = MySQLdb.connect(**db_config)
        cur = db.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("""
            SELECT points
            FROM driver_sponsor_points
            WHERE driver_username=%s AND sponsor=%s
        """, (target_driver, performed_by))
        r = cur.fetchone()
        if r and int(r['points'] or 0) < 50:
            send_low_balance_email(driverEmail, target_driver, int(r['points'] or 0), 50)
        cur.close(); db.close()

        return redirect(url_for('drivers'))



@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Look up user across roles
        cursor.execute("""
            SELECT username, 'driver' AS role FROM drivers WHERE username=%s AND email=%s
            UNION
            SELECT username, 'sponsor' AS role FROM sponsor WHERE username=%s AND email=%s
            UNION
            SELECT username, 'admin' AS role FROM admins WHERE username=%s AND email=%s
        """, (username, email, username, email, username, email))
        user = cursor.fetchone()

        if not user:
            cursor.close(); db.close()
            flash('No account found for that username and email.', 'danger')
            return "<h3>No account found for that username and email.</h3>"

        # Generate a secure random token
        token = secrets.token_urlsafe(32)
        expiration = datetime.now() + timedelta(hours=1)

        # Save token and expiration in passwordResets
        cursor.execute("""
            INSERT INTO passwordResets (username, role, token, expiration)
            VALUES (%s, %s, %s, %s)
        """, (user['username'], user['role'], token, expiration))
        db.commit()

        # Send password reset email
        reset_link = url_for('set_new_password', token=token, _external=True)
        send_reset_email(email, username, reset_link)

        # Log audit event
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("password_reset_request",
             f"Password reset link created for {username} (expires {expiration}).",
             username)
        )
        db.commit()

        cursor.close(); db.close()
        return "<h3>A password reset link has been sent to your email. It expires in 1 hour.</h3>"

    return render_template("reset_password.html")

@app.route('/set_new_password/<token>', methods=['GET', 'POST'])
def set_new_password(token):
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # Verify token is valid, unused, and not expired
    cursor.execute("SELECT * FROM passwordResets WHERE token=%s AND used=FALSE", (token,))
    reset = cursor.fetchone()

    if not reset or reset['expiration'] < datetime.now():
        cursor.close(); db.close()
        return "<h3>This password reset link is invalid or has expired.</h3>"

    # If token valid, handle form
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return "<h3>Passwords do not match.</h3>"

        # Determine which table to update
        table = {'driver': 'drivers', 'sponsor': 'sponsor', 'admin': 'admins'}[reset['role']]
        new_password = sha256_of_string(new_password)
        # Update password 
        cursor.execute(f"""
            UPDATE {table}
            SET password_hash = %s
            WHERE username = %s
        """, (new_password, reset['username']))

        # Mark token as used so it cannot be reused
        cursor.execute("UPDATE passwordResets SET used=TRUE WHERE id=%s", (reset['id'],))

        # Log audit event
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("password_reset",
             f"{reset['username']} successfully reset their password via token.",
             reset['username'])
        )
        db.commit()

        cursor.close(); db.close()
        return "<h3>Password successfully reset. You can now <a href='/login'>log in</a>.</h3>"

    cursor.close(); db.close()
    
    return render_template("set_new_password.html")

@app.route('/sponsors/browse')
def sponsor_browse():
    if 'user' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT username, organization FROM sponsor")
    sponsors = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template("sponsor_browse.html", sponsors=sponsors)

@app.route('/apply/<sponsor>', methods=['POST'])
def apply_to_sponsor(sponsor):
    if 'user' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    username = session['user']
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Only block duplicate active app to the SAME sponsor
        cursor.execute("""
            SELECT id FROM driverApplications
            WHERE driverUsername=%s AND sponsor=%s
              AND status IN ('pending','accepted')
        """, (username, sponsor))
        if cursor.fetchone():
            cursor.close(); db.close()
            return "<h3>You already have an active application with this sponsor.</h3>"

        cursor.execute("""
            INSERT INTO driverApplications (driverUsername, sponsor, status, created_at, updated_at)
            VALUES (%s, %s, 'pending', NOW(), NOW())
        """, (username, sponsor))
        db.commit()

        cursor.execute("""
            INSERT INTO auditLogs (action, description, user_id)
            VALUES (%s, %s, %s)
        """, ("application_created", f"{username} applied to sponsor {sponsor}.", username))
        db.commit()

        cursor.close(); db.close()
        flash(f'Your application to "{sponsor}" has been submitted successfully!', 'success')

        sponsorEmail = get_email_by_username(sponsor)
        if sponsorEmail:
            applicationEmail.send_application_email(sponsorEmail, sponsor)

        return redirect(url_for('driver_applications'))

    except Exception as e:
        return f"<h2>Error applying to sponsor:</h2><p>{e}</p>"


@app.route('/applications')
def driver_applications():
    if 'user' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("""
        SELECT * FROM driverApplications
        WHERE driverUsername=%s
        ORDER BY FIELD(status,'pending','accepted','rejected','withdrawn', 'dropped'), created_at DESC
    """, (username,))
    applications = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template("driver_applications.html", applications=applications)

@app.route('/withdraw/<int:app_id>', methods=['POST'])
def withdraw_application(app_id):
    if 'user' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor()

    cursor.execute("""
        UPDATE driverApplications
        SET status='withdrawn'
        WHERE id=%s AND driverUsername=%s AND status='pending'
    """, (app_id, username))
    db.commit()

    cursor.close()
    db.close()

    return redirect(url_for('driver_applications'))
@app.route('/sponsor/applications')
def sponsor_applications():
    """View list of driver applications for the logged-in sponsor."""
    if 'user' not in session or session['role'] != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("""
        SELECT a.id, a.driverUsername, a.status, a.created_at, a.updated_at
        FROM driverApplications a
        WHERE a.sponsor=%s
        ORDER BY a.created_at DESC
    """, (sponsor,))
    applications = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template("sponsor_applications.html", applications=applications)


@app.route('/sponsor/applications/<int:app_id>')
def sponsor_application_detail(app_id):
    """View details of a specific driver application."""
    if 'user' not in session or session['role'] != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("""
        SELECT a.*, d.first_name, d.last_name, d.email, d.phone, d.address
        FROM driverApplications a
        JOIN drivers d ON a.driverUsername = d.username
        WHERE a.id=%s AND a.sponsor=%s
    """, (app_id, sponsor))
    application = cursor.fetchone()

    cursor.close()
    db.close()

    if not application:
        return "<h3>Application not found or you don’t have access.</h3>"

    return render_template("sponsor_application_detail.html", app=application)


@app.route('/sponsor/applications/<int:app_id>/accept', methods=['POST'])
def accept_application(app_id):
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute("""
            SELECT driverUsername FROM driverApplications
            WHERE id=%s AND sponsor=%s
        """, (app_id, sponsor))
        app_row = cursor.fetchone()
        if not app_row:
            cursor.close(); db.close()
            return "<h3>Application not found.</h3>"

        driver_username = app_row['driverUsername']

        # Accept without global single-sponsor restriction
        cursor.execute("""
            UPDATE driverApplications
            SET status='accepted', updated_at=NOW()
            WHERE id=%s AND sponsor=%s AND status='pending'
        """, (app_id, sponsor))
        db.commit()

        # Ensure per-(driver,sponsor) balance row exists
        cursor.execute("""
            INSERT IGNORE INTO driver_sponsor_points (driver_username, sponsor, points)
            VALUES (%s,%s,0)
        """, (driver_username, sponsor))
        db.commit()

        description = f"{sponsor} accepted {driver_username}'s application"
        cursor.execute("INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                       ("application", description, sponsor))
        db.commit()

        cursor.execute("""
            SELECT d.email, d.first_name
            FROM drivers d
            WHERE d.username=%s
        """, (driver_username,))
        driver = cursor.fetchone()
        if driver:
            send_decision_email(driver['email'], driver['first_name'], sponsor, "accepted")

        cursor.close(); db.close()
        return redirect(url_for('sponsor_applications'))

    except Exception as e:
        return f"<h2>Error accepting application:</h2><p>{e}</p>"


@app.route('/sponsor/applications/<int:app_id>/reject', methods=['POST'])
def reject_application(app_id):
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Reject the application
        cursor.execute("""
            UPDATE driverApplications
            SET status='rejected'
            WHERE id=%s AND sponsor=%s AND status='pending'
        """, (app_id, sponsor))
        db.commit()

        # Fetch driver info for email
        cursor.execute("""
            SELECT d.email, d.first_name, a.sponsor
            FROM driverApplications a
            JOIN drivers d ON a.driverUsername = d.username
            WHERE a.id=%s
        """, (app_id,))
        db.commit()
        
        driver = cursor.fetchone()

        if driver:
            send_decision_email(driver['email'], driver['first_name'], driver['sponsor'], "rejected")

        #Log rejecting
        description = f"{sponsor} rejected {driver['driverUsername']}'s application"
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("application", description, sponsor)
        )

        db.commit()
        cursor.close()
        db.close()
        return redirect(url_for('sponsor_applications'))

    except Exception as e:
        return f"<h2>Error rejecting application:</h2><p>{e}</p>"

@app.route('/sponsor/applications/bulk', methods=['POST'])

def bulk_update_applications():
    """Mass accept or reject driver applications."""
    if 'user' not in session or session['role'] != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']
    action = request.form['action']
    selected_apps = request.form.getlist('selected_apps')

    if not selected_apps:
        flash('No applications were selected.', 'warning')
        return redirect(url_for('sponsor_applications'))

    new_status = 'accepted' if action == 'accept' else 'rejected'

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # --- First, get driver usernames for selected apps ---
    format_strings = ','.join(['%s'] * len(selected_apps))
    cursor.execute(f"""
        SELECT id, driverUsername 
        FROM driverApplications 
        WHERE id IN ({format_strings}) AND sponsor=%s
        """, selected_apps + [sponsor])

    apps_info = cursor.fetchall()

    # --- Update statuses ---
    cursor.executemany("""
        UPDATE driverApplications
        SET status=%s
        WHERE id=%s AND sponsor=%s AND status='pending'
    """, [(new_status, app['id'], sponsor) for app in apps_info])

    db.commit()


    # --- Log each application individually ---
    for app in apps_info:
        description = f"{sponsor} {new_status} {app['driverUsername']}'s application"
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("application", description, sponsor)
        )
    db.commit()
    
    cursor.close()
    db.close()
    flash(f'Successfully updated {len(apps_info)} application(s) to "{new_status}".', 'success')

    return redirect(url_for('sponsor_applications'))

@app.route('/admin/audit_logs/download', methods=['POST'])
def download_audit_logs():
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))


    action_filter = request.form.get('action') or 'all'
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    user_id = request.form.get('user_id')

    # --- Initialize query and params as empty ---
    query = ""
    params = []

    # ---  Add if/else block to choose the query ---
    if action_filter == 'feedback':
        # Build the special query for the feedback table
        query = """
            SELECT 
                submitted_at AS timestamp, 
                'Feedback' AS action, 
                feedback_text AS description, 
                user_role AS user_id 
            FROM feedback 
            WHERE 1=1
        """
        
        # Add date filters (User ID filter is ignored)
        if start_date:
            query += " AND submitted_at >= %s"
            params.append(start_date)
        if end_date:
            query += " AND submitted_at <= %s"
            params.append(end_date)
            
        query += " ORDER BY timestamp DESC"
    
    else:
        query = "SELECT * FROM auditLogs WHERE 1=1"
        
        if action_filter != 'all':
            if action_filter == 'point history':
                query += " AND (action='add points' OR action='remove points')"
            else:
                query += " AND action=%s"
                params.append(action_filter)
        if user_id:
            query += " AND user_id=%s"
            params.append(user_id)
        if start_date:
            query += " AND timestamp >= %s"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= %s"
            params.append(end_date)

        query += " ORDER BY timestamp DESC"

    print("QUERY:", query)
    print("PARAMS:", params)

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(query, params)
    logs = cursor.fetchall()

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=['timestamp', 'action', 'description', 'user_id'])
    writer.writeheader()
    for row in logs:
        lower_row = {k.lower(): v for k, v in row.items()}
        writer.writerow(lower_row)

    
    cursor.close()
    db.close()

    if logs:
        print(logs[0].keys())
    else:
        print("No logs found for current filters.")

    
    response = Response(output.getvalue().encode('utf-8'), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
    return response

# SPRINT 7, STEP 2: Add this new route to handle anonymous feedback submission
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'user' not in session or session.get('role') not in ['driver', 'sponsor']:
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 403

    feedback_text = request.form.get('feedback_text')
    if not feedback_text:
        return jsonify({'status': 'error', 'message': 'Feedback cannot be empty'}), 400

    # Get the user_id from the session
    user_id = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO feedback (user_role, feedback_text) VALUES (%s, %s)",
            (session['role'], feedback_text)
        )
        db.commit()
        cursor.close()
        db.close()
        
        # Prevent the modal from showing again in this session
        session['show_feedback_modal'] = False
        
        return jsonify({'status': 'success', 'message': 'Thank you for your feedback!'})

    except Exception as e:
        print(f"Feedback submission error: {e}") # For your server logs
        return jsonify({'status': 'error', 'message': 'A server error occurred'}), 500


# SPRINT 7: Route to handle dismissing the feedback modal
@app.route('/dismiss_feedback', methods=['POST'])
def dismiss_feedback():
    if 'user' in session:
        session['show_feedback_modal'] = False
    return jsonify({'status': 'success'})

@app.route('/admin/audit_logs', methods=['GET', 'POST'])
def audit_logs():
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # Default filters
    action_filter = request.form.get('action', 'all')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    user_id = request.form.get('user_id')

    # --- Initialize query and params as empty ---
    query = ""
    params = []

    # --- Add if/else block to choose the query ---
    if action_filter == 'feedback':
        # Build the special query for the feedback table
        # We "rename" columns using AS to match the HTML table
        query = """
            SELECT 
                submitted_at AS timestamp, 
                'Feedback' AS action, 
                feedback_text AS description, 
                user_role AS user_id 
            FROM feedback 
            WHERE 1=1
        """
        
        # Add date filters (User ID filter is ignored for anonymous feedback)
        if start_date:
            query += " AND submitted_at >= %s"
            params.append(start_date)
        if end_date:
            query += " AND submitted_at <= %s"
            params.append(end_date)
            
        query += " ORDER BY timestamp DESC"

    else:
        query = "SELECT * FROM auditLogs WHERE 1=1"
        
        if action_filter != 'all':
            if action_filter == 'point history':
                query += " AND (action='add points' OR action='remove points')"
            elif action_filter == 'log in attempt':
                query += " AND (action='login_success' OR action='login_failed' OR action='lockout')"
            else:
                query += " AND action=%s"
                params.append(action_filter)

        if user_id:
            query += " AND user_id=%s"
            params.append(user_id)

        if start_date:
            query += " AND timestamp >= %s"
            params.append(start_date)

        if end_date:
            query += " AND timestamp <= %s"
            params.append(end_date)

        query += " ORDER BY timestamp DESC"

    cursor.execute(query, params)
    logs = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('admin_audit_logs.html', logs=logs)

def get_email_by_username(username):
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("""
            SELECT email 
            FROM drivers WHERE username=%s
            UNION ALL
            SELECT email 
            FROM sponsor WHERE username=%s
            UNION ALL
            SELECT email 
            FROM admins WHERE username=%s
            LIMIT 1
        """, (username, username, username))

        result = cursor.fetchone()
        return result['email'] if result else None

    finally:
        cursor.close()
        db.close()


@app.route('/admin/simulation', methods=['GET'])
def simulation():
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT username FROM drivers")
    drivers = cursor.fetchall()  # list of dicts with {'username': ...}

    cursor.execute("SELECT * FROM simulation_rules ORDER BY id DESC")
    rules = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('simulation.html', drivers=drivers, rules=rules)


@app.route('/simulation/add_rule', methods=['POST'])
def add_rule():
    if 'user' not in session or session.get('role') != 'admin':
        flash("You must be an admin to perform this action.", "danger")
        return redirect(url_for('simulation'))

    # Safely get form data
    rule_type = request.form.get('rule_type')
    schedule = request.form.get('schedule', '').strip()
    points = request.form.get('points')  # may be None
    driver_text = request.form.get('driver_username_text', '').strip()
    driver_dropdown = request.form.get('driver_username_dropdown', '').strip()

    if not rule_type:
        flash("Rule type is required.", "danger")
        return redirect(url_for('simulation'))

    # Determine which driver field to use
    if rule_type in ['add_driver', 'remove_driver']:
        driver_username = driver_text
        points_value = None
    elif rule_type in ['add_points', 'remove_points']:
        driver_username = driver_dropdown
        points_value = int(points) if points else None
    else:
        flash("Invalid rule type.", "danger")
        return redirect(url_for('simulation'))

    if not schedule:
        flash("Schedule is required.", "danger")
        return redirect(url_for('simulation'))

    # Optional: validate driver exists if points action
    if rule_type in ['add_points', 'remove_points'] and not driver_username:
        flash("You must select a driver for points rules.", "danger")
        return redirect(url_for('simulation'))

    # Insert into DB
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO simulation_rules (type, driver_username, points, schedule, enabled)
            VALUES (%s, %s, %s, %s, 1)
        """, (rule_type, driver_username, points_value, schedule))
        db.commit()
    except Exception as e:
        flash(f"Database error: {e}", "danger")
    finally:
        cursor.close()
        db.close()

    flash("Rule added successfully.", "success")
    return redirect(url_for('simulation'))

@app.route('/admin/simulation/toggle/<int:rule_id>', methods=['POST', 'GET'])
def toggle_rule(rule_id):
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor()
    
    # Get current status
    cursor.execute("SELECT enabled FROM simulation_rules WHERE id=%s", (rule_id,))
    row = cursor.fetchone()
    if row:
        current_status = row[0]
        new_status = 0 if current_status else 1
        cursor.execute("UPDATE simulation_rules SET enabled=%s WHERE id=%s", (new_status, rule_id))
        db.commit()
    
    cursor.close()
    db.close()
    flash('Rule status updated.', 'success')
    return redirect(url_for('simulation'))


@app.route('/disable_rule/<int:rule_id>')
def disable_rule(rule_id):
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor()
    cursor.execute("UPDATE simulation_rules SET enabled=FALSE WHERE id=%s", (rule_id,))
    db.commit()
    cursor.close()
    db.close()
    
    return redirect(url_for('simulation'))


@app.route('/remove_rule/<int:rule_id>')
def remove_rule(rule_id):
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor()
    cursor.execute("DELETE FROM simulation_rules WHERE id=%s", (rule_id,))
    db.commit()
    cursor.close()
    db.close()
    
    return redirect(url_for('simulation'))


def sha256_of_string(s: str) -> str:
    """Return hex SHA-256 of a UTF-8 string."""
    b = s.encode('utf-8')
    h = hashlib.sha256(b)
    return h.hexdigest()

    
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
