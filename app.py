from flask import Flask, render_template, session, redirect, url_for, request, flash
import MySQLdb  # mysqlclient
from logInFunctions.auth import authenticate
from emailScripts import welcomeEmail
from emailScripts import cancelledPurchase
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
from emailScripts.favoriteRestockEmail import send_favorite_restock_email
from emailScripts.newCatalogItemEmail import send_new_item_email
from emailScripts.orderPlacedEmail import send_order_placed_email
from emailScripts.sponsor_message_email import send_sponsor_message_email
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
import requests #for recaptcha
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import io
from flask import send_file
import re


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

# --- reCAPTCHA keys ---
app.config['RECAPTCHA_SITE_KEY'] = '6LeEZQIsAAAAAEDy9mv_BznR738L1eYLSxHzMyrL'
app.config['RECAPTCHA_SECRET_KEY'] = '6LeEZQIsAAAAAMCNJL46o17NMP80XxwJn1Xr-WZX'

# --- Upload configuration ---
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pics'
app.config['LOGO_UPLOAD_FOLDER'] = 'static/uploads/company_logos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Password Validation ---
def check_password_strength(password):
    """
    Checks a password against the defined rules.
    Returns (True, "") if valid, or (False, "Error Message") if invalid.
    """
    if len(password) < 4:
        return False, "Password must be at least 4 characters long."
    
    # re.search(r"\d", ...) checks if there is at least one number
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    
    # Add more rules here in the future
    # if not re.search(r"[A-Z]", password):
    #     return False, "Password must contain an uppercase letter."
    
    return True, "" # All checks passed
# --- END OF Password Validation ---

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
        cursor = db.cursor(MySQLdb.cursors.DictCursor)
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
        new_id = cursor.fetchone()["id"]

        # Notify accepted drivers of this sponsor (respect receive_emails)
        try:
            cursor.execute("""
                SELECT d.username AS driver_username, d.email
                FROM driverApplications da
                JOIN drivers d ON d.username = da.driverUsername
                WHERE da.sponsor=%s
                  AND da.status='accepted'
                  AND COALESCE(d.receive_emails, 1)=1
            """, (sponsor_name,))
            subs = cursor.fetchall() or []
            for row in subs:
                email = row.get("email")
                uname = row.get("driver_username")
                if email:
                    try:
                        send_new_item_email(
                            recipient=email,
                            driver_username=uname,
                            sponsor_name=sponsor_name,
                            item_name=title,
                            points_cost=int(points_cost)
                        )
                    except Exception as mail_err:
                        print(f"[newCatalogItemEmail] Failed for {uname}: {mail_err}")
        except Exception as notif_err:
            print(f"[newCatalogItemEmail] Lookup failure: {notif_err}")

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
        # ---  CAPTCHA VERIFICATION START ---
#        captcha_response = request.form.get('g-recaptcha-response')
        
        # Check if CAPTCHA was submitted
#        if not captcha_response:
#          flash("Please complete the CAPTCHA.", "danger")
            # Pass site_key back to the template even on failure
#            return render_template("login.html", site_key=app.config['RECAPTCHA_SITE_KEY'])

        # Verify the response with Google
#        try:
#            response_data = requests.post(
#                'https://www.google.com/recaptcha/api/siteverify',
#                data={
#                    'secret': app.config['RECAPTCHA_SECRET_KEY'],
#                    'response': captcha_response,
#                    'remoteip': request.remote_addr
#                }
#            ).json()
#        except requests.exceptions.RequestException as e:
#            print(f"reCAPTCHA request failed: {e}")
#            flash("Error connecting to CAPTCHA service. Please try again later.", "danger")
#            return render_template("login.html", site_key=app.config['RECAPTCHA_SITE_KEY'])

        # Check if Google's verification was successful
#        if not response_data.get('success'):
#            flash("CAPTCHA verification failed. Please try again.", "danger")
#            return render_template("login.html", site_key=app.config['RECAPTCHA_SITE_KEY'])
        # --- CAPTCHA VERIFICATION END ---

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
                email = r['email']
                table = {'driver': 'drivers', 'sponsor': 'sponsor', 'admin': 'admins'}.get(role)
            
                # open a NEW connection (since db was closed)
                db2 = MySQLdb.connect(**db_config)
                cur = db2.cursor(MySQLdb.cursors.DictCursor)
                cur.execute(f"SELECT receive_emails, login_email FROM {table} WHERE username=%s", (username,))
                prefs = cur.fetchone()
                cur.close(); db2.close()
            
                if prefs and prefs['receive_emails'] and prefs['login_email']:
                    send_login_email(email, username)

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
                    cursor.execute("SELECT email, receive_emails, sponsor_locked_email FROM admins")
                    admins = cursor.fetchall()
                    locked_str = locked_until.strftime('%b %d, %Y %I:%M:%S %p')

                    # Send admin alert
                    for admin in admins:
                        if admin['receive_emails'] and admin['sponsor_locked_email']:
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

        flash(msg,"danger")
        return render_template("login.html", error=msg, last_username=username, site_key=app.config['RECAPTCHA_SITE_KEY'])

    # GET request → render blank login form
    return render_template("login.html", site_key=app.config['RECAPTCHA_SITE_KEY'])

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


@app.route("/bulk_load", methods=["GET", "POST"])
def bulk_load():
    role = session.get("role")

    if role not in ["sponsor", "admin"]:
        flash("Access denied: only sponsors and admins can use bulk load.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if 'file' not in request.files:
            flash("No file uploaded.", "danger")
            return redirect(request.url)

        file = request.files['file']
        if not file.filename.endswith(".txt"):
            flash("Please upload a .txt file.", "danger")
            return redirect(request.url)

        lines = file.read().decode("utf-8").splitlines()
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()

        inserted, skipped = 0, 0
        error_messages = []

        for i, line in enumerate(lines, start=1):
            if not line.strip():
                continue

            parts = [p.strip() for p in line.split("|")]

            # Admin lines: O|org, D|org|fname|lname|email, S|org|fname|lname|email
            # Sponsor lines: D||fname|lname|email, S||fname|lname|email
            line_type = parts[0].upper() if len(parts) > 0 else None

            try:
                if line_type not in ["O", "D", "S"]:
                    raise ValueError(f"Invalid record type '{line_type}' (must be O, D, or S).")

                # ---------- ORGANIZATION (Admins only) ----------
                if line_type == "O":
                    if role != "admin":
                        skipped += 1
                        error_messages.append(f"Line {i}: Sponsors cannot create organizations → {line}")
                    if len(parts) < 2:
                        raise ValueError("Missing organization name.")
                    org_name = parts[1]
                    inserted += 1

                # ---------- DRIVER or SPONSOR ----------
                elif line_type in ["D", "S"]:
                    # Organization name only used for admins
                    if role == "admin":
                        if len(parts) < 5:
                            raise ValueError("Not enough fields (expected 5).")
                        _, org_name, first_name, last_name, email = parts
                    else:
                        if len(parts) < 5:
                            raise ValueError("Not enough fields (expected 5).")
                        _, _, first_name, last_name, email = parts

                    if not first_name or not last_name or not email:
                        raise ValueError("Missing user details.")


                    # Create password automatically (or randomize)
                    password_hash = sha256_of_string("1234")

                    if line_type == "D":
                        cursor.execute("""
                            INSERT INTO drivers (username, first_name, last_name, email, password_hash)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (
                            email.split("@")[0], first_name, last_name, email, password_hash
                        ))

                    elif line_type == "S":
                        cursor.execute("""
                            INSERT INTO sponsor (username, first_name, last_name, email, password_hash)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (
                            email.split("@")[0], first_name, last_name, email, password_hash
                        ))

                    db.commit()
                    inserted += 1

            except Exception as e:
                db.rollback()
                skipped += 1
                error_messages.append(f"Line {i}: {str(e)} → {line}")
                continue

        db.commit()
        cursor.close()

        flash(f"Bulk load complete — {inserted} inserted, {skipped} skipped.", "success")
        if error_messages:
            flash("Errors:\n" + "\n".join(error_messages), "warning")

        return redirect(url_for("bulk_load"))

    return render_template("bulk_load.html")

@app.route('/toggle_account/<role>/<username>', methods=['POST'])
def toggle_account(role, username):
    # Only admins should be toggling other accounts
    if 'user' not in session or session.get('role') != 'admin':
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login'))

    action = request.form.get('action')  # 'enable' or 'disable'
    if action not in ['enable', 'disable']:
        flash("Invalid action.", "danger")
        # default back to something safe
        return redirect(url_for('dashboard'))

    disabled_value = 1 if action == 'disable' else 0

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    try:
        if role == 'sponsor':
            table = 'sponsor'
        elif role == 'driver':
            table = 'drivers'
        else:
            flash("Unsupported role for toggle.", "danger")
            cur.close()
            db.close()
            return redirect(url_for('dashboard'))

        cur.execute(f"UPDATE {table} SET disabled=%s WHERE username=%s", (disabled_value, username))
        db.commit()

        flash_msg = f"{role.capitalize()} '{username}' has been {'disabled' if disabled_value else 'enabled'}."
        flash(flash_msg, "success")

    except Exception as e:
        db.rollback()
        flash(f"Error updating {role} status: {e}", "danger")
    finally:
        cur.close()
        db.close()

    # 🔁 Redirect logic so you stay on the same page type
    if role == 'sponsor':
        # When toggling sponsors from the Sponsors tab, go back to Sponsors
        return redirect(url_for('sponsors'))
    elif role == 'driver':
        # If you ever use this for drivers, send them back to Drivers
        return redirect(url_for('drivers'))
    else:
        # Fallback
        return redirect(url_for('dashboard'))

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

        # Log the profile update
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("profile_update", f"Driver {username} updated their profile information.", username)
        )
        db.commit()

    cursor.execute("SELECT * FROM drivers WHERE username=%s", (username,))
    user_info = cursor.fetchone()

    # fetches the activity logs for this driver from the auditLogs table.
    # 10 most recent entries.
    cursor.execute("""
        SELECT timestamp, action, description 
        FROM auditLogs 
        WHERE user_id = %s 
        ORDER BY timestamp DESC 
        LIMIT 10
    """, (username,))
    activity_logs = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template("driver_profile.html", user=user_info, activity_logs=activity_logs)


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

        # Active sponsor and its balance
        active_sponsor = _get_active_sponsor(username)
        points_balance = _get_points(username, active_sponsor) if active_sponsor else 0

        # Recent point history (same as before)
        cursor.execute("""
            SELECT timestamp, action, description
            FROM auditLogs
            WHERE (action='add points' OR action='remove points')
              AND (description LIKE %s OR description LIKE %s)
            ORDER BY timestamp DESC
            LIMIT 50
        """, (f'% to {username}%', f'% from {username}%'))
        history = cursor.fetchall()

        # All accepted sponsors + per-sponsor points (LEFT JOIN to default to 0)
        cursor.execute("""
            SELECT da.sponsor,
                   COALESCE(dsp.points, 0) AS points
            FROM driverApplications da
            LEFT JOIN driver_sponsor_points dsp
              ON dsp.driver_username = da.driverUsername
             AND dsp.sponsor = da.sponsor
            WHERE da.driverUsername = %s
              AND da.status = 'accepted'
            ORDER BY da.sponsor ASC
        """, (username,))
        sponsor_points = cursor.fetchall()  # list of dicts: {'sponsor': ..., 'points': ...}

        cursor.close()
        db.close()

    except Exception as e:
        return f"<h2>Database error:</h2><p>{e}</p>"

    return render_template(
        "dashboard.html",
        active_sponsor=active_sponsor,
        points_balance=points_balance,
        sponsor_points=sponsor_points,
        history=history
    )

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

        # Get driver's delivery address from profile
        cur.execute("SELECT address FROM drivers WHERE username=%s", (username,))
        addr_row = cur.fetchone()
        delivery_address = (addr_row.get('address') or '').strip() if addr_row else ''

        driver_points = _get_points(username, active_sponsor)

        # Load cart with product details
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

        # Tally totals + build items list for email
        total_points = 0
        email_items = []  # <- for orderPlacedEmail
        for line in cart:
            qty = int(line['qty'])
            stock = int(line['stock'])
            cost = int(line['points_cost'])
            if qty <= 0 or stock < qty:
                cur.close(); db.close()
                return "<h3>Not enough stock for one or more items in your cart.</h3>"
            line_points = cost * qty
            total_points += line_points
            email_items.append({
                "name": line['name'],
                "quantity": qty,
                "points": line_points
            })

        if driver_points < total_points:
            cur.close(); db.close()
            return "<h3>You don't have enough points with this sponsor.</h3>"

        # Expected delivery is 1 week after placement (match your orders page)
        from datetime import datetime, timedelta
        expected_date_str = (datetime.now() + timedelta(days=7)).strftime('%b %d, %Y')

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
                qty = int(line['qty'])
                cur.execute("""
                    INSERT INTO orders
                        (user_id, product_id, sponsor, reward_description, point_cost, quantity, delivery_address, status)
                    VALUES
                        (%s,      %s,         %s,      %s,                 %s,         %s,        %s,               'Processing')
                """, (
                    username,
                    int(line['product_id']),
                    active_sponsor,
                    line['name'],
                    int(line['points_cost']) * qty,
                    qty,
                    delivery_address
                ))

                cur.execute("""
                    UPDATE products
                    SET quantity = quantity - %s
                    WHERE product_id=%s
                """, (qty, int(line['product_id'])))

            # Clear only this sponsor's cart lines
            cur.execute("DELETE FROM cart_items WHERE driver_username=%s AND sponsor=%s",
                        (username, active_sponsor))

            db.commit()

            # --- Emails & low-balance logic ---
            cur.execute("SELECT email, points FROM drivers WHERE username=%s", (username,))
            row = cur.fetchone()
            if row:
                # Pull email + prefs for spend_points & orderPlaced
                cur.execute("""
                    SELECT email, receive_emails, spend_points_email
                    FROM drivers
                    WHERE username=%s
                """, (username,))
                prefs = cur.fetchone()

                # Existing: spent points email
                if prefs and prefs['receive_emails'] and prefs['spend_points_email']:
                    send_spent_points_email(prefs['email'], username, total_points)

                # NEW: order placed email (expects items + expected_date_str)
                try:
                    if prefs and prefs.get('receive_emails'):
                        from emailScripts.orderPlacedEmail import send_order_placed_email
                        send_order_placed_email(
                            recipient=prefs.get('email'),
                            username=username,
                            sponsor=active_sponsor,
                            total_points=total_points,
                            delivery_address=delivery_address,
                            items=email_items,
                            expected_date_str=expected_date_str
                        )
                except Exception as mail_err:
                    print(f"[orderPlacedEmail] Failed to send: {mail_err}")

                # Low balance alert uses overall drivers.points per your existing code
                pts = int(row['points'])
                if pts < 50:
                    cur.execute("""
                        SELECT email, receive_emails, low_balance_email
                        FROM drivers
                        WHERE username=%s
                    """, (username,))
                    prefs_low = cur.fetchone()
                    if prefs_low and prefs_low['receive_emails'] and prefs_low['low_balance_email']:
                        send_low_balance_email(prefs_low['email'], username, pts, 50)

        except Exception as e:
            db.rollback()
            cur.close(); db.close()
            return f"<h3>Checkout failed: {e}</h3>"

        cur.close(); db.close()
        return redirect(url_for('orders_page'))

    except Exception as e:
        return f"<h3>Database error during checkout: {e}</h3>"


@app.route("/orders")
def orders_page():
    if "user" not in session or session.get("role") != "driver":
        return redirect(url_for("login"))

    username = session["user"]

    db = MySQLdb.connect(**db_config)

    # Auto-promote statuses
    _promote_processing_to_shipped(db)
    _promote_shipped_to_delivered(db)

    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # Active sponsor and current point balance
    active_sponsor = _get_active_sponsor(username)
    points_balance = _get_points(username, active_sponsor) if active_sponsor else 0

    # Join drivers to get address; prefer order's delivery_address if present
    cur.execute("""
        SELECT 
            o.order_id,
            o.product_id,
            o.reward_description,
            o.point_cost,
            o.quantity,
            o.status,
            DATE(o.order_date) AS order_date,
            DATE(o.order_date + INTERVAL 7 DAY) AS expected_date,
            COALESCE(o.delivery_address, d.address) AS delivery_address
        FROM orders o
        JOIN drivers d ON d.username = o.user_id
        WHERE o.user_id = %s
        ORDER BY o.order_date DESC, o.order_id DESC
    """, (username,))
    orders = cur.fetchall()

    cur.close()
    db.close()

    return render_template("orders.html", orders=orders, points_balance=points_balance)


# ========== NEW ROUTE ==========
@app.post("/orders/<int:order_id>/update_address")
def orders_update_address(order_id):
    """Allow a driver to update delivery address for a Processing order"""
    if "user" not in session or session.get("role") != "driver":
        return redirect(url_for("login"))

    username = session["user"]
    new_address = (request.form.get("delivery_address") or "").strip()

    if not new_address:
        flash("Address cannot be empty.", "warning")
        return redirect(url_for("orders_page"))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # Ensure it's your order and still in Processing
    cur.execute("""
        SELECT order_id, status
        FROM orders
        WHERE order_id=%s AND user_id=%s
    """, (order_id, username))
    o = cur.fetchone()

    if not o:
        cur.close()
        db.close()
        flash("Order not found.", "danger")
        return redirect(url_for("orders_page"))

    if o["status"] != "Processing":
        cur.close()
        db.close()
        flash("Only Processing orders can be updated.", "warning")
        return redirect(url_for("orders_page"))

    # Update the order's delivery address
    cur.execute("""
        UPDATE orders
        SET delivery_address = %s
        WHERE order_id = %s AND user_id = %s
    """, (new_address, order_id, username))
    db.commit()

    cur.close()
    db.close()

    flash("Delivery address updated for this order.", "success")
    return redirect(url_for("orders_page"))

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
        SELECT order_id, user_id, product_id, point_cost, quantity, status, sponsor
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

        # 2) Refund points to the correct (driver, sponsor) bucket
        #    Use upsert so we handle the case where the row might not exist yet.
        cur.execute("""
            INSERT INTO driver_sponsor_points (driver_username, sponsor, points)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE points = points + VALUES(points)
        """, (username, o['sponsor'], int(o['point_cost'])))

        # 3) Restock if product still exists (it may have been deleted after checkout)
        cur.execute("SELECT product_id FROM products WHERE product_id=%s", (o['product_id'],))
        exists = cur.fetchone()
        if exists:
            cur.execute("""
                UPDATE products
                SET quantity = quantity + %s
                WHERE product_id=%s
            """, (int(o['quantity']), o['product_id']))

        # 4) (Optional) Audit log
        try:
            cur.execute("""
                INSERT INTO auditLogs (action, description, user_id)
                VALUES (%s, %s, %s)
            """, (
                "order_cancelled",
                f"{username} cancelled order {o['order_id']} and was refunded {int(o['point_cost'])} points from sponsor {o['sponsor']}.",
                username
            ))
        except Exception:
            # Don't break cancel if audit insert fails
            pass

        db.commit()

    except Exception as e:
        db.rollback()
        cur.close(); db.close()
        return f"<h3>Cancel failed: {e}</h3>"

    cur.close(); db.close()

    # Send cancellation email (kept from your original flow)
    email = get_email_by_username(username)
    cancelledPurchase.send_cancelled_purchase_email(email, username)

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

def _assign_driver_to_sponsor(driver_username: str, sponsor_username: str):
    """
    Ensure (driver, sponsor) is an accepted relationship in driverApplications,
    and ensure a driver_sponsor_points row exists.
    Returns (created_or_updated: bool, message: str).
    """
    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Check existing app
        cur.execute("""
            SELECT id, status
            FROM driverApplications
            WHERE driverUsername=%s AND sponsor=%s
            ORDER BY id DESC
            LIMIT 1
        """, (driver_username, sponsor_username))
        row = cur.fetchone()

        if row:
            if row['status'] == 'accepted':
                # Nothing to change
                created_or_updated = False
                msg = "Driver is already accepted by this sponsor."
            elif row['status'] in ('pending', 'rejected', 'withdrawn', 'dropped'):
                # Promote/update to accepted
                cur.execute("""
                    UPDATE driverApplications
                    SET status='accepted', updated_at=NOW()
                    WHERE id=%s
                """, (row['id'],))
                db.commit()
                created_or_updated = True
                msg = "Existing application updated to accepted."
        else:
            # Create a new accepted application record
            cur.execute("""
                INSERT INTO driverApplications (driverUsername, sponsor, status, created_at, updated_at)
                VALUES (%s, %s, 'accepted', NOW(), NOW())
            """, (driver_username, sponsor_username))
            db.commit()
            created_or_updated = True
            msg = "New accepted sponsorship created."

        # Ensure a per-(driver,sponsor) points row exists
        cur.execute("""
            INSERT IGNORE INTO driver_sponsor_points (driver_username, sponsor, points)
            VALUES (%s, %s, 0)
        """, (driver_username, sponsor_username))
        db.commit()

        # Audit log
        cur.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("assign_driver",
             f"Admin assigned {driver_username} to sponsor {sponsor_username}.",
             session.get('user') or 'system')
        )
        db.commit()

        return created_or_updated, msg
    finally:
        cur.close()
        db.close()

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
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Insert product
        cursor.execute(
            "INSERT INTO products (name, sponsor, points_cost, quantity, source_type) VALUES (%s, %s, %s, %s, 'local')",
            (name, sponsor_name, points_cost, quantity)
        )
        db.commit()

        # Notify accepted drivers of this sponsor (respect receive_emails)
        try:
            cursor.execute("""
                SELECT d.username AS driver_username, d.email
                FROM driverApplications da
                JOIN drivers d ON d.username = da.driverUsername
                WHERE da.sponsor=%s
                  AND da.status='accepted'
                  AND COALESCE(d.receive_emails, 1)=1
            """, (sponsor_name,))
            subs = cursor.fetchall() or []
            for row in subs:
                email = row.get("email")
                uname = row.get("driver_username")
                if email:
                    try:
                        send_new_item_email(
                            recipient=email,
                            driver_username=uname,
                            sponsor_name=sponsor_name,
                            item_name=name,
                            points_cost=int(points_cost)
                        )
                    except Exception as mail_err:
                        print(f"[newCatalogItemEmail] Failed for {uname}: {mail_err}")
        except Exception as notif_err:
            print(f"[newCatalogItemEmail] Lookup failure: {notif_err}")

        cursor.close()
        db.close()
    except Exception as e:
        # If AJAX/fetch, return JSON error; otherwise page error
        if request.headers.get('X-Requested-With') == 'fetch' or request.args.get('ajax') == '1':
            return jsonify({"ok": False, "error": str(e)}), 500
        return f"<h2>Database error:</h2><p>{e}</p>"

    # If AJAX/fetch, return JSON success; otherwise keep old redirect flow
    if request.headers.get('X-Requested-With') == 'fetch' or request.args.get('ajax') == '1':
        return jsonify({"ok": True})

    flash("Product added and drivers notified.", "success")
    return redirect(url_for('catalog_manager'))

@app.post("/edit_product/<int:product_id>")
def edit_product(product_id):
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor_name = session['user']
    points_cost_raw = request.form.get('points_cost', '').strip()
    quantity_raw    = request.form.get('quantity', '').strip()

    # Basic validation
    try:
        points_cost = int(points_cost_raw)
        quantity    = int(quantity_raw)
        if points_cost < 0 or quantity < 0:
            flash("Points and quantity must be non-negative integers.", "warning")
            return redirect(url_for('catalog_manager'))
    except ValueError:
        flash("Please enter valid whole numbers for points and quantity.", "warning")
        return redirect(url_for('catalog_manager'))

    try:
        db  = MySQLdb.connect(**db_config)
        cur = db.cursor(MySQLdb.cursors.DictCursor)

        # ---- Load current product (to detect 0 -> >0 transition) ----
        cur.execute("""
            SELECT product_id, name, sponsor, points_cost AS old_points, quantity AS old_qty
            FROM products
            WHERE product_id=%s AND sponsor=%s
            LIMIT 1
        """, (product_id, sponsor_name))
        prod = cur.fetchone()

        if not prod:
            cur.close(); db.close()
            flash("Could not update: product not found or not owned by you.", "danger")
            return redirect(url_for('catalog_manager'))

        was_out_of_stock   = int(prod.get("old_qty") or 0) == 0
        will_be_in_stock   = quantity > 0

        # ---- Update product ----
        cur.execute("""
            UPDATE products
               SET points_cost=%s,
                   quantity=%s
             WHERE product_id=%s
               AND sponsor=%s
        """, (points_cost, quantity, product_id, sponsor_name))
        db.commit()

        if cur.rowcount == 0:
            cur.close(); db.close()
            flash("Could not update: product not found or not owned by you.", "danger")
            return redirect(url_for('catalog_manager'))

        # ---- If it just came back in stock, notify favoriting drivers ----
        if was_out_of_stock and will_be_in_stock:
            try:
                # All drivers who favorited this product and accept emails
                cur.execute("""
                    SELECT f.driver_username, d.email
                    FROM favorites f
                    JOIN drivers d ON d.username = f.driver_username
                    WHERE f.product_id=%s
                      AND COALESCE(d.receive_emails, 1) = 1
                """, (product_id,))
                subs = cur.fetchall() or []

                for row in subs:
                    recipient = row.get("email")
                    uname     = row.get("driver_username")
                    if recipient:
                        try:
                            send_favorite_restock_email(
                                recipient=recipient,
                                username=uname,
                                item_name=prod["name"],
                                sponsor_name=sponsor_name,
                                quantity=quantity
                            )
                        except Exception as mail_err:
                            # Log but don't fail the request
                            print(f"[favoriteRestockEmail] Failed for user={uname}: {mail_err}")
            except Exception as lookup_err:
                # Log but don't fail the request
                print(f"[favoriteRestockEmail] Lookup error: {lookup_err}")

        cur.close(); db.close()
        flash("Product updated successfully.", "success")
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        flash(f"Database error while updating product: {e}", "danger")

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
            # --- Password Validation (Moved to top) ---
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if password: # User is trying to update their password
                if password != confirm_password:
                    flash('Passwords do not match. Please try again.', 'danger')
                    return redirect(url_for('settings')) 
                
                is_valid, message = check_password_strength(password)
                if not is_valid:
                    flash(message, 'danger') # e.g., "Password must contain a number."
                    return redirect(url_for('settings'))
            # --- END of validation ---

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

            # --- Driver required fields enforcement ---
            if role == 'driver':
                # Find the driver's sponsor
                cursor.execute("""
                    SELECT sponsor FROM driver_sponsor_points WHERE driver_username=%s
                """, (username,))
                sponsor_row = cursor.fetchone()
            
                if sponsor_row:
                    sponsor = sponsor_row['sponsor']
            
                    # Check what fields are required for this sponsor
                    cursor.execute("""
                        SELECT field_name FROM sponsor_field_requirements
                        WHERE sponsor_username=%s AND is_required=1
                    """, (sponsor,))
                    required_fields = [r['field_name'] for r in cursor.fetchall()]
            
                    missing = []
                    for f in required_fields:
                        val = request.form.get(f)
                        if not val or val.strip() == "":
                            missing.append(f.replace("_", " ").title())
            
                    if missing:
                        flash(f"Your sponsor requires: {', '.join(missing)}", "warning")
                        cursor.close(); db.close()
                        return redirect(url_for('settings'))
            # --- Remove trailing comma and add WHERE ---
            update_query = update_query.rstrip(', ') + " WHERE username=%s"
            update_fields.append(username)
            cursor.execute(update_query, tuple(update_fields))

            # --- Password ---
            # password = request.form.get('password')
            # confirm_password = request.form.get('confirm_password')
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

@app.route('/recurring_reports')
def recurring_reports():
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM recurring_reports")
    reports = cursor.fetchall()

    # fetch sponsors for dropdown
    cursor.execute("SELECT username FROM sponsor")
    sponsors = cursor.fetchall()

    # example report types
    report_types = [
        'Sponsor Sales Summary',
        'Invoice Report',
        'Driver Activity',
        'Point Summary'
    ]
    db.close()

    return render_template(
    'recurring_reports.html',
    reports=reports,
    sponsors=sponsors,
    report_types=report_types
)

# ---------------------------
# Add Recurring Report
# ---------------------------
@app.route('/recurring_reports/add', methods=['POST'])
def add_recurring_report():
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    report_type = request.form.get('report_type')
    sponsor_id = request.form.get('sponsor')
    day_of_week = request.form.get('day_of_week')

    if not report_type or not sponsor_id or not day_of_week:
        flash("All fields are required.", "danger")
        return redirect(url_for('recurring_reports'))

    cursor.execute(
        "INSERT INTO recurring_reports (report_type, sponsor_id, day_of_week) VALUES (%s, %s, %s)",
        (report_type, sponsor_id, day_of_week)
    )
    db.commit()
    db.close()
    flash("Recurring report added successfully!", "success")
    return redirect(url_for('recurring_reports'))

# ---------------------------
# Toggle Enabled/Disabled
# ---------------------------
@app.route('/recurring_reports/toggle/<int:report_id>')
def toggle_recurring_report(report_id):
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT enabled FROM recurring_reports WHERE id = %s", (report_id,))
    report = cursor.fetchone()
    if report:
        new_status = not report['enabled']
        cursor.execute("UPDATE recurring_reports SET enabled = %s WHERE id = %s", (new_status, report_id))
        db.commit()
        flash("Recurring report status updated.", "success")
    db.close()
    return redirect(url_for('recurring_reports'))

# ---------------------------
# Delete Recurring Report
# ---------------------------
@app.route('/recurring_reports/delete/<int:report_id>')
def delete_recurring_report(report_id):
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("DELETE FROM recurring_reports WHERE id = %s", (report_id,))
    db.commit()
    db.close()
    flash("Recurring report deleted.", "success")
    return redirect(url_for('recurring_reports'))


@app.route('/update_notifications', methods=['POST'])
def update_notifications():
    if 'user' not in session or 'role' not in session:
        return redirect(url_for('login'))

    username = session['user']
    role = session['role']

    # Correct table names by role
    table_by_role = {'driver': 'drivers', 'sponsor': 'sponsors', 'admin': 'admins'}
    table = table_by_role.get(role)
    if not table:
        flash("Unknown role.", "danger")
        return redirect(url_for('settings'))

    form = request.form

    # Checkbox -> 0/1 helper
    def cb(name): 
        return 1 if name in form else 0

    try:
        db = MySQLdb.connect(**db_config)
        cur = db.cursor(MySQLdb.cursors.DictCursor)

        if role == 'driver':
            # Includes the three NEW prefs
            cur.execute(f"""
                UPDATE {table}
                   SET receive_emails=%s,
                       login_email=%s,
                       low_balance_email=%s,
                       points_added_email=%s,
                       points_removed_email=%s,
                       driver_dropped_email=%s,
                       spend_points_email=%s,
                       favorite_back_in_stock_email=%s,
                       new_item_email=%s,
                       order_placed_email=%s
                 WHERE username=%s
            """, (
                cb('receive_emails'),
                cb('login_email'),
                cb('low_balance_email'),
                cb('points_added_email'),
                cb('points_removed_email'),
                cb('driver_dropped_email'),
                cb('spend_points_email'),
                cb('favorite_back_in_stock_email'),
                cb('new_item_email'),
                cb('order_placed_email'),
                username
            ))

        elif role == 'sponsor':
            cur.execute(f"""
                UPDATE {table}
                   SET receive_emails=%s,
                       login_email=%s,
                       driver_app_email=%s
                 WHERE username=%s
            """, (
                cb('receive_emails'),
                cb('login_email'),
                cb('driver_app_email'),
                username
            ))

        elif role == 'admin':
            cur.execute(f"""
                UPDATE {table}
                   SET receive_emails=%s,
                       login_email=%s,
                       sponsor_locked_email=%s
                 WHERE username=%s
            """, (
                cb('receive_emails'),
                cb('login_email'),
                cb('sponsor_locked_email'),
                username
            ))

        db.commit()
        cur.close(); db.close()
        flash("Notification preferences updated successfully.", "success")

    except Exception as e:
        flash(f"Error updating preferences: {e}", "danger")

    return redirect(url_for('settings'))

@app.route('/sponsor_requirements', methods=['GET', 'POST'])
def sponsor_requirements():
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']
    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # Default fields to control
    fields = ['address', 'phone', 'twitter', 'facebook', 'instagram', 'vehicle_make', 'vehicle_model', 'vehicle_year']

    if request.method == 'POST':
        # Clear old requirements
        cur.execute("DELETE FROM sponsor_field_requirements WHERE sponsor_username=%s", (sponsor,))
        # Insert updated requirements
        for f in fields:
            if request.form.get(f):  # checkbox selected
                cur.execute("""
                    INSERT INTO sponsor_field_requirements (sponsor_username, field_name, is_required)
                    VALUES (%s, %s, 1)
                """, (sponsor, f))
        db.commit()
        flash("Field requirements updated successfully.", "success")

    # Load current settings
    cur.execute("""
        SELECT field_name FROM sponsor_field_requirements
        WHERE sponsor_username=%s AND is_required=1
    """, (sponsor,))
    required_fields = {row['field_name'] for row in cur.fetchall()}
    cur.close(); db.close()

    return render_template('sponsor_requirements.html',
                           fields=fields, required_fields=required_fields)
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
        
        # --- Password Validation ---
        is_valid, message = check_password_strength(new_password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('add_user'))
        # --- END OF validation ---

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
    return render_template("add_user.html", can_create_admin=(requester_role == 'admin'))

@app.route('/drivers')
def drivers():
    # Only sponsors/admins can access
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    try:
        if session.get('role') == 'sponsor':
            # ✅ Sponsor view (unchanged logic from earlier fix): only their accepted drivers,
            # and points pulled from driver_sponsor_points for THIS sponsor.
            cur.execute("""
                SELECT d.username,
                       d.email,
                       d.disabled,
                       COALESCE(dsp.points, 0) AS points
                FROM driverApplications a
                JOIN drivers d
                  ON d.username = a.driverUsername
                LEFT JOIN driver_sponsor_points dsp
                  ON dsp.driver_username = a.driverUsername
                 AND dsp.sponsor = a.sponsor
                WHERE a.sponsor=%s
                  AND a.status='accepted'
                ORDER BY d.username
            """, (session['user'],))
            drivers_list = cur.fetchall()
            role = 'sponsor'

        else:
            # ✅ Admin view: every driver, with ALL accepted sponsors + per-sponsor points
            # Build one row per driver; sponsors+points packed into a string to keep it simple in template.
            cur.execute("""
                SELECT
                    d.username,
                    d.email,
                    d.disabled,
                    -- Pack "sponsor::points" per sponsor; only accepted relationships
                    GROUP_CONCAT(CONCAT(dsp.sponsor, '::', COALESCE(dsp.points,0))
                                 ORDER BY dsp.sponsor SEPARATOR '||') AS sponsors_points
                FROM drivers d
                LEFT JOIN driverApplications da
                  ON da.driverUsername = d.username
                 AND da.status = 'accepted'
                LEFT JOIN driver_sponsor_points dsp
                  ON dsp.driver_username = d.username
                 AND dsp.sponsor = da.sponsor
                GROUP BY d.username, d.email, d.disabled
                ORDER BY d.username
            """)
            drivers_list = cur.fetchall()
            role = 'admin'

    finally:
        cur.close()
        db.close()

    return render_template("drivers.html", drivers=drivers_list, role=role)


@app.route('/driver/<username>', methods=['GET', 'POST'])
def sponsor_edit_driver(username):
    # Now BOTH sponsors and admins can use this route
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    role = session.get('role')
    current_user = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # Authorization:
    # - Sponsor: must actually sponsor this driver (same check as before)
    # - Admin: can edit any driver
    if role == 'sponsor':
        cursor.execute("""
            SELECT COUNT(*) AS valid
            FROM driverApplications
            WHERE driverUsername=%s AND sponsor=%s AND status='accepted'
        """, (username, current_user))
        valid = cursor.fetchone()
        if not valid or valid['valid'] == 0:
            flash("You are not authorized to edit this driver.", "danger")
            cursor.close()
            db.close()
            return redirect(url_for('drivers'))
    else:
        # Admin: just make sure the driver exists
        cursor.execute("SELECT COUNT(*) AS cnt FROM drivers WHERE username=%s", (username,))
        row = cursor.fetchone()
        if not row or row['cnt'] == 0:
            flash("Driver not found.", "danger")
            cursor.close()
            db.close()
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
    cursor.close()
    db.close()

    return render_template("sponsor_edit_driver.html", driver=driver)

@app.route('/sponsor/drop_driver', methods=['POST'])
def sponsor_drop_driver():
    # Must be logged in as sponsor
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))

    sponsor = session['user']
    username = request.form.get('username')

    if not username:
        flash("Invalid request.", "danger")
        return redirect(url_for('drivers'))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Ensure this sponsor–driver relationship exists and is currently accepted
        cur.execute("""
            SELECT 1
            FROM driverApplications
            WHERE driverUsername=%s AND sponsor=%s AND status='accepted'
            LIMIT 1
        """, (username, sponsor))
        row = cur.fetchone()
        if not row:
            flash("You are not authorized to drop this driver or they are not currently accepted.", "danger")
            return redirect(url_for('drivers'))

        # Soft drop the relationship (preserve history)
        cur.execute("""
            UPDATE driverApplications
            SET status='dropped'
            WHERE driverUsername=%s AND sponsor=%s AND status='accepted'
        """, (username, sponsor))

        # Remove per-sponsor points so they cannot be used after the drop
        cur.execute("""
            DELETE FROM driver_sponsor_points
            WHERE driver_username=%s AND sponsor=%s
        """, (username, sponsor))

        db.commit()
        flash(f"Driver '{username}' has been dropped.", "success")

    except Exception as e:
        db.rollback()
        flash("An error occurred while dropping the driver.", "danger")
    finally:
        cur.close()
        db.close()

    return redirect(url_for('drivers'))


@app.route('/sponsors')
def sponsors():
    # Only sponsors/admins can access
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        if session.get('role') == 'sponsor':
            # Look up this sponsor's organization
            cursor.execute("SELECT organization FROM sponsor WHERE username=%s", (session['user'],))
            row = cursor.fetchone()
            org = row['organization'] if row else None

            # Show only sponsors from the same organization (including self)
            cursor.execute("""
                SELECT username, email, disabled, organization
                FROM sponsor
                WHERE organization <=> %s
                ORDER BY username
            """, (org,))
        else:
            # Admins see all sponsors
            cursor.execute("""
                SELECT username, email, disabled, organization
                FROM sponsor
                ORDER BY organization IS NULL, organization, username
            """)

        sponsors_list = cursor.fetchall()
        cursor.close()
        db.close()

    except Exception as e:
        flash(f"Database error loading sponsors list: {e}", "danger")
        sponsors_list = []

    return render_template("sponsors.html", sponsors=sponsors_list, role=session.get('role'))

@app.route('/message_sponsor', methods=['GET'])
def message_sponsor_page():
    if 'user' not in session or session.get('role') not in ['admin', 'sponsor']:
        return redirect(url_for('login'))

    role = session.get('role')
    current_user = session['user']
    username = request.args.get('username', '').strip()

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    if role == 'admin':
        # Admin can message any sponsor
        cur.execute("""
            SELECT username, email, disabled
            FROM sponsor
            WHERE username = %s
            LIMIT 1
        """, (username,))
    else:
        # Sponsor can only message sponsors in their organization
        # First get current sponsor's organization
        cur.execute("""
            SELECT organization
            FROM sponsor
            WHERE username = %s
            LIMIT 1
        """, (current_user,))
        row = cur.fetchone()
        org = row['organization'] if row else None

        # Now ensure target sponsor is in same org (NULL-safe using <=>)
        cur.execute("""
            SELECT username, email, disabled
            FROM sponsor
            WHERE username = %s
              AND organization <=> %s
            LIMIT 1
        """, (username, org))

    sponsor = cur.fetchone()
    cur.close()
    db.close()

    if not sponsor:
        if role == 'admin':
            flash("Sponsor not found.", "danger")
        else:
            flash("You can only message sponsors within your organization.", "danger")
        return redirect(url_for('sponsors'))

    if sponsor['disabled']:
        flash("Cannot message a disabled sponsor.", "warning")
        return redirect(url_for('sponsors'))

    return render_template('message_sponsor.html', sponsor=sponsor)

@app.route('/message_sponsor/send', methods=['POST'])
def message_sponsor_send():
    if 'user' not in session or session.get('role') not in ['admin', 'sponsor']:
        return redirect(url_for('login'))

    role = session.get('role')
    actor = session['user']

    sponsor_username = request.form.get('sponsor_username', '').strip()
    subject = request.form.get('subject', '').strip()
    message = request.form.get('message', '').strip()

    if not sponsor_username or not subject or not message:
        flash("All fields are required.", "warning")
        return redirect(url_for('sponsors'))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # Validate target sponsor + org rules
    if role == 'admin':
        cur.execute("""
            SELECT email, disabled
            FROM sponsor
            WHERE username=%s
            LIMIT 1
        """, (sponsor_username,))
    else:
        # Sponsor -> must be same org
        cur.execute("""
            SELECT organization
            FROM sponsor
            WHERE username=%s
            LIMIT 1
        """, (actor,))
        row = cur.fetchone()
        org = row['organization'] if row else None

        cur.execute("""
            SELECT email, disabled
            FROM sponsor
            WHERE username=%s
              AND organization <=> %s
            LIMIT 1
        """, (sponsor_username, org))

    row = cur.fetchone()

    if not row:
        cur.close()
        db.close()
        if role == 'admin':
            flash("Sponsor not found.", "danger")
        else:
            flash("You can only message sponsors within your organization.", "danger")
        return redirect(url_for('sponsors'))

    if row['disabled']:
        cur.close()
        db.close()
        flash("Cannot message a disabled sponsor.", "warning")
        return redirect(url_for('sponsors'))

    sponsor_email = row['email']

    try:
        # Hook up your real email sending here if you like.
        # Example placeholder:
        # send_message_to_sponsor_email(
        #     to_email=sponsor_email,
        #     sponsor_username=sponsor_username,
        #     sender_username=actor,
        #     subject=subject,
        #     message=message
        # )

        # Log to auditLogs
        cur = db.cursor()
        actor_label = "Admin" if role == 'admin' else "Sponsor"
        cur.execute("""
            INSERT INTO auditLogs (action, description, user_id)
            VALUES (%s, %s, %s)
        """, (
            "message_sponsor",
            f"{actor_label} '{actor}' messaged sponsor '{sponsor_username}' (subject: {subject})",
            actor
        ))
        db.commit()

        flash("Message recorded (hook up email sending here).", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error while processing message: {e}", "danger")
    finally:
        cur.close()
        db.close()

    return redirect(url_for('sponsors'))

@app.route('/admin/driver/toggle', methods=['POST'])
def admin_toggle_driver():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = request.form.get('username')
    action = request.form.get('action')  # 'disable' or 'enable'

    if not username or action not in ('disable', 'enable'):
        flash("Invalid request.", "danger")
        return redirect(url_for('drivers'))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    try:
        cur.execute("SELECT username FROM drivers WHERE username=%s LIMIT 1", (username,))
        if not cur.fetchone():
            flash("Driver not found.", "danger")
            return redirect(url_for('drivers'))

        new_disabled = 1 if action == 'disable' else 0
        cur.execute("UPDATE drivers SET disabled=%s WHERE username=%s", (new_disabled, username))
        db.commit()

        flash(f"Driver '{username}' has been {'disabled' if new_disabled else 'enabled'}.", "success")
    except Exception:
        db.rollback()
        flash("An error occurred while updating the driver status.", "danger")
    finally:
        cur.close()
        db.close()

    return redirect(url_for('drivers'))


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
            driver_email = driver['email']
            cursor.execute("SELECT receive_emails, driver_dropped_email FROM drivers WHERE username=%s", (driver_username,))
            prefs = cursor.fetchone()
            if prefs and prefs['receive_emails'] and prefs['driver_dropped_email']:
                send_driver_dropped_email(driver_email, driver_username, sponsor_username)

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
    # Ensure only sponsors or admins can impersonate
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    original_user = session['user']
    original_role = session.get('role')
    target_driver = request.form['username']

    # Check that driver exists and isn't disabled
    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT disabled FROM drivers WHERE username=%s", (target_driver,))
    driver = cur.fetchone()
    if not driver:
        cur.close()
        db.close()
        flash("Driver not found.", "warning")
        return redirect(url_for('drivers'))

    if driver['disabled']:
        cur.close()
        db.close()
        flash("Cannot impersonate a disabled driver.", "warning")
        return redirect(url_for('drivers'))

    # Log impersonation in auditLogs
    actor_label = "Sponsor" if original_role == 'sponsor' else "Admin"
    cur.execute("""
        INSERT INTO auditLogs (action, description, user_id)
        VALUES (%s, %s, %s)
    """, (
        "impersonation",
        f"{actor_label} '{original_user}' impersonated driver '{target_driver}'.",
        original_user
    ))
    db.commit()
    cur.close()
    db.close()

    # Impersonate by setting session
    session['impersonated_user'] = target_driver
    session['original_user'] = original_user
    session['original_role'] = original_role
    session['user'] = target_driver
    session['role'] = 'driver'

    flash(f"You are now logged in as {target_driver}.", "info")
    return redirect(url_for('driver_profile'))


@app.route('/stop_impersonation')
def stop_impersonation():
    if 'original_user' not in session or 'original_role' not in session:
        flash("No active impersonation session.", "warning")
        return redirect(url_for('dashboard'))

    original_user = session['original_user']
    original_role = session['original_role']

    # Log that impersonation ended
    db = MySQLdb.connect(**db_config)
    cur = db.cursor()
    cur.execute("""
        INSERT INTO auditLogs (action, description, user_id)
        VALUES (%s, %s, %s)
    """, (
        "stop_impersonation",
        f"User '{original_user}' ended impersonation session.",
        original_user
    ))
    db.commit()
    cur.close()
    db.close()

    # Restore session
    session['user'] = original_user
    session['role'] = original_role
    session.pop('impersonated_user', None)
    session.pop('original_user', None)
    session.pop('original_role', None)

    flash("You have returned to your original account.", "success")

    # Send them somewhere sensible based on role
    if original_role in ['sponsor', 'admin']:
        return redirect(url_for('drivers'))
    else:
        return redirect(url_for('dashboard'))


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

@app.route('/points', methods=['GET'])
def points_page():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    role = session.get('role')
    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    try:
        if role == 'sponsor':
            # This sponsor's accepted drivers + current points
            cur.execute("""
                SELECT d.username AS driver_username,
                       d.email AS driver_email,
                       COALESCE(p.points, 0) AS points
                  FROM driverApplications a
                  JOIN drivers d
                    ON d.username = a.driverUsername
             LEFT JOIN driver_sponsor_points p
                    ON p.driver_username = a.driverUsername
                   AND p.sponsor = a.sponsor
                 WHERE a.sponsor = %s
                   AND a.status = 'accepted'
                 ORDER BY d.username
            """, (session['user'],))
            sponsor_rows = cur.fetchall()
            return render_template('points_manage.html', role='sponsor', sponsor_rows=sponsor_rows, admin_rows=None)

        # Admin: all accepted pairs
        cur.execute("""
            SELECT d.username AS driver_username,
                   d.email    AS driver_email,
                   a.sponsor  AS sponsor,
                   COALESCE(p.points, 0) AS points
              FROM driverApplications a
              JOIN drivers d
                ON d.username = a.driverUsername
         LEFT JOIN driver_sponsor_points p
                ON p.driver_username = a.driverUsername
               AND p.sponsor = a.sponsor
             WHERE a.status='accepted'
             ORDER BY d.username, a.sponsor
        """)
        pairs = cur.fetchall()

        # Group by driver
        from collections import defaultdict
        grouped = defaultdict(list)
        for r in pairs:
            grouped[(r['driver_username'], r['driver_email'])].append({'sponsor': r['sponsor'], 'points': r['points']})

        admin_rows = []
        for (du, de), sponsor_list in grouped.items():
            admin_rows.append({'driver_username': du, 'driver_email': de, 'sponsors': sponsor_list})

        return render_template('points_manage.html', role='admin', sponsor_rows=None, admin_rows=admin_rows)
    finally:
        cur.close()
        db.close()

@app.route('/sponsor/message_driver', methods=['GET'])
def sponsor_message_driver_page():
    # Allow BOTH sponsors and admins
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    role = session.get('role')
    actor = session['user']
    username = request.args.get('username', '').strip()

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    if role == 'sponsor':
        # Original behavior: can only message drivers you currently sponsor
        cur.execute("""
            SELECT d.username, d.email, d.disabled,
                   COALESCE(d.receive_emails, 1) AS receive_emails
            FROM drivers d
            JOIN driver_sponsor_points dsp
              ON dsp.driver_username = d.username
            WHERE d.username=%s AND dsp.sponsor=%s
            LIMIT 1
        """, (username, actor))
    else:
        # Admin: can message ANY driver
        cur.execute("""
            SELECT d.username, d.email, d.disabled,
                   COALESCE(d.receive_emails, 1) AS receive_emails
            FROM drivers d
            WHERE d.username=%s
            LIMIT 1
        """, (username,))

    driver = cur.fetchone()
    cur.close()
    db.close()

    if not driver:
        if role == 'sponsor':
            flash("You can only message drivers you currently sponsor.", "danger")
        else:
            flash("Driver not found.", "danger")
        return redirect(url_for('drivers'))

    if driver['disabled']:
        flash("Cannot message a disabled driver.", "warning")
        return redirect(url_for('drivers'))

    return render_template('message_driver.html', driver=driver)


@app.route('/sponsor/message_driver/send', methods=['POST'])
def sponsor_message_driver_send():
    # Allow BOTH sponsors and admins
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    role = session.get('role')
    actor = session['user']

    driver_username = request.form.get('driver_username', '').strip()
    subject = request.form.get('subject', '').strip()
    message = request.form.get('message', '').strip()

    if not driver_username or not subject or not message:
        flash("All fields are required.", "warning")
        return redirect(url_for('drivers'))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # Verify permissions + fetch driver email
    if role == 'sponsor':
        cur.execute("""
            SELECT d.email, d.disabled, COALESCE(d.receive_emails,1) AS receive_emails
            FROM drivers d
            JOIN driver_sponsor_points dsp
              ON dsp.driver_username = d.username
            WHERE d.username=%s AND dsp.sponsor=%s
            LIMIT 1
        """, (driver_username, actor))
    else:
        # Admin: just load driver directly
        cur.execute("""
            SELECT d.email, d.disabled, COALESCE(d.receive_emails,1) AS receive_emails
            FROM drivers d
            WHERE d.username=%s
            LIMIT 1
        """, (driver_username,))

    row = cur.fetchone()

    if not row:
        cur.close()
        db.close()
        if role == 'sponsor':
            flash("You can only message drivers you currently sponsor.", "danger")
        else:
            flash("Driver not found.", "danger")
        return redirect(url_for('drivers'))

    if row['disabled']:
        cur.close()
        db.close()
        flash("Cannot message a disabled driver.", "warning")
        return redirect(url_for('drivers'))

    if not row['receive_emails']:
        cur.close()
        db.close()
        flash("This driver has opted out of emails.", "warning")
        return redirect(url_for('drivers'))

    try:
        # Reuse same email helper
        send_sponsor_message_email(
            to_email=row['email'],
            driver_username=driver_username,
            sponsor_username=actor,  # for admin, this is the admin username
            subject=subject,
            message=message
        )
        # audit
        cur = db.cursor()
        actor_label = "Sponsor" if role == 'sponsor' else 'Admin'
        cur.execute("""
            INSERT INTO auditLogs (action, description, user_id)
            VALUES (%s, %s, %s)
        """, (
            "sponsor_message",
            f"{actor_label} '{actor}' emailed driver '{driver_username}' (subject: {subject})",
            actor
        ))
        db.commit()
        flash("Message sent successfully!", "success")
    except Exception as e:
        db.rollback()
        flash(f"Email failed: {e}", "danger")
    finally:
        cur.close()
        db.close()

    return redirect(url_for('drivers'))

@app.route('/add_points', methods=['POST'])
def add_points():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    role = session.get('role')
    target_driver = request.form['username']
    points = int(request.form['points_to_add'])
    reason = request.form.get('reason', '(no reason provided)').strip()

    performed_by = session['user']
    acting_sponsor = performed_by

    # Allow admins to act in a sponsor context from the form
    if role == 'admin':
        acting_sponsor = request.form.get('as_sponsor', '').strip() or acting_sponsor

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # Ensure driver-sponsor relationship exists and is accepted (especially important for admin)
    cursor.execute("""
        SELECT 1 FROM driverApplications
         WHERE driverUsername=%s AND sponsor=%s AND status='accepted' LIMIT 1
    """, (target_driver, acting_sponsor))
    if not cursor.fetchone():
        flash("No accepted relationship for that driver and sponsor.", "danger")
        cursor.close(); db.close()
        return redirect(url_for('points_page'))

    cursor.execute("SELECT min_points, max_points FROM sponsor WHERE username=%s", (acting_sponsor,))
    sp = cursor.fetchone()
    if not sp:
        flash("Sponsor not found.", "danger");  
        cursor.close(); db.close()
        return redirect(url_for('points_page'))

    cursor.execute("""
        SELECT points FROM driver_sponsor_points
        WHERE driver_username=%s AND sponsor=%s
    """, (target_driver, acting_sponsor))
    row = cursor.fetchone()
    current = int(row['points']) if row and row['points'] is not None else 0
    new_total = current + points

    if new_total > sp['max_points']:
        flash(f"Cannot add points — this would exceed the max of {sp['max_points']} points for {acting_sponsor}.", "warning")
    else:
        cursor.execute("""
            INSERT INTO driver_sponsor_points (driver_username, sponsor, points)
            VALUES (%s,%s,%s)
            ON DUPLICATE KEY UPDATE points = points + VALUES(points)
        """, (target_driver, acting_sponsor, points))
        db.commit()
        cursor.execute("INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                       ("add points", f"{performed_by} added {points} points to {target_driver}. Reason: {reason}", performed_by))
        db.commit()
        flash(f'{points} points were successfully added to "{target_driver}" under {acting_sponsor}.', 'success')

    cursor.close(); db.close()
    return redirect(url_for('points_page'))

@app.route('/remove_points', methods=['POST'])
def remove_points():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    role = session.get('role')
    target_driver = request.form['username']
    points = int(request.form['points_to_remove'])
    reason = request.form.get('reason', '(no reason provided)').strip()

    performed_by = session['user']
    acting_sponsor = performed_by
    if role == 'admin':
        acting_sponsor = request.form.get('as_sponsor', '').strip() or acting_sponsor

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # Ensure accepted relationship
    cursor.execute("""
        SELECT 1 FROM driverApplications
         WHERE driverUsername=%s AND sponsor=%s AND status='accepted' LIMIT 1
    """, (target_driver, acting_sponsor))
    if not cursor.fetchone():
        flash("No accepted relationship for that driver and sponsor.", "danger")
        cursor.close(); db.close()
        return redirect(url_for('points_page'))

    cursor.execute("SELECT min_points, max_points FROM sponsor WHERE username=%s", (acting_sponsor,))
    sp = cursor.fetchone()
    if not sp:
        flash("Sponsor not found.", "danger");  
        cursor.close(); db.close()
        return redirect(url_for('points_page'))

    cursor.execute("""
        SELECT points FROM driver_sponsor_points
        WHERE driver_username=%s AND sponsor=%s
    """, (target_driver, acting_sponsor))
    row = cursor.fetchone()
    current = int(row['points']) if row and row['points'] is not None else 0
    new_total = current - points

    if new_total < sp['min_points']:
        flash(f"Cannot remove points — this would go below the min of {sp['min_points']} points for {acting_sponsor}.", "warning")
    else:
        cursor.execute("""
            UPDATE driver_sponsor_points
               SET points = GREATEST(0, points - %s)
             WHERE driver_username=%s AND sponsor=%s
        """, (points, target_driver, acting_sponsor))
        db.commit()
        cursor.execute("INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                       ("remove points", f"{performed_by} removed {points} points from {target_driver}. Reason: {reason}", performed_by))
        db.commit()
        flash(f'{points} points were successfully removed from "{target_driver}" under {acting_sponsor}.', 'success')

    cursor.close(); db.close()
    return redirect(url_for('points_page'))


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
        
        # --- START OF Password Validation ---
            is_valid, message = check_password_strength(new_password)
            if not is_valid:
                flash(message, 'danger')
                return redirect(url_for('set_new_password', token=token))
            # --- END OF Password validation ---

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

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # --- My Sponsors (accepted only) ---
    cursor.execute("""
        SELECT s.username, s.organization
        FROM driverApplications da
        JOIN sponsor s ON s.username = da.sponsor
        WHERE da.driverUsername = %s
          AND da.status = 'accepted'
        ORDER BY s.username ASC
    """, (username,))
    my_sponsors = cursor.fetchall()

    # --- All sponsors with my current application status (if any) ---
    # We peek at the driver's most recent status per sponsor to drive the UI (badge/disable state).
    cursor.execute("""
        SELECT
            s.username,
            s.organization,
            (
                SELECT da.status
                FROM driverApplications da
                WHERE da.driverUsername = %s
                  AND da.sponsor = s.username
                ORDER BY da.updated_at DESC
                LIMIT 1
            ) AS my_status
        FROM sponsor s
        ORDER BY s.username ASC
    """, (username,))
    sponsors = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "sponsor_browse.html",
        my_sponsors=my_sponsors,
        sponsors=sponsors
    )


@app.route('/apply/<sponsor>', methods=['POST'])
def apply_to_sponsor(sponsor):
    if 'user' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    username = session['user']
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Block only duplicate active app to the SAME sponsor
        cursor.execute("""
            SELECT id FROM driverApplications
            WHERE driverUsername=%s AND sponsor=%s
              AND status IN ('pending','accepted')
        """, (username, sponsor))
        if cursor.fetchone():
            cursor.close(); db.close()
            flash("You already have an active application with this sponsor.", "warning")
            return redirect(url_for('sponsor_browse'))

        # Create application
        cursor.execute("""
            INSERT INTO driverApplications (driverUsername, sponsor, status, created_at, updated_at)
            VALUES (%s, %s, 'pending', NOW(), NOW())
        """, (username, sponsor))
        db.commit()

        # Audit log
        cursor.execute("""
            INSERT INTO auditLogs (action, description, user_id)
            VALUES (%s, %s, %s)
        """, ("application_created", f"{username} applied to sponsor {sponsor}.", username))
        db.commit()

        cursor.close(); db.close()

        flash(f'Your application to "{sponsor}" has been submitted successfully!', 'success')

        # ---- Optional: notify sponsor (safe, separate connection & variables) ----
        try:
            sponsor_email = get_email_by_username(sponsor)  # uses its own connection
            if sponsor_email:
                db2 = MySQLdb.connect(**db_config)
                cur2 = db2.cursor(MySQLdb.cursors.DictCursor)
                cur2.execute("""
                    SELECT receive_emails, driver_app_email
                    FROM sponsor
                    WHERE username=%s
                """, (sponsor,))
                prefs = cur2.fetchone()
                cur2.close(); db2.close()

                if prefs and prefs.get('receive_emails') and prefs.get('driver_app_email'):
                    # Send notification to the sponsor
                    applicationEmail.send_application_email(sponsor_email, sponsor)
        except Exception as notify_err:
            # Don’t break the flow if email fails; optionally log
            print(f"[notify] Failed to notify sponsor {sponsor}: {notify_err}")

        return redirect(url_for('driver_applications'))

    except Exception as e:
        # If anything goes wrong earlier, show a friendly error
        return f"<h2>Error applying to sponsor:</h2><p>{e}</p>"


@app.route('/drop_sponsor/<sponsor>', methods=['POST'])
def drop_sponsor(sponsor):
    if 'user' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor()

    try:
        # Update latest accepted/pending application to dropped
        cursor.execute("""
            UPDATE driverApplications
            SET status='dropped', updated_at=NOW()
            WHERE driverUsername=%s AND sponsor=%s AND status='accepted'
        """, (username, sponsor))
        db.commit()

        # Optional: Keep record clean by also setting points to 0
        cursor.execute("""
            UPDATE driver_sponsor_points
            SET points=0
            WHERE driver_username=%s AND sponsor=%s
        """, (username, sponsor))
        db.commit()

        # Audit log
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("drop_sponsor",
             f"{username} dropped sponsor {sponsor}",
             username)
        )
        db.commit()

        flash(f"You have dropped {sponsor}.", "info")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('sponsor_browse'))


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

    db = None
    cursor = None
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

        # Fetch driver info for email + logging
        cursor.execute("""
            SELECT d.email,
                   d.first_name,
                   a.sponsor,
                   a.driverUsername
            FROM driverApplications a
            JOIN drivers d ON a.driverUsername = d.username
            WHERE a.id=%s
        """, (app_id,))
        driver = cursor.fetchone()

        if driver:
            # Try email, but don't let it crash the request
            try:
                send_decision_email(
                    driver['email'],
                    driver['first_name'],
                    driver['sponsor'],
                    "rejected"
                )
            except Exception as email_err:
                # Optional: log somewhere, but don't break user flow
                print("Email error (reject):", email_err)

            # Log rejecting
            description = f"{sponsor} rejected {driver['driverUsername']}'s application"
            cursor.execute(
                "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                ("application", description, sponsor)
            )
            db.commit()

        return redirect(url_for('sponsor_applications'))

    except Exception as e:
        # This is what's currently giving you the error page
        return f"<h2>Error rejecting application:</h2><p>{e}</p>"
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()

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

@app.route('/admin/assign', methods=['GET', 'POST'])
def admin_assign():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    try:
        if request.method == 'POST':
            driver_username = request.form.get('driver_username', '').strip()
            sponsor_username = request.form.get('sponsor_username', '').strip()
            if not driver_username or not sponsor_username:
                flash("Please choose both a driver and a sponsor.", "warning")
                return redirect(url_for('admin_assign'))

            # Validate both exist
            cur.execute("SELECT username FROM drivers WHERE username=%s", (driver_username,))
            d = cur.fetchone()
            cur.execute("SELECT username FROM sponsor WHERE username=%s", (sponsor_username,))
            s = cur.fetchone()
            if not d or not s:
                flash("Invalid driver or sponsor.", "danger")
                return redirect(url_for('admin_assign'))

            changed, msg = _assign_driver_to_sponsor(driver_username, sponsor_username)
            flash(msg, "success" if changed else "info")
            return redirect(url_for('admin_assign'))

        # GET → show form
        cur.execute("SELECT username FROM drivers ORDER BY username ASC")
        drivers = cur.fetchall()

        cur.execute("SELECT username, organization FROM sponsor ORDER BY username ASC")
        sponsors = cur.fetchall()

        # Optional: list a recent summary of accepted links to help admins see state
        cur.execute("""
            SELECT a.driverUsername AS driver, a.sponsor, a.status, a.updated_at
            FROM driverApplications a
            WHERE a.status='accepted'
            ORDER BY a.updated_at DESC
            LIMIT 50
        """)
        recent = cur.fetchall()

        return render_template('admin_assign.html', drivers=drivers, sponsors=sponsors, recent=recent)

    finally:
        cur.close()
        db.close()


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

@app.route('/reports')
def reports_dashboard():
    if 'user' not in session or session.get('role') not in ['admin', 'sponsor']:
        return redirect(url_for('login'))
    return render_template('reports.html')


@app.route('/generate_report')
def generate_report():
    if 'user' not in session or session.get('role') not in ['admin', 'sponsor']:
        return redirect(url_for('login'))

    report_type = request.args.get('report_type')
    driver = request.args.get('driver')
    start_date = request.args.get('start_date') or None
    end_date = request.args.get('end_date') or None

    role = session.get('role')
    user = session['user']

    if not report_type:
        flash("Please select a report type.", "warning")
        return redirect(url_for('reports_dashboard'))

    # Shared date filter pieces
    date_clause_where = ""
    date_clause_on = ""
    date_params = []

    if start_date:
        date_clause_where += " AND o.order_date >= %s"
        date_clause_on += " AND o.order_date >= %s"
        date_params.append(start_date)

    if end_date:
        date_clause_where += " AND o.order_date <= %s"
        date_clause_on += " AND o.order_date <= %s"
        date_params.append(end_date)

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    # --- Catalog Purchase Report (by Item) ---
    if report_type == 'catalog_purchase':
        if role == 'sponsor':
            # Only this sponsor's items
            query = f"""
                SELECT 
                    p.name AS Item,
                    COUNT(o.order_id) AS `Times Purchased`
                FROM orders o
                JOIN products p ON o.product_id = p.product_id
                WHERE o.sponsor = %s
                {date_clause_where}
                GROUP BY p.product_id, p.name
                ORDER BY `Times Purchased` DESC, Item ASC;
            """
            params = [user] + date_params
            cur.execute(query, params)
            data = cur.fetchall()
            cur.close(); db.close()
            return render_template(
                'report_summary.html',
                title="Catalog Purchase Summary (Your Items)",
                columns=["Item", "Times Purchased"],
                data=data
            )
        else:
            # Admin: all items across sponsors
            query = f"""
                SELECT 
                    p.name    AS Item,
                    o.sponsor AS Sponsor,
                    COUNT(o.order_id) AS `Times Purchased`
                FROM orders o
                JOIN products p ON o.product_id = p.product_id
                WHERE 1=1
                {date_clause_where}
                GROUP BY p.product_id, p.name, o.sponsor
                ORDER BY `Times Purchased` DESC, Item ASC;
            """
            cur.execute(query, date_params)
            data = cur.fetchall()
            cur.close(); db.close()
            return render_template(
                'report_summary.html',
                title="Catalog Purchase Summary (All Items)",
                columns=["Item", "Sponsor", "Times Purchased"],
                data=data
            )

    # --- Driver Activity Report ---
    if report_type == 'driver_activity':
        if role == 'sponsor':
            # Activity for drivers accepted under this sponsor
            query = f"""
                SELECT
                    d.username AS Driver,
                    CONCAT(d.first_name, ' ', d.last_name) AS `Driver Name`,
                    CASE WHEN d.disabled = 1 THEN 'Disabled' ELSE 'Active' END AS Status,
                    COUNT(o.order_id) AS `Total Orders`,
                    COALESCE(SUM(o.quantity * o.point_cost), 0) AS `Total Points Used`,
                    MAX(o.order_date) AS `Last Order Date`
                FROM driverApplications da
                JOIN drivers d
                  ON d.username = da.driverUsername
                LEFT JOIN orders o
                  ON o.user_id = d.username
                 AND o.sponsor = da.sponsor
                 {date_clause_on}
                WHERE da.sponsor = %s
                  AND da.status = 'accepted'
                GROUP BY d.username, d.first_name, d.last_name, d.disabled
                ORDER BY `Last Order Date` IS NULL, `Last Order Date` DESC;
            """
            params = date_params + [user]
            cur.execute(query, params)
        else:
            # Admin: activity for all drivers
            query = f"""
                SELECT
                    d.username AS Driver,
                    CONCAT(d.first_name, ' ', d.last_name) AS `Driver Name`,
                    CASE WHEN d.disabled = 1 THEN 'Disabled' ELSE 'Active' END AS Status,
                    COUNT(o.order_id) AS `Total Orders`,
                    COALESCE(SUM(o.quantity * o.point_cost), 0) AS `Total Points Used`,
                    MAX(o.order_date) AS `Last Order Date`
                FROM drivers d
                LEFT JOIN orders o
                  ON o.user_id = d.username
                 {date_clause_on}
                GROUP BY d.username, d.first_name, d.last_name, d.disabled
                ORDER BY `Last Order Date` IS NULL, `Last Order Date` DESC;
            """
            cur.execute(query, date_params)

        data = cur.fetchall()
        cur.close(); db.close()
        return render_template(
            'report_summary.html',
            title="Driver Activity Report",
            columns=["Driver", "Driver Name", "Status", "Total Orders", "Total Points Used", "Last Order Date"],
            data=data
        )

    # --- Driver Point Transactions (for a specific driver) ---
    if report_type == 'driver_points':
        if not driver:
            flash("Please enter a driver username for the point transactions report.", "warning")
            cur.close(); db.close()
            return redirect(url_for('reports_dashboard'))

        query = f"""
            SELECT 
                o.order_id   AS `Transaction ID`,
                o.order_date AS `Date`,
                o.sponsor    AS `Sponsor`,
                p.name       AS `Description`,
                (o.quantity * o.point_cost) AS `Points Change`,
                o.status     AS `Status`
            FROM orders o
            JOIN products p ON o.product_id = p.product_id
            WHERE o.user_id = %s
            {date_clause_where}
            ORDER BY o.order_date DESC, o.order_id DESC;
        """
        params = [driver] + date_params
        cur.execute(query, params)
        data = cur.fetchall()
        cur.close(); db.close()

        return render_template(
            'report_summary.html',
            title=f"Driver Point Transactions: {driver}",
            columns=["Transaction ID", "Date", "Sponsor", "Description", "Points Change", "Status"],
            data=data
        )

    # --- Driver Purchase Summary ---
    if report_type == 'driver_summary':
        query = f"""
            SELECT 
                d.username AS `Driver`,
                CONCAT(d.first_name,' ',d.last_name) AS `Driver Name`,
                COUNT(o.order_id) AS `Total Orders`,
                COALESCE(SUM(o.quantity * o.point_cost), 0) AS `Total Points Used`
            FROM orders o
            JOIN drivers d ON o.user_id = d.username
            WHERE 1=1
            {date_clause_where}
            GROUP BY d.username
            ORDER BY `Total Points Used` DESC;
        """
        cur.execute(query, date_params)
        data = cur.fetchall()
        cur.close(); db.close()
        return render_template(
            'report_summary.html',
            title="Driver Purchase Summary",
            columns=["Driver", "Driver Name", "Total Orders", "Total Points Used"],
            data=data
        )

   # --- Driver Purchase Detail (requires driver username) ---
    if report_type == 'driver_detail':
        if not driver:
            flash("Please enter a driver username for the detail report.", "warning")
            cur.close(); db.close()
            return redirect(url_for('reports_dashboard'))

        query = f"""
            SELECT 
                o.order_id   AS OrderID,
                o.order_date AS OrderDate,
                p.name       AS ProductName,
                o.sponsor    AS Sponsor,
                o.quantity   AS Quantity,
                o.point_cost AS PointsEach,
                (o.quantity * o.point_cost) AS TotalPoints,
                o.status     AS Status
            FROM orders o
            JOIN products p ON o.product_id = p.product_id
            WHERE o.user_id = %s
            {date_clause_where}
            ORDER BY o.order_date DESC, o.order_id DESC;
        """
        params = [driver] + date_params
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close(); db.close()

        # Group rows by order ID
        orders_map = {}
        for r in rows:
            oid = r['OrderID']
            if oid not in orders_map:
                orders_map[oid] = {
                    'order_id': oid,
                    'order_date': r['OrderDate'],
                    'sponsor': r['Sponsor'],
                    'status': r['Status'],
                    'items': [],
                    'subtotal': 0
                }
            orders_map[oid]['items'].append({
                'product_name': r['ProductName'],
                'quantity': r['Quantity'],
                'points_each': r['PointsEach'],
                'total_points': r['TotalPoints']
            })
            orders_map[oid]['subtotal'] += r['TotalPoints']

        orders = list(orders_map.values())
        grand_total = sum(o['subtotal'] for o in orders)

        return render_template(
            'report_detail_grouped.html',
            title="Purchase Detail",
            driver=driver,
            orders=orders,
            grand_total=grand_total
        )

    # --- Sponsor Purchase Summary ---
    if report_type == 'sponsor_summary':
        query = f"""
            SELECT 
                    s.username AS `Sponsor`,
                    s.organization AS `Organization`,
                    COUNT(o.order_id) AS `Total Orders`,
                    COALESCE(SUM(o.quantity * o.point_cost), 0) AS `Total Points Used`
            FROM orders o
            JOIN sponsor s ON o.sponsor = s.username
            WHERE 1=1
            {date_clause_where}
            GROUP BY s.username
            ORDER BY `Total Points Used` DESC;
        """
        cur.execute(query, date_params)
        data = cur.fetchall()
        cur.close(); db.close()
        return render_template(
            'report_summary.html',
            title="Sponsor Purchase Summary",
            columns=["Sponsor", "Organization", "Total Orders", "Total Points Used"],
            data=data
        )

    # --- INVOICE REPORT ---
    if report_type == 'invoice_report':
        query = f"""
            SELECT 
                s.username AS `Sponsor`,
                s.organization AS `Organization`,
                ROUND(COALESCE(SUM(o.quantity * o.point_cost), 0) / 100, 2) AS `Fee`
            FROM orders o
            JOIN sponsor s ON o.sponsor = s.username
            WHERE 1=1
            {date_clause_where}
            GROUP BY s.username
            ORDER BY `Fee` DESC;
        """
        cur.execute(query, date_params)
        data = cur.fetchall()
        cur.close(); db.close()

        return render_template(
            'report_summary.html',
            title="Invoice Report",
            columns=["Sponsor", "Organization", "Fee"],
            data=data
        )
    # --- Sponsor Detailed Sales Report ---
    if report_type == 'sponsor_detail':
        sponsor_filter = request.args.get('sponsor')
    
        if not sponsor_filter:
            flash("Please enter a sponsor username for detailed sponsor sales report.", "warning")
            cur.close(); db.close()
            return redirect(url_for('reports_dashboard'))
    
        query = f"""
            SELECT 
                o.order_id AS OrderID,
                o.order_date AS OrderDate,
                o.user_id AS Driver,
                p.name AS Product,
                o.quantity AS Quantity,
                o.point_cost AS PointsEach,
                (o.quantity * o.point_cost) AS TotalPoints,
                o.status AS Status
            FROM orders o
            JOIN products p ON o.product_id = p.product_id
            WHERE o.sponsor = %s
            {date_clause_where}
            ORDER BY o.order_date DESC, o.order_id DESC;
        """
    
        params = [sponsor_filter] + date_params
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close(); db.close()
    
        return render_template(
            'report_sponsor_detail.html',
            title=f"Sponsor Detailed Sales Report: {sponsor_filter}",
            sponsor=sponsor_filter,
            data=rows
        )
    
    # --- AUDIT LOG REPORT ---
    if report_type == "audit_log":
        # Filters from form
        filter_driver = request.args.get("driver") or None
        filter_sponsor = request.args.get("sponsor") or None
        category = request.args.get("category") or None

        params = []

        # -----------------------------
        # Category mapping (matches DB)
        # -----------------------------
        # NOTE:
        #  - auditLogs.action uses text like 'add points' / 'remove points'
        #  - loginAttempts uses successful = 1/0
        #  - driverApplications status enum is already descriptive
        audit_condition = "1=1"
        login_condition = "1=1"
        app_condition = "1=1"

        if category == "points_added":
            audit_condition = "action = 'add points'"
            login_condition = "0"
            app_condition = "0"
        elif category == "points_removed":
            audit_condition = "action = 'remove points'"
            login_condition = "0"
            app_condition = "0"
        elif category == "login":
            audit_condition = "0"
            login_condition = "1=1"  # include both success & failure
            app_condition = "0"
        elif category == "driver_application":
            audit_condition = "0"
            login_condition = "0"
            app_condition = "1=1"

        # -----------------------------
        # Base UNION query (no params)
        # -----------------------------
        base_query = f"""
            -- Points added / removed from auditLogs
            SELECT 
                timestamp AS Date,
                user_id  AS User,
                action   AS Action,
                description AS Description
            FROM auditLogs
            WHERE {audit_condition}

            UNION ALL

            -- Login attempts
            SELECT
                timestamp AS Date,
                username AS User,
                CASE 
                    WHEN successful = 1 THEN 'login_success'
                    ELSE 'login_failure'
                END AS Action,
                CONCAT('IP: ', COALESCE(ip_address, 'Unknown')) AS Description
            FROM loginAttempts
            WHERE {login_condition}

            UNION ALL

            -- Driver application lifecycle
            SELECT
                created_at AS Date,
                driverUsername AS User,
                CONCAT('driver_application_', status) AS Action,
                CONCAT('Sponsor: ', sponsor) AS Description
            FROM driverApplications
            WHERE {app_condition}
        """

        # Wrap union so we can safely apply filters
        query = f"SELECT * FROM ({base_query}) AS full_log WHERE 1=1"

        # -----------------------------
        # Final-level filters (safe)
        # -----------------------------
        # 1) Sponsor role restriction
        if role == "sponsor":
            # Sponsor sees:
            #  - Their own username
            #  - Their accepted drivers (via driverApplications)
            query += """
                AND (
                    User = %s
                    OR User IN (
                        SELECT driverUsername
                        FROM driverApplications
                        WHERE sponsor = %s AND status = 'accepted'
                    )
                )
            """
            params.extend([user, user])

        # 2) Filter by driver username (if provided)
        if filter_driver:
            query += " AND User = %s"
            params.append(filter_driver)

        # 3) Filter by sponsor (search in description)
        if filter_sponsor:
            query += " AND Description LIKE %s"
            params.append(f"%{filter_sponsor}%")

        # 4) Date range filters
        if start_date:
            query += " AND Date >= %s"
            params.append(start_date)
        if end_date:
            query += " AND Date <= %s"
            params.append(end_date)

        # Final ordering
        query += " ORDER BY Date DESC"

        # Debug (optional while testing)
        # print("AUDIT LOG QUERY:", query)
        # print("PARAMS:", params)

        cur.execute(query, params)
        data = cur.fetchall()
        cur.close()
        db.close()

        return render_template(
            "report_audit_log.html",
            title="Audit Log Report",
            data=data
        )
            
    
    # fallthrough
    cur.close(); db.close()
    flash("Invalid report type.", "danger")
    return redirect(url_for('reports_dashboard'))

@app.route('/download_report')
def download_report():
    if 'user' not in session or session.get('role') not in ['admin', 'sponsor']:
        return redirect(url_for('login'))

    report_type = request.args.get('report_type')
    driver = request.args.get('driver')
    start_date = request.args.get('start_date') or None
    end_date = request.args.get('end_date') or None

    role = session.get('role')
    user = session['user']

    # Shared date filter pieces
    date_clause_where = ""
    date_clause_on = ""
    date_params = []

    if start_date:
        date_clause_where += " AND o.order_date >= %s"
        date_clause_on += " AND o.order_date >= %s"
        date_params.append(start_date)

    if end_date:
        date_clause_where += " AND o.order_date <= %s"
        date_clause_on += " AND o.order_date <= %s"
        date_params.append(end_date)

    db = MySQLdb.connect(**db_config)
    cur = db.cursor(MySQLdb.cursors.DictCursor)

    title = ""
    columns = []
    table_data = []

    # ===============================
    #  DRIVER PURCHASE SUMMARY
    # ===============================
    if report_type == 'driver_summary':
        query = f"""
            SELECT 
                d.username AS Driver,
                CONCAT(d.first_name,' ',d.last_name) AS DriverName,
                COUNT(o.order_id) AS TotalOrders,
                COALESCE(SUM(o.quantity * o.point_cost), 0) AS TotalPointsUsed
            FROM orders o
            JOIN drivers d ON o.user_id = d.username
            WHERE 1=1
            {date_clause_where}
            GROUP BY d.username
            ORDER BY TotalPointsUsed DESC;
        """
        cur.execute(query, date_params)
        data = cur.fetchall()
        title = "Driver Purchase Summary"
        columns = ["Driver", "Driver Name", "Total Orders", "Total Points Used"]
        table_data = [[r['Driver'], r['DriverName'], r['TotalOrders'], r['TotalPointsUsed']] for r in data]

    # ===============================
    #  DRIVER PURCHASE DETAIL
    # ===============================
    elif report_type == 'driver_detail':
        if not driver:
            flash("Driver username required for detail report.", "warning")
            cur.close(); db.close()
            return redirect(url_for('reports_dashboard'))

        query = f"""
            SELECT 
                o.order_id   AS OrderID,
                o.order_date AS OrderDate,
                p.name       AS ProductName,
                o.sponsor    AS Sponsor,
                o.quantity   AS Quantity,
                o.point_cost AS PointsEach,
                (o.quantity * o.point_cost) AS TotalPoints,
                o.status     AS Status
            FROM orders o
            JOIN products p ON o.product_id = p.product_id
            WHERE o.user_id = %s
            {date_clause_where}
            ORDER BY o.order_date DESC;
        """
        params = [driver] + date_params
        cur.execute(query, params)
        data = cur.fetchall()
        title = f"Driver Purchase Detail: {driver}"
        columns = ["Order ID", "Order Date", "Product", "Sponsor", "Quantity", "Points Each", "Total Points", "Status"]
        table_data = [
            [r['OrderID'], r['OrderDate'], r['ProductName'], r['Sponsor'],
             r['Quantity'], r['PointsEach'], r['TotalPoints'], r['Status']]
            for r in data
        ]

    # ===============================
    #  SPONSOR PURCHASE SUMMARY
    # ===============================
    elif report_type == 'sponsor_summary':
        query = f"""
            SELECT 
                s.username AS Sponsor,
                s.organization AS Organization,
                COUNT(o.order_id) AS TotalOrders,
                COALESCE(SUM(o.quantity * o.point_cost), 0) AS TotalPointsUsed
            FROM orders o
            JOIN sponsor s ON o.sponsor = s.username
            WHERE 1=1
            {date_clause_where}
            GROUP BY s.username
            ORDER BY TotalPointsUsed DESC;
        """
        cur.execute(query, date_params)
        data = cur.fetchall()
        title = "Sponsor Purchase Summary"
        columns = ["Sponsor", "Organization", "Total Orders", "Total Points Used"]
        table_data = [[r['Sponsor'], r['Organization'], r['TotalOrders'], r['TotalPointsUsed']] for r in data]

    # ===============================
    #  CATALOG PURCHASE SUMMARY (BY ITEM)
    # ===============================
    elif report_type == 'catalog_purchase':
        if role == 'sponsor':
            query = f"""
                SELECT 
                    p.name AS Item,
                    COUNT(o.order_id) AS `Times Purchased`
                FROM orders o
                JOIN products p ON o.product_id = p.product_id
                WHERE o.sponsor = %s
                {date_clause_where}
                GROUP BY p.product_id, p.name
                ORDER BY `Times Purchased` DESC, Item ASC;
            """
            params = [user] + date_params
            cur.execute(query, params)
            data = cur.fetchall()
            title = "Catalog Purchase Summary (Your Items)"
            columns = ["Item", "Times Purchased"]
            table_data = [[r['Item'], r['Times Purchased']] for r in data]
        else:
            query = f"""
                SELECT 
                    p.name    AS Item,
                    o.sponsor AS Sponsor,
                    COUNT(o.order_id) AS `Times Purchased`
                FROM orders o
                JOIN products p ON o.product_id = p.product_id
                WHERE 1=1
                {date_clause_where}
                GROUP BY p.product_id, p.name, o.sponsor
                ORDER BY `Times Purchased` DESC, Item ASC;
            """
            cur.execute(query, date_params)
            data = cur.fetchall()
            title = "Catalog Purchase Summary (All Items)"
            columns = ["Item", "Sponsor", "Times Purchased"]
            table_data = [[r['Item'], r['Sponsor'], r['Times Purchased']] for r in data]

    # ===============================
    #  DRIVER ACTIVITY REPORT
    # ===============================
    elif report_type == 'driver_activity':
        if role == 'sponsor':
            query = f"""
                SELECT
                    d.username AS Driver,
                    CONCAT(d.first_name, ' ', d.last_name) AS `Driver Name`,
                    CASE WHEN d.disabled = 1 THEN 'Disabled' ELSE 'Active' END AS Status,
                    COUNT(o.order_id) AS `Total Orders`,
                    COALESCE(SUM(o.quantity * o.point_cost), 0) AS `Total Points Used`,
                    MAX(o.order_date) AS `Last Order Date`
                FROM driverApplications da
                JOIN drivers d
                  ON d.username = da.driverUsername
                LEFT JOIN orders o
                  ON o.user_id = d.username
                 AND o.sponsor = da.sponsor
                 {date_clause_on}
                WHERE da.sponsor = %s
                  AND da.status = 'accepted'
                GROUP BY d.username, d.first_name, d.last_name, d.disabled
                ORDER BY `Last Order Date` IS NULL, `Last Order Date` DESC;
            """
            params = date_params + [user]
            cur.execute(query, params)
        else:
            query = f"""
                SELECT
                    d.username AS Driver,
                    CONCAT(d.first_name, ' ', d.last_name) AS `Driver Name`,
                    CASE WHEN d.disabled = 1 THEN 'Disabled' ELSE 'Active' END AS Status,
                    COUNT(o.order_id) AS `Total Orders`,
                    COALESCE(SUM(o.quantity * o.point_cost), 0) AS `Total Points Used`,
                    MAX(o.order_date) AS `Last Order Date`
                FROM drivers d
                LEFT JOIN orders o
                  ON o.user_id = d.username
                 {date_clause_on}
                GROUP BY d.username, d.first_name, d.last_name, d.disabled
                ORDER BY `Last Order Date` IS NULL, `Last Order Date` DESC;
            """
            cur.execute(query, date_params)

        data = cur.fetchall()
        title = "Driver Activity Report"
        columns = ["Driver", "Driver Name", "Status", "Total Orders", "Total Points Used", "Last Order Date"]
        table_data = [
            [r['Driver'], r['Driver Name'], r['Status'],
             r['Total Orders'], r['Total Points Used'], r['Last Order Date']]
            for r in data
        ]

    # ===============================
    #  DRIVER POINT TRANSACTIONS
    # ===============================
    elif report_type == 'driver_points':
        if not driver:
            flash("Driver username required for point transactions report.", "warning")
            cur.close(); db.close()
            return redirect(url_for('reports_dashboard'))

        query = f"""
            SELECT 
                o.order_id   AS `Transaction ID`,
                o.order_date AS `Date`,
                o.sponsor    AS `Sponsor`,
                p.name       AS `Description`,
                (o.quantity * o.point_cost) AS `Points Change`,
                o.status     AS `Status`
            FROM orders o
            JOIN products p ON o.product_id = p.product_id
            WHERE o.user_id = %s
            {date_clause_where}
            ORDER BY o.order_date DESC, o.order_id DESC;
        """
        params = [driver] + date_params
        cur.execute(query, params)
        data = cur.fetchall()
        title = f"Driver Point Transactions: {driver}"
        columns = ["Transaction ID", "Date", "Sponsor", "Description", "Points Change", "Status"]
        table_data = [
            [r['Transaction ID'], r['Date'], r['Sponsor'], r['Description'],
             r['Points Change'], r['Status']]
            for r in data
        ]

    else:
        flash("Invalid report type for download.", "danger")
        cur.close(); db.close()
        return redirect(url_for('reports_dashboard'))

    cur.close(); db.close()

    # ===============================
    #  PDF GENERATION (shared logic)
    # ===============================
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph(title, styles['Title']), Spacer(1, 12)]

    table_data.insert(0, columns)  # add header row
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8)
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    filename = f"{report_type}_report.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')

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
