from flask import Flask, render_template, session, redirect, url_for, request, flash
import MySQLdb  # mysqlclient
from logInFunctions.auth import authenticate
from emailScripts import welcomeEmail
from createUser import _create_user_in_table
from emailScripts.resetEmail import send_reset_email
from emailScripts.decisionEmail import send_decision_email
from emailScripts.lockEmail import send_lock_email
import secrets
import os
import csv
from io import StringIO
from flask import Response
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from flask import jsonify
import os, time, json, base64
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
    app.permanent_session_lifetime = timedelta(seconds=15)
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
                session.clear()
                flash("You were logged out due to inactivity.", "warning")
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
#For now just a place holder
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Authenticate 
        role, user_row = authenticate(username, password)

        # If login is successful starts session & redirects
        if role:
            session['user'] = username
            session['role'] = role

            if role == 'driver':
                session['show_feedback_modal'] = True
                return redirect(url_for('driver_profile'))
            elif role == 'admin':
                return redirect(url_for('admin_profile'))
            elif role == 'sponsor':
                session['show_feedback_modal'] = True
                return redirect(url_for('sponsor_profile'))

       
        # If login failed, check for lockout reason
        locked_until = None
        try:
            db = MySQLdb.connect(**db_config)
            cursor = db.cursor(MySQLdb.cursors.DictCursor)

            # Check if user exists and has an active lockout in any table
            for table in ['drivers', 'sponsor', 'admins']:
                cursor.execute(f"SELECT locked_until FROM {table} WHERE username=%s", (username,))
                row = cursor.fetchone()
                if row and row.get('locked_until') and row['locked_until'] > datetime.now():
                    locked_until = row['locked_until']
                    break

            cursor.close()
            db.close()
        except Exception:
            # fallback if DB lookup fails
            locked_until = None

        if locked_until:
            try:
                db = MySQLdb.connect(**db_config)
                cursor = db.cursor(MySQLdb.cursors.DictCursor)
                # Find the user's email (and role) by username across all tables
                cursor.execute("""
                    SELECT email, 'driver'  AS role FROM drivers WHERE username=%s
                    UNION ALL
                    SELECT email, 'sponsor' AS role FROM sponsor WHERE username=%s
                    UNION ALL
                    SELECT email, 'admin'   AS role FROM admins  WHERE username=%s
                    LIMIT 1
                """, (username, username, username))
                r = cursor.fetchone()
                cursor.close(); db.close()

                if r and r.get('email'):
                    locked_str = locked_until.strftime('%b %d, %Y %I:%M:%S %p')
                    send_lock_email(r['email'], username, r.get('role', 'user'), locked_str)
            except Exception:
                pass  # don't block login page rendering if email fails
        
        #Render login.html with message
        if locked_until:
            msg = (
                    "Your account is locked until "
                    f"{locked_until.strftime('%b %d, %Y %I:%M:%S %p')}. Please try again later."
            )
        else:
            msg = "Invalid username or password."

        return render_template("login.html", error=msg, last_username=username)

    # GET request → render blank login form
    return render_template("login.html")
@app.route('/logout')
def logout():
    session.clear() #clears all data from session(user,role)
    return redirect(url_for('login'))
    #return redirect(url_for('home')) this would redirect for cleaner experiance

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

    # ===================================================================
    # SPRINT 4 CHANGE: FETCH SPONSOR DASHBOARD DATA
    # These queries get the summary metrics and driver list for the sponsor.
    # ===================================================================
    cursor.execute("""
        SELECT COUNT(*) as driver_count 
        FROM driverApplications 
        WHERE sponsor=%s AND status='accepted'
    """, (username,))
    driver_count = cursor.fetchone()['driver_count']

    cursor.execute("""
        SELECT SUM(d.points) as total_points 
        FROM drivers d 
        JOIN driverApplications da ON d.username = da.driverUsername 
        WHERE da.sponsor=%s AND da.status='accepted'
    """, (username,))
    total_points = cursor.fetchone()['total_points'] or 0

    cursor.execute("""
        SELECT d.username, d.first_name, d.last_name, d.points 
        FROM drivers d 
        JOIN driverApplications da ON d.username = da.driverUsername 
        WHERE da.sponsor=%s AND da.status='accepted' 
        ORDER BY d.points DESC
    """, (username,))
    driver_list = cursor.fetchall()
    # ===================================================================


    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        address = request.form['address']
        phone = request.form['phone']
        organization = request.form['organization']

        cursor.execute("""
            UPDATE sponsor
            SET first_name=%s, last_name=%s, address=%s, phone=%s, organization=%s
            WHERE username=%s
        """, (first_name, last_name, address, phone, organization, username))
        db.commit()

    cursor.execute("SELECT * FROM sponsor WHERE username=%s", (username,))
    user_info = cursor.fetchone()

    cursor.close()
    db.close()

    return render_template("sponsor_profile.html", user=user_info, driver_count=driver_count, total_points=total_points, driver_list=driver_list)
    


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
    # Ensure only drivers can access
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Retrieve driver info to get their points balance
        cursor.execute("SELECT * FROM drivers WHERE username=%s", (username,))
        driver_info = cursor.fetchone()
        points_balance = driver_info['points'] if driver_info else 0

        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Database error:</h2><p>{e}</p>"

    # Render template and pass points_balance
    return render_template("dashboard.html", points_balance=points_balance)


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
        return f"<h2>Database error:</h2><p>{e}</p>"

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
        return f"<h2>Database error:</h2><p>{e}</p>"

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

        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Database error:</h2><p>{e}</p>"

    return redirect(url_for('catalog_manager'))

@app.route('/item_catalog', methods=['GET'])
def item_catalog():
    # --- Access control ---
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # --- Get driver’s point balance ---
    cursor.execute("SELECT points FROM drivers WHERE username=%s", (username,))
    driver = cursor.fetchone()
    points_balance = driver['points'] if driver else 0

    # --- Get search, sort, and filter parameters ---
    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'points_cost_asc')
    sponsor = request.args.get('sponsor', 'all')

    # --- Build SQL query dynamically ---
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND (name LIKE %s OR sponsor LIKE %s)"
        like_term = f"%{search}%"
        params.extend([like_term, like_term])

    if sponsor != 'all':
        query += " AND sponsor = %s"
        params.append(sponsor)

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

    # --- Get unique sponsors for dropdown filter ---
    cursor.execute("SELECT DISTINCT sponsor FROM products WHERE sponsor IS NOT NULL")
    sponsors = [row['sponsor'] for row in cursor.fetchall()]

    cursor.close()
    db.close()

    return render_template(
        "item_catalog.html",
        items=items,
        points_balance=points_balance,
        search=search,
        sort=sort,
        sponsor=sponsor,
        sponsors=sponsors
    )




@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session or 'role' not in session:
        return redirect(url_for('login'))

    username = session['user']
    role = session['role']

    table = {'driver':'drivers', 'sponsor':'sponsor', 'admin':'admins'}.get(role)
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

            # --- Social media ---
            if role in ['driver','sponsor']:
                for f in ['twitter','facebook','instagram']:
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
                    # FLASH AN ERROR: Send an error message if passwords don't match.
                    flash('Passwords do not match. Please try again.', 'danger')
                    cursor.execute(f"UPDATE {table} SET password_hash=%s WHERE username=%s",
                                   (password, username))
                    
                    cursor.execute(
                        "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                        ("password reset", f"{username} reset their password successfully while logged in.", username)
                    )

                    # db.commit() // this was causing the logo error
                    
                else:
                    cursor.close()
                    db.close()
                    return "<h3>Passwords do not match.</h3>"

            # --- Profile picture ---
            file = request.files.get('profile_picture')
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{username}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                cursor.execute(f"UPDATE {table} SET profile_picture=%s WHERE username=%s",
                               (filename, username))

            if role == 'sponsor':
                logo_file = request.files.get('company_logo')
                remove_logo_checked = 'remove_logo' in request.form

                # CASE 1: User is CHANGING the logo by uploading a new one
                if logo_file and allowed_file(logo_file.filename):
                    logo_filename = secure_filename(f"{username}_logo_{logo_file.filename}")
                    logo_folder_path = app.config['LOGO_UPLOAD_FOLDER']
                    os.makedirs(logo_folder_path, exist_ok=True)
                    logo_path = os.path.join(logo_folder_path, logo_filename)
                    logo_file.save(logo_path)
                    cursor.execute("UPDATE sponsor SET company_logo=%s WHERE username=%s", (logo_filename, username))
                
                # CASE 2: User is REMOVING the logo (and not uploading a new one)
                elif remove_logo_checked:
                    # First, get the current logo's filename to delete the file
                    cursor.execute("SELECT company_logo FROM sponsor WHERE username=%s", (username,))
                    result = cursor.fetchone()
                    if result and result['company_logo']:
                        logo_to_delete = result['company_logo']
                        path_to_delete = os.path.join(app.config['LOGO_UPLOAD_FOLDER'], logo_to_delete)
                        
                        # Delete the physical file from the server if it exists
                        if os.path.exists(path_to_delete):
                            os.remove(path_to_delete)

                    # Finally, set the database field to NULL
                    cursor.execute("UPDATE sponsor SET company_logo = NULL WHERE username=%s", (username,))

            
            db.commit()
            flash('Your profile has been updated successfully!', 'success')
            cursor.close()
            db.close()
            return redirect(url_for(profile_route))

        # GET request: fetch current info
        cursor.execute(f"SELECT * FROM {table} WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

    except Exception as e:
        return f"<h2>Database error:</h2><p>{e}</p>"

    return render_template("settings.html", user=user)



@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    # Only allow sponsors and admins
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get data from the form
        new_username = request.form['username']
        new_email = request.form['email']
        new_password = request.form['password']
        new_role = request.form['role']

        #TODO: hash the password
        #For now:
        password_hash = new_password;
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

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT username, email, points FROM drivers;")
        drivers_list = cursor.fetchall()
        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Database error:</h2><p>{e}</p>"

    return render_template("drivers.html", drivers=drivers_list)

@app.route('/sponsors')
def sponsors():
    # Only sponsors/admins can access
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT username, email FROM sponsor;")
        sponsors_list = cursor.fetchall()
        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Database error:</h2><p>{e}</p>"

    return render_template("sponsors.html", sponsors=sponsors_list)


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
        return f"<h2>Error removing sponsor:</h2><p>{e}</p>"
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
    return redirect(url_for('driver_profile'))

@app.route('/login_as_sponsor', methods=['POST'])
def login_as_sponsor():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    username = request.form['username']
    session['user'] = username
    session['role'] = 'sponsor'
    return redirect(url_for('sponsor_profile'))

@app.route('/add_points', methods=['POST'])
def add_points():
    username = request.form['username']
    points = int(request.form['points_to_add'])
    reason = request.form.get('reason', '(no reason provided)')
    performed_by = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()

        # --- Add points to driver ---
        cursor.execute(
            "UPDATE drivers SET points = points + %s WHERE username = %s;",
            (points, username)
        )
        db.commit()

        # --- Log the action ---
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("add points", f"{performed_by} added {points} points to {username}. Reason: {reason}", performed_by)
        )
        db.commit()

        cursor.close()
        db.close()
        flash(f'{points} points were successfully added to "{username}".', 'success')

    except Exception as e:
        return f"<h2>Error adding points:</h2><p>{e}</p>"
        flash(f'Error adding points: {e}', 'danger')

    return render_template('points_added.html', username=username, points=points)


@app.route('/remove_points', methods=['POST'])
def remove_points():
    username = request.form['username']
    points = int(request.form['points_to_remove'])
    reason = request.form.get('reason', '(no reason provided)')
    performed_by = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()

        # --- Remove points from driver ---
        cursor.execute(
            "UPDATE drivers SET points = points - %s WHERE username = %s;",
            (points, username)
        )
        db.commit()

        # --- Log the action ---
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("remove points", f"{performed_by} removed {points} points from {username}. Reason: {reason}", performed_by)
        )
        db.commit()

        cursor.close()
        db.close()
        flash(f'{points} points were successfully removed from "{username}".', 'success')

    except Exception as e:
        return f"<h2>Error removing points:</h2><p>{e}</p>"
        flash(f'Error removing points: {e}', 'danger')

    return render_template('points_removed.html', username=username, points=points)



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
    """
    Allows a driver to apply to a sponsor.
    Enforces the following rules:
      1. A driver can have only one active (pending/accepted) application per sponsor.
      2. A driver cannot apply to another sponsor if already accepted by one.
      3. Drivers can reapply only after rejection or withdrawal.
    """
    # Ensure user is logged in and is a driver
    if 'user' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    username = session['user']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Check if driver already has an accepted sponsor (any sponsor)
        cursor.execute("""
            SELECT sponsor FROM driverApplications
            WHERE driverUsername = %s AND status = 'accepted'
            LIMIT 1
        """, (username,))
        accepted_anywhere = cursor.fetchone()
        if accepted_anywhere:
            cursor.close()
            db.close()
            return (
                f"<h3>You are already accepted by {accepted_anywhere['sponsor']}. "
                f"Withdraw first if you want to apply elsewhere.</h3>"
            )

        # Check for existing active application (pending/accepted) to this sponsor
        cursor.execute("""
            SELECT id, status FROM driverApplications
            WHERE driverUsername = %s AND sponsor = %s
              AND status IN ('pending', 'accepted')
        """, (username, sponsor))
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            db.close()
            return "<h3>You already have an active application with this sponsor.</h3>"

        # Create new pending application
        cursor.execute("""
            INSERT INTO driverApplications (driverUsername, sponsor, status, created_at, updated_at)
            VALUES (%s, %s, 'pending', NOW(), NOW())
        """, (username, sponsor))
        db.commit()

        # Log audit entry for transparency
        cursor.execute("""
            INSERT INTO auditLogs (action, description, user_id)
            VALUES (%s, %s, %s)
        """, (
            "application_created",
            f"{username} applied to sponsor {sponsor}.",
            username
        ))
        db.commit()

        cursor.close()
        db.close()
        flash(f'Your application to "{sponsor}" has been submitted successfully!', 'success')

        return redirect(url_for('driver_applications'))

    except Exception as e:
        return f"<h2>Error applying to sponsor:</h2><p>{e}</p>"
        flash(f'An error occurred while applying: {e}', 'danger')

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
        ORDER BY FIELD(status,'pending','accepted','rejected','withdrawn'), created_at DESC
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

        # Get driverUsername for this application
        cursor.execute("SELECT driverUsername FROM driverApplications WHERE id=%s", (app_id,))
        app_row = cursor.fetchone()
        if not app_row:
            return "<h3>Application not found.</h3>"

        driver_username = app_row['driverUsername']

        # Check if driver already has an accepted sponsor
        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM driverApplications
            WHERE driverUsername=%s AND status='accepted'
        """, (driver_username,))
        existing = cursor.fetchone()
        if existing['count'] > 0:
            cursor.close()
            db.close()
            return "<h3>This driver already has an accepted sponsor. Withdraw/reject before accepting another.</h3>"

        # Accept the application
        cursor.execute("""
            UPDATE driverApplications
            SET status='accepted'
            WHERE id=%s AND sponsor=%s AND status='pending'
        """, (app_id, sponsor))
        db.commit()

        #Log accepting
        description = f"{sponsor} accepted {driver['driverUsername']}'s application"
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("application", description, sponsor)
        )

        db.commit()

        # Fetch driver info for email
        cursor.execute("""
            SELECT d.email, d.first_name, a.sponsor
            FROM driverApplications a
            JOIN drivers d ON a.driverUsername = d.username
            WHERE a.id=%s
        """, (app_id,))
        driver = cursor.fetchone()

        if driver:
            send_decision_email(driver['email'], driver['first_name'], driver['sponsor'], "accepted")

        cursor.close()
        db.close()
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

    query = "SELECT * FROM auditLogs WHERE 1=1"
    params = []

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

    query = "SELECT * FROM auditLogs WHERE 1=1"
    params = []

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
    
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
