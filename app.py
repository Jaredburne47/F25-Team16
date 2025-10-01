from flask import Flask, render_template, session, redirect, url_for, request
import MySQLdb  # mysqlclient
from logInFunctions.auth import authenticate
from emailScripts import welcomeEmail
from createUser import _create_user_in_table
from emailScripts.resetEmail import send_reset_email
import secrets
import os

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
        username = request.form['username']
        password = request.form['password']

        #we need to hash the password later
        #authenticate lives in logInFunctions/auth.py and checks db for matches and returns the role
        role, user_row = authenticate(username, password)

        if role == 'driver':
            print(f"User {username} is a DRIVER")
            session['user'] = username
            session['role'] = role
            #return f"{username} is a driver."
            return redirect(url_for('driver_profile'))

        elif role == 'admin':
            print(f"User {username} is an ADMIN")
            session['user'] = username
            session['role'] = role
            #return f"{username} is a admin."
            return redirect(url_for('admin_profile'))

        elif role == 'sponsor':
            print(f"User {username} is a SPONSOR")
            session['user'] = username
            session['role'] = role
            #return f"{username} is a sponsor."
            return redirect(url_for('sponsor_profile'))

        else:
            print(f"User {username} does NOT EXIST")
            #flash('Invalid credentials. Please try again.', 'error')

    # GET request – just render login page
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

    return render_template("sponsor_profile.html", user=user_info)


@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = session['user']

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

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

    return render_template("admin_profile.html", user=user_info)


@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    # User must be logged in
    if 'user' not in session or 'role' not in session:
        return redirect(url_for('login'))

    username = session['user']
    role = session['role']

    # Determine table and profile route based on role
    if role == 'driver':
        table = 'drivers'
        profile_route = 'driver_profile'
    elif role == 'sponsor':
        table = 'sponsor'
        profile_route = 'sponsor_profile'
    elif role == 'admin':
        table = 'admins'
        profile_route = 'admin_profile'
    else:
        return "Invalid role", 400

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        if request.method == 'POST':
            # Update first name, last name, address, phone
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            address = request.form['address']
            phone = request.form['phone']

            cursor.execute(f"""
                UPDATE {table}
                SET first_name=%s, last_name=%s, address=%s, phone=%s
                WHERE username=%s
            """, (first_name, last_name, address, phone, username))
            
            # Handle password update
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if password and confirm_password:
                if password == confirm_password:
                    cursor.execute(f"""
                        UPDATE {table}
                        SET password_hash=%s
                        WHERE username=%s
                    """, (password, username))
                else:
                    cursor.close()
                    db.close()
                    return "<h3>Passwords do not match. Please try again.</h3>"
            
            db.commit()
            cursor.close()
            db.close()

            # Redirect back to profile page
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
        return redirect(url_for('login'))

    username = request.form['username']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("DELETE FROM drivers WHERE username = %s;", (username,))
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Error removing driver:</h2><p>{e}</p>"

    return redirect(url_for('drivers'))

@app.route('/remove_sponsor', methods=['POST'])
def remove_sponsor():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    username = request.form['username']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("DELETE FROM sponsor WHERE username = %s;", (username,))
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Error removing sponsor:</h2><p>{e}</p>"

    return redirect(url_for('sponsors'))


@app.route('/login_as_driver', methods=['POST'])
def login_as_driver():
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
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
    #add the points
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("UPDATE drivers SET points = points + %s WHERE username = %s;",(points, username))
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Error adding points:</h2><p>{e}</p>"
    return render_template('points_added.html', username=username, points=points)

@app.route('/remove_points', methods=['POST'])
def remove_points():
    username = request.form['username']
    points = int(request.form['points_to_remove'])
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("UPDATE drivers SET points = points - %s WHERE username = %s;",(points, username))
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        return f"<h2>Error removing points:</h2><p>{e}</p>"
    print(f"Removed {points} points from driver {username}")
    return render_template('points_removed.html', username=username, points=points)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # find user by BOTH username and email
        cursor.execute("""
            SELECT username, 'driver' as role FROM drivers WHERE username=%s AND email=%s
            UNION
            SELECT username, 'sponsor' as role FROM sponsor WHERE username=%s AND email=%s
            UNION
            SELECT username, 'admin' as role FROM admins WHERE username=%s AND email=%s
        """, (username, email, username, email, username, email))

        user = cursor.fetchone()
        cursor.close()
        db.close()

        if not user:
            return "<h3>No account found with that username/email combination.</h3>"

        # generate reset token
        token = secrets.token_urlsafe(32)

        # store reset info in session
        session['reset_user'] = user['username']
        session['reset_role'] = user['role']
        session['reset_token'] = token

        reset_link = url_for('set_new_password', token=token, _external=True)

        # send reset email
        send_reset_email(email, user['username'], reset_link)

        return "<h3>A password reset link has been sent to your email.</h3>"

    return render_template("reset_password.html")

@app.route('/set_new_password/<token>', methods=['GET', 'POST'])
def set_new_password(token):
    if 'reset_token' not in session or session['reset_token'] != token:
        return "<h3>Invalid or expired reset link.</h3>"

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return "<h3>Passwords do not match.</h3>"

        username = session['reset_user']
        role = session['reset_role']
        table = 'drivers' if role == 'driver' else ('sponsor' if role == 'sponsor' else 'admins')

        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()
        cursor.execute(f"""
            UPDATE {table}
            SET password_hash=%s
            WHERE username=%s
        """, (new_password, username))
        db.commit()
        cursor.close()
        db.close()

        # Clear reset session data
        session.pop('reset_token', None)
        session.pop('reset_user', None)
        session.pop('reset_role', None)

        return redirect(url_for('login'))

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

    db = MySQLdb.connect(**db_config)
    cursor = db.cursor()

    cursor.execute("""
        INSERT INTO driverApplications (driverUsername, sponsor, status)
        VALUES (%s, %s, 'pending')
    """, (username, sponsor))
    db.commit()

    cursor.close()
    db.close()

    return redirect(url_for('driver_applications'))

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

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
