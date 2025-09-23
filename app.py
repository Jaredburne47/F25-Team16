from flask import Flask, render_template, session, redirect, url_for, request
import MySQLdb  # mysqlclient
from logInFunctions.auth import authenticate
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
    session.pop("user", None)
    session.pop("role", None) # Also clears the role
    return render_template("home.html")
    #return redirect(url_for('home')) this would redirect for cleaner experiance

# New dedicated Profile routes
@app.route('/driver/profile')
def driver_profile():
    # Protect this page: only logged-in drivers can see it
    if 'user' not in session or session.get('role') != 'driver':
        return redirect(url_for('login'))
    
    # If they are a driver, show them the driver profile page
    return render_template("driver_profile.html")

@app.route('/sponsor/profile')
def sponsor_profile():
    # Protect this page: only sponsors can see it
    if 'user' not in session or session.get('role') != 'sponsor':
        return redirect(url_for('login'))
        
    return render_template("sponsor_profile.html")

@app.route('/admin/profile')
def admin_profile():
    # Protect this page: only admins can see it
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    return render_template("admin_profile.html")

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

@app.route('/settings')
def settings():
    return render_template("settings.html")

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    # Only allow sponsors and admins
    if 'user' not in session or session.get('role') not in ['sponsor', 'admin']:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get data from the form
        new_username = request.form['username']
        new_password = request.form['password']
        new_role = request.form['role']

        # For now, just return a text block with the values
        return f"""
        <h2>New User Submitted</h2>
        <p><strong>Username:</strong> {new_username}</p>
        <p><strong>Password:</strong> {new_password}</p>
        <p><strong>Role:</strong> {new_role}</p>
        """

    # GET request – show the form
    return render_template("add_user.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
