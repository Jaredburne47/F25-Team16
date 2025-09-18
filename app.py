from flask import Flask, render_template, session, redirect, url_for, request
import MySQLdb  # mysqlclient
from logInFunctions.auth import authenticate

app = Flask(__name__)

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

        #we need to hash this later
        role, user_row = authenticate(username, password)

        if role == 'driver':
            print(f"User {username} is a DRIVER")
            session['user'] = username
            session['role'] = role
            return f"{username} is a driver."
            #return redirect(url_for('driver_dashboard'))

        elif role == 'admin':
            print(f"User {username} is an ADMIN")
            session['user'] = username
            session['role'] = role
            return f"{username} is a admin."
            #return redirect(url_for('admin_dashboard'))

        elif role == 'sponsor':
            print(f"User {username} is a SPONSOR")
            session['user'] = username
            session['role'] = role
            return f"{username} is a sponsor."
            #return redirect(url_for('sponsor_dashboard'))

        else:
            print(f"User {username} does NOT EXIST")
            #flash('Invalid credentials. Please try again.', 'error')

    # GET request – just render login page
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop("user", None)
    return render_template("home.html")

@app.route('/profile')
def profile():
    return render_template("profile.html")

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

@app.route('/settings')
def settings():
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
