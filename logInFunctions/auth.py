import MySQLdb

db_config = {
    'host': 'cpsc4910-f25.cobd8enwsupz.us-east-1.rds.amazonaws.com',
    'user': 'Team16',
    'passwd': 'Tlaw16',
    'db': 'Team16_DB',
    'charset': 'utf8'
}

def authenticate(username: str, password: str):
    """
    Checks drivers, admin, and sponsors tables for a matching username/password.

    Returns (role, user_row) on success,
            (None, None) on failure.
    """
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    # Drivers table – assumes columns username and password (or password_hash later)
    cursor.execute("SELECT * FROM drivers WHERE username=%s AND password_hash=%s", (username, password))
    driver_row = cursor.fetchone()
    if driver_row:
        cursor.execute(
            "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
            ("log in attempt", f"{username} logged in successfully", username)
        )
        db.commit()
        cursor.close()
        db.close()
        return 'driver', driver_row

    # Admin table – assumes columns username and password
    cursor.execute("SELECT * FROM admins WHERE username=%s AND password_hash=%s", (username, password))
    admin_row = cursor.fetchone()
    if admin_row:
        cursor.execute(
            "INSERT INTO auditLogs (action, description, username) VALUES (%s, %s, %s)",
            ("log in attempt", f"{username} logged in successfully", username)
        )
        db.commit()
        cursor.close()
        db.close()
        return 'admin', admin_row

    # Sponsors table – assumes columns username and password
    cursor.execute("SELECT * FROM sponsor WHERE username=%s AND password_hash=%s", (username, password))
    sponsor_row = cursor.fetchone()
    if sponsor_row:
        cursor.execute(
            "INSERT INTO auditLogs (action, description, username) VALUES (%s, %s, %s)",
            ("log in attempt", f"{username} logged in successfully", username)
        )
        db.commit()
        cursor.close()
        db.close()
        return 'sponsor', sponsor_row

    # --- Failed attempt ---
    cursor.execute(
        "INSERT INTO auditLogs (action, description, username) VALUES (%s, %s, %s)",
        ("log in attempt", f"{username} attempted to log in — failed", username)
    )
    db.commit()
    cursor.close()
    db.close()
    return None, None
