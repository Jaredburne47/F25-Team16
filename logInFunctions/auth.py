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
    cursor.execute("SELECT * FROM drivers WHERE username=%s AND password=%s", (username, password))
    driver_rows = cursor.fetchall()
    for row in driver_rows:
        cursor.close()
        db.close()
        return 'driver', row

    # Admin table – assumes columns username and password
    cursor.execute("SELECT * FROM admins WHERE username=%s AND password=%s", (username, password))
    admin_rows = cursor.fetchall()
    for row in admin_rows:
        cursor.close()
        db.close()
        return 'admin', row

    # Sponsors table – assumes columns username and password
    cursor.execute("SELECT * FROM sponsor WHERE username=%s AND password=%s", (username, password))
    sponsor_rows = cursor.fetchall()
    for row in sponsor_rows:
        cursor.close()
        db.close()
        return 'sponsor', row

    cursor.close()
    db.close()
    return None, None
