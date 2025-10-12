#used for lockout duration
from datetime import datetime, timedelta
# used for IP logging
from flask import request   
import MySQLdb

db_config = {
    'host': 'cpsc4910-f25.cobd8enwsupz.us-east-1.rds.amazonaws.com',
    'user': 'Team16',
    'passwd': 'Tlaw16',
    'db': 'Team16_DB',
    'charset': 'utf8'
}

FAILED_LIMIT = 5
LOCKOUT_DURATION = timedelta(minutes=15)

def authenticate(username: str, password: str):
    """
    Authenticates user across drivers, sponsor, and admins.
    Implements account lockout and logging of all attempts.
    Returns (role, user_row) on success, (None, None) on failure.
    """
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)

    roles = {
        'driver': 'drivers',
        'sponsor': 'sponsor',
        'admin': 'admins'
    }
    
    # Loop through each role table to find username
    for role, table in roles.items():
        cursor.execute(f"SELECT * FROM {table} WHERE username=%s", (username,))
        user = cursor.fetchone()
        if not user:
            continue

        now = datetime.now()

        # Checks if the current user's lockout status
        if user.get('locked_until') and user['locked_until'] and user['locked_until'] > now:
            cursor.execute(
                "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                ("login_locked",
                 f"{username}'s account locked until {user['locked_until']}",
                 username)
            )
            db.commit()
            cursor.close(); db.close()
            return None, None

        # Password check 
        if password == user['password_hash']:
            # Successful login → reset counters
            cursor.execute(f"UPDATE {table} SET failed_attempts=0, locked_until=NULL WHERE username=%s", (username,))
            db.commit()

            # Logs success
            cursor.execute("""
                INSERT INTO loginAttempts (username, role, ip_address, successful)
                VALUES (%s, %s, %s, TRUE)
            """, (username, role, request.remote_addr))
            cursor.execute(
                "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                ("login_success", f"{username} logged in successfully as {role}.", username)
            )
            db.commit()
            cursor.close(); db.close()
            return role, user

        # Handle failed password 
        new_attempts = (user['failed_attempts'] or 0) + 1
        lock_until = None

        if new_attempts >= FAILED_LIMIT:
            lock_until = now + LOCKOUT_DURATION
            cursor.execute(f"""
                UPDATE {table}
                SET failed_attempts=%s, locked_until=%s
                WHERE username=%s
            """, (new_attempts, lock_until, username))
            cursor.execute(
                "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                ("lockout", f"{username} account locked until {lock_until}", username)
            )
        else:
            cursor.execute(f"UPDATE {table} SET failed_attempts=%s WHERE username=%s",
                           (new_attempts, username))
            cursor.execute(
                "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
                ("login_failed",
                 f"{username} failed login attempt {new_attempts}/5",
                 username)
            )

        # Log failed attempt
        cursor.execute("""
            INSERT INTO loginAttempts (username, role, ip_address, successful)
            VALUES (%s, %s, %s, FALSE)
        """, (username, role, request.remote_addr))
        db.commit()
        cursor.close(); db.close()
        return None, None

    # User isn't found anywhere
    cursor.execute(
        "INSERT INTO auditLogs (action, description, user_id) VALUES (%s, %s, %s)",
        ("login_failed", f"Unknown username {username} attempted login.", username)
    )
    db.commit()
    cursor.close(); db.close()
    return None, None
