import MySQLdb

# --- Database configuration ---
db_config = {
    'host': 'cpsc4910-f25.cobd8enwsupz.us-east-1.rds.amazonaws.com',
    'user': 'Team16',
    'passwd': 'Tlaw16',  
    'db': 'Team16_DB',
    'charset': 'utf8'
}

def _create_user_in_table(table_name, username, email, password_hash):
    """Generic helper: check and insert into a table."""
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()

        # Check if username exists
        cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE username = %s", (username,))
        (count,) = cursor.fetchone()
        if count > 0:
            cursor.close()
            db.close()
            return False, f"Username '{username}' already exists in {table_name} table."

        # Insert new user
        cursor.execute(
            f"INSERT INTO {table_name} (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, password_hash)
        )
        db.commit()
        cursor.close()
        db.close()
        return True, f"User '{username}' added to {table_name} table successfully."

    except Exception as e:
        return False, f"Database error: {e}"
