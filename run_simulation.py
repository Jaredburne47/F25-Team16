import MySQLdb
import schedule
import time
from datetime import datetime, timedelta

# ----------------------
# Database Configuration
# ----------------------
db_config = {
    'host': 'localhost',
    'user': 'Team16',
    'passwd': 'Tlaw16',
    'db': 'Team16_DB'
}

# ----------------------
# Helper Functions
# ----------------------
def is_rule_due(schedule_str):
    """Check if a rule schedule matches the current time within ±15 minutes."""
    now = datetime.now()
    try:
        parts = schedule_str.strip().split()
        day_part = parts[0].lower()
        time_part = parts[1]

        # Convert scheduled day to number (0=Monday)
        days_map = {
            'mon': 0, 'monday': 0,
            'tue': 1, 'tuesday': 1,
            'wed': 2, 'wednesday': 2,
            'thu': 3, 'thursday': 3,
            'fri': 4, 'friday': 4,
            'sat': 5, 'saturday': 5,
            'sun': 6, 'sunday': 6
        }

        scheduled_day = days_map.get(day_part[:3])
        if scheduled_day is None:
            print(f"[WARN] Unknown day in schedule: {schedule_str}")
            return False

        # Parse scheduled time
        scheduled_time = datetime.strptime(time_part, "%H:%M").time()
        scheduled_datetime = datetime.combine(
            now.date() + timedelta(days=(scheduled_day - now.weekday()) % 7),
            scheduled_time
        )

        # Check if current time is within ±15 minutes
        window_start = scheduled_datetime - timedelta(minutes=15)
        window_end = scheduled_datetime + timedelta(minutes=15)
        return window_start <= now <= window_end
    except Exception as e:
        print(f"[ERROR] Failed to parse schedule '{schedule_str}': {e}")
        return False

def run_simulation():
    """Main simulation runner."""
    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Fetch all enabled rules
        cursor.execute("SELECT * FROM simulation_rules WHERE enabled=1")
        rules = cursor.fetchall()

        for rule in rules:
            if is_rule_due(rule['schedule']):
                execute_rule(rule)

        cursor.close()
        db.close()
    except Exception as e:
        print(f"[ERROR] Simulation failed: {e}")

def execute_rule(rule):
    """Perform the action defined by a rule."""
    action_type = rule['type']
    value = rule['action_value']

    try:
        db = MySQLdb.connect(**db_config)
        cursor = db.cursor()

        if action_type == 'add_driver':
            username = rule.get('driver_username')
            if username:
                cursor.execute("INSERT IGNORE INTO drivers (username) VALUES (%s)", (username,))
                db.commit()
                print(f"[SIM] Added driver '{username}'")
            else:
                print(f"[WARN] Missing username for add_driver rule {rule['id']}")

        elif action_type == 'remove_driver':
            username = rule.get('driver_username')
            if username:
                cursor.execute("DELETE FROM drivers WHERE username=%s", (username,))
                db.commit()
                print(f"[SIM] Removed driver '{username}'")
            else:
                print(f"[WARN] Missing username for remove_driver rule {rule['id']}")

        elif action_type == 'add_points':
            username = rule.get('driver_username')
            if username and value is not None:
                cursor.execute("UPDATE drivers SET points = points + %s WHERE username=%s", (value, username))
                db.commit()
                print(f"[SIM] Added {value} points to '{username}'")
            else:
                print(f"[WARN] Missing username or value for add_points rule {rule['id']}")

        elif action_type == 'remove_points':
            username = rule.get('driver_username')
            if username and value is not None:
                cursor.execute("UPDATE drivers SET points = GREATEST(points - %s, 0) WHERE username=%s", (value, username))
                db.commit()
                print(f"[SIM] Removed {value} points from '{username}'")
            else:
                print(f"[WARN] Missing username or value for remove_points rule {rule['id']}")

        cursor.close()
        db.close()
    except Exception as e:
        print(f"[ERROR] Failed to execute rule {rule['id']}: {e}")

# ----------------------
# Scheduler
# ----------------------
schedule.every(15).minutes.do(run_simulation)

print("[INFO] Simulation scheduler started. Running every 15 minutes.")
run_simulation()  # Optional: run immediately on startup

while True:
    schedule.run_pending()
    time.sleep(1)

