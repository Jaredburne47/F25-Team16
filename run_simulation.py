import MySQLdb
from datetime import datetime
from dateutil.parser import parse

# Database config
db_config = {
    'host': 'localhost',
    'user': 'Team16',
    'passwd': 'Tlaw16',
    'db': 'Team16_DB'
}

# Helper: check if rule is due now
def is_rule_due(schedule_text):
    """
    Example schedule_text: "Tuesdays 9 AM", "Mondays 14:30"
    Returns True if the current day & hour match the schedule
    """
    now = datetime.now()
    
    try:
        # Split weekday and time
        day_part, time_part = schedule_text.split()
        day_part = day_part.lower().rstrip('s')  # e.g., "Tuesdays" -> "tuesday"
        
        # Check day of week
        if day_part != now.strftime("%A").lower():
            return False
        
        # Parse time
        schedule_time = parse(time_part)
        if schedule_time.hour == now.hour:
            return True
    except Exception:
        # Invalid format
        return False
    
    return False

# Main simulation runner
def run_simulation():
    db = MySQLdb.connect(**db_config)
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute("SELECT * FROM simulation_rules WHERE enabled=1")
    rules = cursor.fetchall()
    
    for rule in rules:
        if not rule['schedule']:
            continue  # skip rules without schedule
        if not is_rule_due(rule['schedule']):
            continue  # skip if not due now
        
        # Execute action
        if rule['type'] in ['add_driver', 'remove_driver']:
            driver = rule.get('driver_username')  # can be None
            if driver:
                if rule['type'] == 'add_driver':
                    cursor.execute("INSERT IGNORE INTO drivers (username) VALUES (%s)", (driver,))
                else:
                    cursor.execute("DELETE FROM drivers WHERE username=%s", (driver,))
        elif rule['type'] in ['add_points', 'remove_points']:
            driver = rule.get('driver_username')
            points = rule.get('action_value', 0)
            if driver:
                if rule['type'] == 'add_points':
                    cursor.execute("UPDATE drivers SET points = points + %s WHERE username=%s", (points, driver))
                else:
                    cursor.execute("UPDATE drivers SET points = points - %s WHERE username=%s", (points, driver))
    
    db.commit()
    cursor.close()
    db.close()

if __name__ == "__main__":
    run_simulation()
