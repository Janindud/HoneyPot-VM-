import json
import time
import os
import mysql.connector
import geoip2.database
from datetime import datetime

# ==========================================
# CONFIGURATION
# ==========================================
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LOG_FILE = os.getenv("COWRIE_LOG_PATH", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
GEOIP_DB = os.getenv("GEOIP_DB", os.path.join(PROJECT_ROOT, "GeoLite2-Country.mmdb"))
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'cowrie_user'),
    'password': os.getenv('DB_PASSWORD', 'cowrie_pass'),
    'database': os.getenv('DB_NAME', 'cowrie_prod')
}
BATCH_SIZE = int(os.getenv("COWRIE_BATCH_SIZE", "1"))
READ_FROM_START = os.getenv("COWRIE_READ_FROM_START", "0") == "1"
EXIT_AFTER_EOF = os.getenv("COWRIE_EXIT_AFTER_EOF", "0") == "1"

# In-memory IP Geolocation Cache
ip_country_cache = {}

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def parse_timestamp(ts_string):
    """Robustly parse Cowrie ISO8601 timestamps into MySQL DATETIME format."""
    try:
        # Format: "2023-10-27T10:00:00.123456Z" or similar
        ts_clean = ts_string.split('.')[0].replace('Z', '')
        dt = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        return None

def get_country(ip_address, reader):
    """Resolve IP to Country using an in-memory cache to optimize performance."""
    if ip_address in ip_country_cache:
        return ip_country_cache[ip_address]
        
    if reader is None: 
        return "Unknown"
        
    try:
        response = reader.country(ip_address)
        country = response.country.name or "Unknown"
    except (geoip2.errors.AddressNotFoundError, Exception):
        country = "Unknown"
        
    # Store in cache
    ip_country_cache[ip_address] = country
    return country

def tail_f(filepath, read_from_start=False, follow=True):
    """Read Cowrie JSON lines, reopening automatically after log rotation."""
    if not os.path.exists(filepath):
        print(f"Waiting for {filepath} to be created...")
        while not os.path.exists(filepath):
            time.sleep(5)

    first_open = True
    while True:
        file_stat = os.stat(filepath)
        with open(filepath, "r") as f:
            if read_from_start and first_open:
                print(f"Reading existing events from {filepath}...")
            else:
                f.seek(0, 2)
                print(f"Following new events from {filepath}...")

            first_open = False

            while True:
                line = f.readline()
                if line:
                    yield line
                    continue

                if not follow:
                    return

                time.sleep(0.5)

                try:
                    current_stat = os.stat(filepath)
                except FileNotFoundError:
                    print(f"{filepath} disappeared; waiting for recreated log file...")
                    while not os.path.exists(filepath):
                        time.sleep(1)
                    break

                rotated = (
                    current_stat.st_ino != file_stat.st_ino
                    or current_stat.st_dev != file_stat.st_dev
                    or current_stat.st_size < f.tell()
                )
                if rotated:
                    print(f"Detected Cowrie log rotation; reopening {filepath}...")
                    break

        while True:
            line = f.readline()
            if not line:
                if not follow:
                    break
                time.sleep(0.5)
                continue
            yield line

# ==========================================
# DATABASE OPERATION FUNCTIONS
# ==========================================
def get_or_create_attacker(cursor, ip, reader):
    """Ensure attacker exists in the DB or create them, returning ip_id."""
    cursor.execute("SELECT ip_id FROM attackers WHERE src_ip = %s", (ip,))
    row = cursor.fetchone()
    
    if row:
        return row[0]
        
    country = get_country(ip, reader)
    cursor.execute(
        "INSERT INTO attackers (src_ip, country) VALUES (%s, %s)", 
        (ip, country)
    )
    return cursor.lastrowid

def check_session_exists(cursor, session_id):
    """Database query to verify if a session ID exists."""
    cursor.execute("SELECT 1 FROM sessions WHERE session_id = %s", (session_id,))
    return cursor.fetchone() is not None

def insert_session(cursor, session_id, ip_id, ts):
    """Insert a new session idempotently."""
    cursor.execute(
        "INSERT IGNORE INTO sessions (session_id, ip_id, start_time) VALUES (%s, %s, %s)", 
        (session_id, ip_id, ts)
    )

def handle_auth_attempt(cursor, log, session_id, ts):
    """Extract and capture a brute-force credential attempt."""
    event_id = log.get('eventid')
    user = log.get('username', '')
    pw = log.get('password', '')
    success = (event_id == 'cowrie.login.success')
    
    cursor.execute(
        "INSERT IGNORE INTO auth_attempts (session_id, timestamp, username, password, is_success) VALUES (%s, %s, %s, %s, %s)",
        (session_id, ts, user, pw, success)
    )

def handle_command_input(cursor, log, session_id, ts):
    """Extract and capture executed high-interaction commands."""
    cmd = log.get('input', '')
    cursor.execute(
        "INSERT IGNORE INTO commands (session_id, timestamp, input) VALUES (%s, %s, %s)", 
        (session_id, ts, cmd)
    )

def handle_session_closed(cursor, log, session_id, ts):
    """Mark session as closed and compute actual duration."""
    duration = log.get('duration', 0)
    cursor.execute(
        "UPDATE sessions SET end_time = %s, duration_seconds = %s WHERE session_id = %s", 
        (ts, duration, session_id)
    )

# ==========================================
# MAIN EVENT PROCESSOR
# ==========================================
def process_event(cursor, log, reader):
    """Main routing function for individual JSON events."""
    event_id = log.get('eventid')
    session_id = log.get('session')
    ip = log.get('src_ip')
    raw_ts = log.get('timestamp')
    
    # Validation 1: Required fields
    if not event_id or not session_id or not ip or not raw_ts:
        return False

    # Validation 2: Timestamp Parsing
    ts = parse_timestamp(raw_ts)
    if not ts:
        return False

    # Route based on event type
    if event_id == 'cowrie.session.connect':
        ip_id = get_or_create_attacker(cursor, ip, reader)
        insert_session(cursor, session_id, ip_id, ts)
        return True
        
    elif event_id in ['cowrie.login.failed', 'cowrie.login.success']:
        if check_session_exists(cursor, session_id):
            handle_auth_attempt(cursor, log, session_id, ts)
            return True
            
    elif event_id == 'cowrie.command.input':
        if check_session_exists(cursor, session_id):
            handle_command_input(cursor, log, session_id, ts)
            return True
            
    elif event_id == 'cowrie.session.closed':
        if check_session_exists(cursor, session_id):
            handle_session_closed(cursor, log, session_id, ts)
            return True

    return False

# ==========================================
# MAIN ETL LOOP
# ==========================================
def run_realtime_ingest():
    print("Starting Optimized REAL-TIME Cowrie ETL Pipeline...")
    
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
    except Exception as e:
        print(f"CRITICAL: Failed to connect to MySQL Database: {e}")
        return

    # Load GeoIP Reader
    reader = None
    if os.path.exists(GEOIP_DB):
        reader = geoip2.database.Reader(GEOIP_DB)
    else:
        print(f"Warning: GeoIP DB not found at {GEOIP_DB}. Lookups disabled.")

    batch_counter = 0
    processed_counter = 0

    try:
        for line in tail_f(LOG_FILE, READ_FROM_START, not EXIT_AFTER_EOF):
            try:
                log = json.loads(line)
                success = process_event(cursor, log, reader)
                
                # Batch Commit Processing
                if success:
                    batch_counter += 1
                    processed_counter += 1
                    if batch_counter >= BATCH_SIZE:
                        conn.commit()
                        batch_counter = 0

            except json.JSONDecodeError:
                # Safely skip broken lines without crashing the pipeline
                continue
            except mysql.connector.Error as db_err:
                print(f"Database Error processing line: {db_err}")
                # Rollback this transaction but keep the pipeline alive
                conn.rollback() 
                continue
            except Exception as e:
                print(f"Unexpected ETL Error: {e}")
                continue
    finally:
        if batch_counter:
            conn.commit()
        cursor.close()
        conn.close()
        print(f"ETL stopped. Processed {processed_counter} database events.")

if __name__ == "__main__":
    run_realtime_ingest()
