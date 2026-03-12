#!/usr/bin/env python3
import os
import pwd
import sqlite3
import stat
import time
import hashlib
from datetime import datetime, timedelta

DB_PATH = "/var/lib/hids_collector/logs.db"
ALERTS_DB_PATH = "/var/lib/hids_collector/alerts.db"  # Separate database for alerts
CHECK_INTERVAL = 5

# Rule Thresholds
BRUTE_FORCE_THRESHOLD = 5
NEW_PROCESS_THRESHOLD = 10  # Alert if more than 10 new processes in CHECK_INTERVAL
NETWORK_ACTIVITY_THRESHOLD = 50  # Alert if more than 50 network events in CHECK_INTERVAL
FILE_MOD_THRESHOLD = 20  # Alert if more than 20 file modifications in CHECK_INTERVAL
EVENT_ESCALATION_THRESHOLD = 3  # Alert if 3+ high severity events in short time

# Honeypot Configuration
HONEYPOT_IPS = ["192.168.1.100"]  # Add your honeypot IPs here
HONEYPOT_PORTS = [22, 80, 443, 3306]  # Common honeypot ports

# Critical System Files for Hash Checking
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
]

# Baseline hash storage (initialize with known good hashes)
FILE_HASHES = {}

# Authorized Users
AUTHORIZED_DB_USER = "ec2-user"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def connect_db():
    """Connect to the logs database (read-only for events)"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def connect_alerts_db():
    """Connect to the separate alerts database"""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    create_alerts_table(conn)
    return conn


def create_alerts_table(conn):
    """Create alerts table if it doesn't exist"""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            event_ref INTEGER
        )
    """)
    conn.commit()


def create_alert(alerts_conn, rule_name, severity, description, event_ref=None):
    alerts_conn.execute(
        """
        INSERT INTO alerts(timestamp, rule_name, severity, source, description, event_ref)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            rule_name,
            severity,
            "rules_engine",
            description,
            event_ref,
        ),
    )
    alerts_conn.commit()


def alert_exists(alerts_conn, rule_name, event_ref):
    cur = alerts_conn.cursor()
    cur.execute(
        """
        SELECT 1 FROM alerts
        WHERE rule_name=? AND event_ref=?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


# --------------------------
# Brute Force Rule
# --------------------------

def check_brute_force(logs_conn, alerts_conn):
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            LOWER(message) LIKE '%failed%'
            OR LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%failed password%'
        ORDER BY id DESC
        LIMIT 25
        """
    )

    rows = cur.fetchall()

    if len(rows) >= BRUTE_FORCE_THRESHOLD:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "Brute Force Login", newest):
            create_alert(
                alerts_conn,
                "Brute Force Login",
                "high",
                f"Detected {len(rows)} recent failed authentication events",
                newest,
            )


# --------------------------
# Database Access Control Rule
# --------------------------

def check_db_permissions(logs_conn, alerts_conn):
    if not os.path.exists(DB_PATH):
        create_alert(
            alerts_conn,
            "Database Integrity",
            "high",
            "Database file missing",
        )
        return

    st = os.stat(DB_PATH)
    owner = pwd.getpwuid(st.st_uid).pw_name
    mode = stat.S_IMODE(st.st_mode)

    if owner != AUTHORIZED_DB_USER:
        create_alert(
            alerts_conn,
            "Database Access Control",
            "high",
            f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}",
        )

    if mode != EXPECTED_DB_MODE:
        create_alert(
            alerts_conn,
            "Database Permission Error",
            "high",
            f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}",
        )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(logs_conn, alerts_conn):
    """Detect any connections to honeypot IPs"""
    cur = logs_conn.cursor()
    
    ip_list = ",".join([f"'{ip}'" for ip in HONEYPOT_IPS])
    
    cur.execute(
        f"""
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%{HONEYPOT_IPS[0]}%'
            OR LOWER(message) LIKE '%connect%'
            OR LOWER(message) LIKE '%honeypot%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Honeypot Access", newest):
            create_alert(
                alerts_conn,
                "Honeypot Access",
                "critical",
                f"Connection to honeypot detected. {len(rows)} event(s) detected",
                newest,
            )


# --------------------------
# File Hash Verification (Hash Mismatch)
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file"""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return None


def check_file_integrity(logs_conn, alerts_conn):
    """Detect file modifications via hash comparison"""
    for filepath in CRITICAL_FILES:
        if not os.path.exists(filepath):
            continue
        
        current_hash = compute_file_hash(filepath)
        if current_hash is None:
            continue
        
        # Initialize hash if not present
        if filepath not in FILE_HASHES:
            FILE_HASHES[filepath] = current_hash
            continue
        
        # Check if hash changed
        if FILE_HASHES[filepath] != current_hash:
            if not alert_exists(alerts_conn, "File Integrity Violation", hash(filepath)):
                create_alert(
                    alerts_conn,
                    "File Integrity Violation",
                    "critical",
                    f"Hash mismatch for {filepath}. File has been modified!",
                    hash(filepath),
                )
            FILE_HASHES[filepath] = current_hash


# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn):
    """Detect new suspicious processes"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%new process%'
            OR LOWER(message) LIKE '%process spawned%'
            OR LOWER(message) LIKE '%exec%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NEW_PROCESS_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Excessive New Processes", newest):
            create_alert(
                alerts_conn,
                "Excessive New Processes",
                "medium",
                f"Detected {len(rows)} new processes in short timeframe",
                newest,
            )


# --------------------------
# Privilege Escalation Detection
# --------------------------

def check_privilege_escalation(logs_conn, alerts_conn):
    """Detect unauthorized privilege escalation attempts"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%sudo%'
            OR LOWER(message) LIKE '%privilege escalation%'
            OR LOWER(message) LIKE '%unauthorized privilege%'
            OR LOWER(message) LIKE '%root access%'
            OR LOWER(message) LIKE '%elevated privileges%'
            OR LOWER(message) LIKE '%suid%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            create_alert(
                alerts_conn,
                "Privilege Escalation Attempt",
                "high",
                f"Potential privilege escalation detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Event Escalation Detection
# --------------------------

def check_event_escalation(logs_conn, alerts_conn):
    """Detect rapid escalation of high-severity events"""
    cur = alerts_conn.cursor()
    
    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE severity='high' OR severity='critical'
        AND timestamp > datetime('now', '-1 minutes')
        """
    )
    
    result = cur.fetchone()
    count = result["count"] if result else 0
    
    if count >= EVENT_ESCALATION_THRESHOLD:
        if not alert_exists(alerts_conn, "Event Escalation", count):
            create_alert(
                alerts_conn,
                "Event Escalation",
                "critical",
                f"Rapid escalation: {count} high/critical alerts in 1 minute",
                count,
            )


# --------------------------
# Network Activity Detection
# --------------------------

def check_network_anomalies(logs_conn, alerts_conn):
    """Detect unusual network activity"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%network%'
            OR LOWER(message) LIKE '%connection%'
            OR LOWER(message) LIKE '%packet%'
            OR LOWER(message) LIKE '%traffic%'
            OR LOWER(message) LIKE '%socket%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NETWORK_ACTIVITY_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Abnormal Network Activity", newest):
            create_alert(
                alerts_conn,
                "Abnormal Network Activity",
                "medium",
                f"High network activity detected: {len(rows)} events in short time",
                newest,
            )


# --------------------------
# File Modification Detection
# --------------------------

def check_file_modifications(logs_conn, alerts_conn):
    """Detect excessive file modifications"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%modify%'
            OR LOWER(message) LIKE '%write%'
            OR LOWER(message) LIKE '%delete%'
            OR LOWER(message) LIKE '%rename%'
            OR LOWER(message) LIKE '%chmod%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= FILE_MOD_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Excessive File Modifications", newest):
            create_alert(
                alerts_conn,
                "Excessive File Modifications",
                "medium",
                f"Detected {len(rows)} file modification events in short time",
                newest,
            )


# --------------------------
# Suspicious Port Activity
# --------------------------

def check_suspicious_ports(logs_conn, alerts_conn):
    """Detect suspicious port opening/closing or SSH changes"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%port%'
            OR LOWER(message) LIKE '%ssh%'
            OR LOWER(message) LIKE '%sshd%'
            OR LOWER(message) LIKE '%listening%'
            OR LOWER(message) LIKE '%bind%')
            AND (LOWER(message) LIKE '%open%'
            OR LOWER(message) LIKE '%close%'
            OR LOWER(message) LIKE '%change%'
            OR LOWER(message) LIKE '%modify%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Suspicious Port Activity", newest):
            create_alert(
                alerts_conn,
                "Suspicious Port Activity",
                "high",
                f"Suspicious port/SSH activity detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Main Loop
# --------------------------

def main():
    print("Rule engine started")
    print("Alerts database: " + ALERTS_DB_PATH)
    print("Running rules:")
    print("  - Brute Force Detection")
    print("  - Database Access Control")
    print("  - Honeypot Access Detection")
    print("  - File Integrity Verification")
    print("  - New Process Detection")
    print("  - Privilege Escalation Detection")
    print("  - Event Escalation Detection")
    print("  - Network Anomaly Detection")
    print("  - File Modification Detection")
    print("  - Suspicious Port Activity Detection")

    while True:
        try:
            logs_conn = connect_db()
            alerts_conn = connect_alerts_db()

            # Run all detection rules
            check_brute_force(logs_conn, alerts_conn)
            check_db_permissions(logs_conn, alerts_conn)
            check_honeypot_access(logs_conn, alerts_conn)
            check_file_integrity(logs_conn, alerts_conn)
            check_new_processes(logs_conn, alerts_conn)
            check_privilege_escalation(logs_conn, alerts_conn)
            check_event_escalation(logs_conn, alerts_conn)
            check_network_anomalies(logs_conn, alerts_conn)
            check_file_modifications(logs_conn, alerts_conn)
            check_suspicious_ports(logs_conn, alerts_conn)

            logs_conn.close()
            alerts_conn.close()

        except Exception as e:
            print(f"[RULE ENGINE ERROR] {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()# Authorized Users
AUTHORIZED_DB_USER = "ec2-user"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def connect_db():
    """Connect to the logs database (read-only for events)"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def connect_alerts_db():
    """Connect to the separate alerts database"""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    create_alerts_table(conn)
    return conn


def create_alerts_table(conn):
    """Create alerts table if it doesn't exist"""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            event_ref INTEGER
        )
    """)
    conn.commit()


def create_alert(alerts_conn, rule_name, severity, description, event_ref=None):
    alerts_conn.execute(
        """
        INSERT INTO alerts(timestamp, rule_name, severity, source, description, event_ref)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            rule_name,
            severity,
            "rules_engine",
            description,
            event_ref,
        ),
    )
    alerts_conn.commit()


def alert_exists(alerts_conn, rule_name, event_ref):
    cur = alerts_conn.cursor()
    cur.execute(
        """
        SELECT 1 FROM alerts
        WHERE rule_name=? AND event_ref=?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


# --------------------------
# Brute Force Rule
# --------------------------

def check_brute_force(logs_conn, alerts_conn):
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            LOWER(message) LIKE '%failed%'
            OR LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%failed password%'
        ORDER BY id DESC
        LIMIT 25
        """
    )

    rows = cur.fetchall()

    if len(rows) >= BRUTE_FORCE_THRESHOLD:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "Brute Force Login", newest):
            create_alert(
                alerts_conn,
                "Brute Force Login",
                "high",
                f"Detected {len(rows)} recent failed authentication events",
                newest,
            )


# --------------------------
# Database Access Control Rule
# --------------------------

def check_db_permissions(logs_conn, alerts_conn):
    if not os.path.exists(DB_PATH):
        create_alert(
            alerts_conn,
            "Database Integrity",
            "high",
            "Database file missing",
        )
        return

    st = os.stat(DB_PATH)
    owner = pwd.getpwuid(st.st_uid).pw_name
    mode = stat.S_IMODE(st.st_mode)

    if owner != AUTHORIZED_DB_USER:
        create_alert(
            alerts_conn,
            "Database Access Control",
            "high",
            f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}",
        )

    if mode != EXPECTED_DB_MODE:
        create_alert(
            alerts_conn,
            "Database Permission Error",
            "high",
            f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}",
        )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(logs_conn, alerts_conn):
    """Detect any connections to honeypot IPs"""
    cur = logs_conn.cursor()
    
    ip_list = ",".join([f"'{ip}'" for ip in HONEYPOT_IPS])
    
    cur.execute(
        f"""
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%{HONEYPOT_IPS[0]}%'
            OR LOWER(message) LIKE '%connect%'
            OR LOWER(message) LIKE '%honeypot%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Honeypot Access", newest):
            create_alert(
                alerts_conn,
                "Honeypot Access",
                "critical",
                f"Connection to honeypot detected. {len(rows)} event(s) detected",
                newest,
            )


# --------------------------
# File Hash Verification (Hash Mismatch)
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file"""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return None


def check_file_integrity(logs_conn, alerts_conn):
    """Detect file modifications via hash comparison"""
    for filepath in CRITICAL_FILES:
        if not os.path.exists(filepath):
            continue
        
        current_hash = compute_file_hash(filepath)
        if current_hash is None:
            continue
        
        # Initialize hash if not present
        if filepath not in FILE_HASHES:
            FILE_HASHES[filepath] = current_hash
            continue
        
        # Check if hash changed
        if FILE_HASHES[filepath] != current_hash:
            if not alert_exists(alerts_conn, "File Integrity Violation", hash(filepath)):
                create_alert(
                    alerts_conn,
                    "File Integrity Violation",
                    "critical",
                    f"Hash mismatch for {filepath}. File has been modified!",
                    hash(filepath),
                )
            FILE_HASHES[filepath] = current_hash


# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn):
    """Detect new suspicious processes"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%new process%'
            OR LOWER(message) LIKE '%process spawned%'
            OR LOWER(message) LIKE '%exec%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NEW_PROCESS_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Excessive New Processes", newest):
            create_alert(
                alerts_conn,
                "Excessive New Processes",
                "medium",
                f"Detected {len(rows)} new processes in short timeframe",
                newest,
            )


# --------------------------
# Privilege Escalation Detection
# --------------------------

def check_privilege_escalation(logs_conn, alerts_conn):
    """Detect unauthorized privilege escalation attempts"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%sudo%'
            OR LOWER(message) LIKE '%privilege escalation%'
            OR LOWER(message) LIKE '%unauthorized privilege%'
            OR LOWER(message) LIKE '%root access%'
            OR LOWER(message) LIKE '%elevated privileges%'
            OR LOWER(message) LIKE '%suid%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            create_alert(
                alerts_conn,
                "Privilege Escalation Attempt",
                "high",
                f"Potential privilege escalation detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Event Escalation Detection
# --------------------------

def check_event_escalation(logs_conn, alerts_conn):
    """Detect rapid escalation of high-severity events"""
    cur = alerts_conn.cursor()
    
    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE severity='high' OR severity='critical'
        AND timestamp > datetime('now', '-1 minutes')
        """
    )
    
    result = cur.fetchone()
    count = result["count"] if result else 0
    
    if count >= EVENT_ESCALATION_THRESHOLD:
        if not alert_exists(alerts_conn, "Event Escalation", count):
            create_alert(
                alerts_conn,
                "Event Escalation",
                "critical",
                f"Rapid escalation: {count} high/critical alerts in 1 minute",
                count,
            )


# --------------------------
# Network Activity Detection
# --------------------------

def check_network_anomalies(logs_conn, alerts_conn):
    """Detect unusual network activity"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%network%'
            OR LOWER(message) LIKE '%connection%'
            OR LOWER(message) LIKE '%packet%'
            OR LOWER(message) LIKE '%traffic%'
            OR LOWER(message) LIKE '%socket%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NETWORK_ACTIVITY_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Abnormal Network Activity", newest):
            create_alert(
                alerts_conn,
                "Abnormal Network Activity",
                "medium",
                f"High network activity detected: {len(rows)} events in short time",
                newest,
            )


# --------------------------
# File Modification Detection
# --------------------------

def check_file_modifications(logs_conn, alerts_conn):
    """Detect excessive file modifications"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%modify%'
            OR LOWER(message) LIKE '%write%'
            OR LOWER(message) LIKE '%delete%'
            OR LOWER(message) LIKE '%rename%'
            OR LOWER(message) LIKE '%chmod%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= FILE_MOD_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Excessive File Modifications", newest):
            create_alert(
                alerts_conn,
                "Excessive File Modifications",
                "medium",
                f"Detected {len(rows)} file modification events in short time",
                newest,
            )


# --------------------------
# Suspicious Port Activity
# --------------------------

def check_suspicious_ports(logs_conn, alerts_conn):
    """Detect suspicious port opening/closing or SSH changes"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%port%'
            OR LOWER(message) LIKE '%ssh%'
            OR LOWER(message) LIKE '%sshd%'
            OR LOWER(message) LIKE '%listening%'
            OR LOWER(message) LIKE '%bind%')
            AND (LOWER(message) LIKE '%open%'
            OR LOWER(message) LIKE '%close%'
            OR LOWER(message) LIKE '%change%'
            OR LOWER(message) LIKE '%modify%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Suspicious Port Activity", newest):
            create_alert(
                alerts_conn,
                "Suspicious Port Activity",
                "high",
                f"Suspicious port/SSH activity detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Main Loop
# --------------------------

def main():
    print("Rule engine started")
    print("Alerts database: " + ALERTS_DB_PATH)
    print("Running rules:")
    print("  - Brute Force Detection")
    print("  - Database Access Control")
    print("  - Honeypot Access Detection")
    print("  - File Integrity Verification")
    print("  - New Process Detection")
    print("  - Privilege Escalation Detection")
    print("  - Event Escalation Detection")
    print("  - Network Anomaly Detection")
    print("  - File Modification Detection")
    print("  - Suspicious Port Activity Detection")

    while True:
        try:
            logs_conn = connect_db()
            alerts_conn = connect_alerts_db()

            # Run all detection rules
            check_brute_force(logs_conn, alerts_conn)
            check_db_permissions(logs_conn, alerts_conn)
            check_honeypot_access(logs_conn, alerts_conn)
            check_file_integrity(logs_conn, alerts_conn)
            check_new_processes(logs_conn, alerts_conn)
            check_privilege_escalation(logs_conn, alerts_conn)
            check_event_escalation(logs_conn, alerts_conn)
            check_network_anomalies(logs_conn, alerts_conn)
            check_file_modifications(logs_conn, alerts_conn)
            check_suspicious_ports(logs_conn, alerts_conn)

            logs_conn.close()
            alerts_conn.close()

        except Exception as e:
            print(f"[RULE ENGINE ERROR] {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()# Authorized Users
AUTHORIZED_DB_USER = "c0nn13"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def connect_db():
    """Connect to the logs database (read-only for events)"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def connect_alerts_db():
    """Connect to the separate alerts database"""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    create_alerts_table(conn)
    return conn


def create_alerts_table(conn):
    """Create alerts table if it doesn't exist"""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            event_ref INTEGER
        )
    """)
    conn.commit()


def create_alert(alerts_conn, rule_name, severity, description, event_ref=None):
    alerts_conn.execute(
        """
        INSERT INTO alerts(timestamp, rule_name, severity, source, description, event_ref)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            rule_name,
            severity,
            "rules_engine",
            description,
            event_ref,
        ),
    )
    alerts_conn.commit()


def alert_exists(alerts_conn, rule_name, event_ref):
    cur = alerts_conn.cursor()
    cur.execute(
        """
        SELECT 1 FROM alerts
        WHERE rule_name=? AND event_ref=?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


# --------------------------
# Brute Force Rule
# --------------------------

def check_brute_force(logs_conn, alerts_conn):
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            LOWER(message) LIKE '%failed%'
            OR LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%failed password%'
        ORDER BY id DESC
        LIMIT 25
        """
    )

    rows = cur.fetchall()

    if len(rows) >= BRUTE_FORCE_THRESHOLD:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "Brute Force Login", newest):
            create_alert(
                alerts_conn,
                "Brute Force Login",
                "high",
                f"Detected {len(rows)} recent failed authentication events",
                newest,
            )


# --------------------------
# Database Access Control Rule
# --------------------------

def check_db_permissions(logs_conn, alerts_conn):
    if not os.path.exists(DB_PATH):
        create_alert(
            alerts_conn,
            "Database Integrity",
            "high",
            "Database file missing",
        )
        return

    st = os.stat(DB_PATH)
    owner = pwd.getpwuid(st.st_uid).pw_name
    mode = stat.S_IMODE(st.st_mode)

    if owner != AUTHORIZED_DB_USER:
        create_alert(
            alerts_conn,
            "Database Access Control",
            "high",
            f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}",
        )

    if mode != EXPECTED_DB_MODE:
        create_alert(
            alerts_conn,
            "Database Permission Error",
            "high",
            f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}",
        )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(logs_conn, alerts_conn):
    """Detect any connections to honeypot IPs"""
    cur = logs_conn.cursor()
    
    ip_list = ",".join([f"'{ip}'" for ip in HONEYPOT_IPS])
    
    cur.execute(
        f"""
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%{HONEYPOT_IPS[0]}%'
            OR LOWER(message) LIKE '%connect%'
            OR LOWER(message) LIKE '%honeypot%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Honeypot Access", newest):
            create_alert(
                alerts_conn,
                "Honeypot Access",
                "critical",
                f"Connection to honeypot detected. {len(rows)} event(s) detected",
                newest,
            )


# --------------------------
# File Hash Verification (Hash Mismatch)
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file"""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return None


def check_file_integrity(logs_conn, alerts_conn):
    """Detect file modifications via hash comparison"""
    for filepath in CRITICAL_FILES:
        if not os.path.exists(filepath):
            continue
        
        current_hash = compute_file_hash(filepath)
        if current_hash is None:
            continue
        
        # Initialize hash if not present
        if filepath not in FILE_HASHES:
            FILE_HASHES[filepath] = current_hash
            continue
        
        # Check if hash changed
        if FILE_HASHES[filepath] != current_hash:
            if not alert_exists(alerts_conn, "File Integrity Violation", hash(filepath)):
                create_alert(
                    alerts_conn,
                    "File Integrity Violation",
                    "critical",
                    f"Hash mismatch for {filepath}. File has been modified!",
                    hash(filepath),
                )
            FILE_HASHES[filepath] = current_hash


# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn):
    """Detect new suspicious processes"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%new process%'
            OR LOWER(message) LIKE '%process spawned%'
            OR LOWER(message) LIKE '%exec%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NEW_PROCESS_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Excessive New Processes", newest):
            create_alert(
                alerts_conn,
                "Excessive New Processes",
                "medium",
                f"Detected {len(rows)} new processes in short timeframe",
                newest,
            )


# --------------------------
# Privilege Escalation Detection
# --------------------------

def check_privilege_escalation(logs_conn, alerts_conn):
    """Detect unauthorized privilege escalation attempts"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%sudo%'
            OR LOWER(message) LIKE '%privilege escalation%'
            OR LOWER(message) LIKE '%unauthorized privilege%'
            OR LOWER(message) LIKE '%root access%'
            OR LOWER(message) LIKE '%elevated privileges%'
            OR LOWER(message) LIKE '%suid%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            create_alert(
                alerts_conn,
                "Privilege Escalation Attempt",
                "high",
                f"Potential privilege escalation detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Event Escalation Detection
# --------------------------

def check_event_escalation(logs_conn, alerts_conn):
    """Detect rapid escalation of high-severity events"""
    cur = alerts_conn.cursor()
    
    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE severity='high' OR severity='critical'
        AND timestamp > datetime('now', '-1 minutes')
        """
    )
    
    result = cur.fetchone()
    count = result["count"] if result else 0
    
    if count >= EVENT_ESCALATION_THRESHOLD:
        if not alert_exists(alerts_conn, "Event Escalation", count):
            create_alert(
                alerts_conn,
                "Event Escalation",
                "critical",
                f"Rapid escalation: {count} high/critical alerts in 1 minute",
                count,
            )


# --------------------------
# Network Activity Detection
# --------------------------

def check_network_anomalies(logs_conn, alerts_conn):
    """Detect unusual network activity"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%network%'
            OR LOWER(message) LIKE '%connection%'
            OR LOWER(message) LIKE '%packet%'
            OR LOWER(message) LIKE '%traffic%'
            OR LOWER(message) LIKE '%socket%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NETWORK_ACTIVITY_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Abnormal Network Activity", newest):
            create_alert(
                alerts_conn,
                "Abnormal Network Activity",
                "medium",
                f"High network activity detected: {len(rows)} events in short time",
                newest,
            )


# --------------------------
# File Modification Detection
# --------------------------

def check_file_modifications(logs_conn, alerts_conn):
    """Detect excessive file modifications"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%modify%'
            OR LOWER(message) LIKE '%write%'
            OR LOWER(message) LIKE '%delete%'
            OR LOWER(message) LIKE '%rename%'
            OR LOWER(message) LIKE '%chmod%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= FILE_MOD_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Excessive File Modifications", newest):
            create_alert(
                alerts_conn,
                "Excessive File Modifications",
                "medium",
                f"Detected {len(rows)} file modification events in short time",
                newest,
            )


# --------------------------
# Suspicious Port Activity
# --------------------------

def check_suspicious_ports(logs_conn, alerts_conn):
    """Detect suspicious port opening/closing or SSH changes"""
    cur = logs_conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%port%'
            OR LOWER(message) LIKE '%ssh%'
            OR LOWER(message) LIKE '%sshd%'
            OR LOWER(message) LIKE '%listening%'
            OR LOWER(message) LIKE '%bind%')
            AND (LOWER(message) LIKE '%open%'
            OR LOWER(message) LIKE '%close%'
            OR LOWER(message) LIKE '%change%'
            OR LOWER(message) LIKE '%modify%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Suspicious Port Activity", newest):
            create_alert(
                alerts_conn,
                "Suspicious Port Activity",
                "high",
                f"Suspicious port/SSH activity detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Main Loop
# --------------------------

def main():
    print("Rule engine started")
    print("Alerts database: " + ALERTS_DB_PATH)
    print("Running rules:")
    print("  - Brute Force Detection")
    print("  - Database Access Control")
    print("  - Honeypot Access Detection")
    print("  - File Integrity Verification")
    print("  - New Process Detection")
    print("  - Privilege Escalation Detection")
    print("  - Event Escalation Detection")
    print("  - Network Anomaly Detection")
    print("  - File Modification Detection")
    print("  - Suspicious Port Activity Detection")

    while True:
        try:
            logs_conn = connect_db()
            alerts_conn = connect_alerts_db()

            # Run all detection rules
            check_brute_force(logs_conn, alerts_conn)
            check_db_permissions(logs_conn, alerts_conn)
            check_honeypot_access(logs_conn, alerts_conn)
            check_file_integrity(logs_conn, alerts_conn)
            check_new_processes(logs_conn, alerts_conn)
            check_privilege_escalation(logs_conn, alerts_conn)
            check_event_escalation(logs_conn, alerts_conn)
            check_network_anomalies(logs_conn, alerts_conn)
            check_file_modifications(logs_conn, alerts_conn)
            check_suspicious_ports(logs_conn, alerts_conn)

            logs_conn.close()
            alerts_conn.close()

        except Exception as e:
            print(f"[RULE ENGINE ERROR] {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()AUTHORIZED_DB_USER = "c0nn13"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_alert(conn, rule_name, severity, description, event_ref=None):
    conn.execute(
        """
        INSERT INTO alerts(timestamp, rule_name, severity, source, description, event_ref)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            rule_name,
            severity,
            "rules_engine",
            description,
            event_ref,
        ),
    )
    conn.commit()


def alert_exists(conn, rule_name, event_ref):
    cur = conn.cursor()
    cur.execute(
        """
        SELECT 1 FROM alerts
        WHERE rule_name=? AND event_ref=?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


# --------------------------
# Brute Force Rule
# --------------------------

def check_brute_force(conn):
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            LOWER(message) LIKE '%failed%'
            OR LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%failed password%'
        ORDER BY id DESC
        LIMIT 25
        """
    )

    rows = cur.fetchall()

    if len(rows) >= BRUTE_FORCE_THRESHOLD:
        newest = rows[0]["id"]

        if not alert_exists(conn, "Brute Force Login", newest):
            create_alert(
                conn,
                "Brute Force Login",
                "high",
                f"Detected {len(rows)} recent failed authentication events",
                newest,
            )


# --------------------------
# Database Access Control Rule
# --------------------------

def check_db_permissions(conn):
    if not os.path.exists(DB_PATH):
        create_alert(
            conn,
            "Database Integrity",
            "high",
            "Database file missing",
        )
        return

    st = os.stat(DB_PATH)
    owner = pwd.getpwuid(st.st_uid).pw_name
    mode = stat.S_IMODE(st.st_mode)

    if owner != AUTHORIZED_DB_USER:
        create_alert(
            conn,
            "Database Access Control",
            "high",
            f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}",
        )

    if mode != EXPECTED_DB_MODE:
        create_alert(
            conn,
            "Database Permission Error",
            "high",
            f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}",
        )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(conn):
    """Detect any connections to honeypot IPs"""
    cur = conn.cursor()
    
    ip_list = ",".join([f"'{ip}'" for ip in HONEYPOT_IPS])
    
    cur.execute(
        f"""
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%{HONEYPOT_IPS[0]}%'
            OR LOWER(message) LIKE '%connect%'
            OR LOWER(message) LIKE '%honeypot%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(conn, "Honeypot Access", newest):
            create_alert(
                conn,
                "Honeypot Access",
                "critical",
                f"Connection to honeypot detected. {len(rows)} event(s) detected",
                newest,
            )


# --------------------------
# File Hash Verification (Hash Mismatch)
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file"""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return None


def check_file_integrity(conn):
    """Detect file modifications via hash comparison"""
    for filepath in CRITICAL_FILES:
        if not os.path.exists(filepath):
            continue
        
        current_hash = compute_file_hash(filepath)
        if current_hash is None:
            continue
        
        # Initialize hash if not present
        if filepath not in FILE_HASHES:
            FILE_HASHES[filepath] = current_hash
            continue
        
        # Check if hash changed
        if FILE_HASHES[filepath] != current_hash:
            if not alert_exists(conn, "File Integrity Violation", hash(filepath)):
                create_alert(
                    conn,
                    "File Integrity Violation",
                    "critical",
                    f"Hash mismatch for {filepath}. File has been modified!",
                    hash(filepath),
                )
            FILE_HASHES[filepath] = current_hash


# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(conn):
    """Detect new suspicious processes"""
    cur = conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%new process%'
            OR LOWER(message) LIKE '%process spawned%'
            OR LOWER(message) LIKE '%exec%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NEW_PROCESS_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(conn, "Excessive New Processes", newest):
            create_alert(
                conn,
                "Excessive New Processes",
                "medium",
                f"Detected {len(rows)} new processes in short timeframe",
                newest,
            )


# --------------------------
# Privilege Escalation Detection
# --------------------------

def check_privilege_escalation(conn):
    """Detect unauthorized privilege escalation attempts"""
    cur = conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%sudo%'
            OR LOWER(message) LIKE '%privilege escalation%'
            OR LOWER(message) LIKE '%unauthorized privilege%'
            OR LOWER(message) LIKE '%root access%'
            OR LOWER(message) LIKE '%elevated privileges%'
            OR LOWER(message) LIKE '%suid%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(conn, "Privilege Escalation Attempt", newest):
            create_alert(
                conn,
                "Privilege Escalation Attempt",
                "high",
                f"Potential privilege escalation detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Event Escalation Detection
# --------------------------

def check_event_escalation(conn):
    """Detect rapid escalation of high-severity events"""
    cur = conn.cursor()
    
    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE severity='high' OR severity='critical'
        AND timestamp > datetime('now', '-1 minutes')
        """
    )
    
    result = cur.fetchone()
    count = result["count"] if result else 0
    
    if count >= EVENT_ESCALATION_THRESHOLD:
        if not alert_exists(conn, "Event Escalation", count):
            create_alert(
                conn,
                "Event Escalation",
                "critical",
                f"Rapid escalation: {count} high/critical alerts in 1 minute",
                count,
            )


# --------------------------
# Network Activity Detection
# --------------------------

def check_network_anomalies(conn):
    """Detect unusual network activity"""
    cur = conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%network%'
            OR LOWER(message) LIKE '%connection%'
            OR LOWER(message) LIKE '%packet%'
            OR LOWER(message) LIKE '%traffic%'
            OR LOWER(message) LIKE '%socket%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= NETWORK_ACTIVITY_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(conn, "Abnormal Network Activity", newest):
            create_alert(
                conn,
                "Abnormal Network Activity",
                "medium",
                f"High network activity detected: {len(rows)} events in short time",
                newest,
            )


# --------------------------
# File Modification Detection
# --------------------------

def check_file_modifications(conn):
    """Detect excessive file modifications"""
    cur = conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%modify%'
            OR LOWER(message) LIKE '%write%'
            OR LOWER(message) LIKE '%delete%'
            OR LOWER(message) LIKE '%rename%'
            OR LOWER(message) LIKE '%chmod%')
            AND timestamp > datetime('now', '-1 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if len(rows) >= FILE_MOD_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(conn, "Excessive File Modifications", newest):
            create_alert(
                conn,
                "Excessive File Modifications",
                "medium",
                f"Detected {len(rows)} file modification events in short time",
                newest,
            )


# --------------------------
# Suspicious Port Activity
# --------------------------

def check_suspicious_ports(conn):
    """Detect suspicious port opening/closing or SSH changes"""
    cur = conn.cursor()
    
    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE
            (LOWER(message) LIKE '%port%'
            OR LOWER(message) LIKE '%ssh%'
            OR LOWER(message) LIKE '%sshd%'
            OR LOWER(message) LIKE '%listening%'
            OR LOWER(message) LIKE '%bind%')
            AND (LOWER(message) LIKE '%open%'
            OR LOWER(message) LIKE '%close%'
            OR LOWER(message) LIKE '%change%'
            OR LOWER(message) LIKE '%modify%')
            AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )
    
    rows = cur.fetchall()
    
    if rows:
        newest = rows[0]["id"]
        if not alert_exists(conn, "Suspicious Port Activity", newest):
            create_alert(
                conn,
                "Suspicious Port Activity",
                "high",
                f"Suspicious port/SSH activity detected. {len(rows)} event(s)",
                newest,
            )


# --------------------------
# Main Loop
# --------------------------

def main():
    print("Rule engine started")
    print("Running rules:")
    print("  - Brute Force Detection")
    print("  - Database Access Control")
    print("  - Honeypot Access Detection")
    print("  - File Integrity Verification")
    print("  - New Process Detection")
    print("  - Privilege Escalation Detection")
    print("  - Event Escalation Detection")
    print("  - Network Anomaly Detection")
    print("  - File Modification Detection")
    print("  - Suspicious Port Activity Detection")

    while True:
        try:
            conn = connect_db()

            # Run all detection rules
            check_brute_force(conn)
            check_db_permissions(conn)
            check_honeypot_access(conn)
            check_file_integrity(conn)
            check_new_processes(conn)
            check_privilege_escalation(conn)
            check_event_escalation(conn)
            check_network_anomalies(conn)
            check_file_modifications(conn)
            check_suspicious_ports(conn)

            conn.close()

        except Exception as e:
            print(f"[RULE ENGINE ERROR] {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
