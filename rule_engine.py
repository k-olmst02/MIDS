#!/usr/bin/env python3
import os
import pwd
import sqlite3
import stat
import time
import hashlib
from datetime import datetime

DB_PATH = "/var/lib/hids_collector/logs.db"
ALERTS_DB_PATH = "/var/lib/hids_collector/alerts.db"
CHECK_INTERVAL = 5

# Rule Thresholds
BRUTE_FORCE_THRESHOLD = 5
NEW_PROCESS_THRESHOLD = 10
NETWORK_ACTIVITY_THRESHOLD = 50
FILE_MOD_THRESHOLD = 20
EVENT_ESCALATION_THRESHOLD = 3

# Honeypot Configuration
HONEYPOT_IPS = ["192.168.1.100"]
HONEYPOT_PORTS = [22, 80, 443, 3306]

# Critical System Files for Hash Checking
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
]

# Baseline hash storage
FILE_HASHES = {}

# Authorized Users
AUTHORIZED_DB_USER = "ec2-user"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def connect_db():
    """Connect to the logs database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def connect_alerts_db():
    """Connect to the separate alerts database."""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    create_alerts_table(conn)
    return conn


def create_alerts_table(conn):
    """Create alerts table if it doesn't exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            event_ref INTEGER
        )
        """
    )
    conn.commit()


def create_alert(alerts_conn, rule_name, severity, description, event_ref=None):
    """Insert a new alert."""
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
    """Check if exact event_ref alert already exists."""
    if event_ref is None:
        return False

    cur = alerts_conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM alerts
        WHERE rule_name = ? AND event_ref = ?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


def recent_alert_exists(alerts_conn, rule_name, seconds=60, description_contains=None):
    """Return True if a similar alert was created recently."""
    cur = alerts_conn.cursor()

    if description_contains:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND description LIKE ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"%{description_contains}%", f"-{seconds} seconds"),
        )
    else:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"-{seconds} seconds"),
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
            if not recent_alert_exists(alerts_conn, "Brute Force Login", 120):
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
        if not recent_alert_exists(alerts_conn, "Database Integrity", 10):
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
        desc = f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}"
        if not recent_alert_exists(alerts_conn, "Database Access Control", 10, owner):
            create_alert(
                alerts_conn,
                "Database Access Control",
                "high",
                desc,
            )

    if mode != EXPECTED_DB_MODE:
        desc = f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}"
        if not recent_alert_exists(alerts_conn, "Database Permission Error", 10, oct(mode)):
            create_alert(
                alerts_conn,
                "Database Permission Error",
                "high",
                desc,
            )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(logs_conn, alerts_conn):
    """Detect any connections to honeypot IPs."""
    cur = logs_conn.cursor()

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
            if not recent_alert_exists(alerts_conn, "Honeypot Access", 10):
                create_alert(
                    alerts_conn,
                    "Honeypot Access",
                    "critical",
                    f"Connection to honeypot detected. {len(rows)} event(s) detected",
                    newest,
                )


# --------------------------
# File Hash Verification
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def check_file_integrity(logs_conn, alerts_conn):
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, path, action
        FROM file_integrity
        WHERE path IN (
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/root/.ssh/authorized_keys'
        )
        ORDER BY id DESC
        LIMIT 10
        """
    )

    rows = cur.fetchall()

    if rows:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "File Integrity Violation", newest):
            create_alert(
                alerts_conn,
                "File Integrity Violation",
                "critical",
                f"{rows[0]['action']} detected on {rows[0]['path']}",
                newest,
            )
# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn):
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid AS event_id, command
        FROM processes
        ORDER BY rowid DESC
        LIMIT 50
        """
    )

    rows = cur.fetchall()

    if len(rows) >= NEW_PROCESS_THRESHOLD:
        newest = rows[0]["event_id"]

        if not alert_exists(alerts_conn, "Excessive New Processes", newest):
            create_alert(
                alerts_conn,
                "Excessive New Processes",
                "medium",
                f"{len(rows)} processes created recently",
                newest,
            )


    if len(rows) >= NEW_PROCESS_THRESHOLD:
        newest = rows[0]["id"]
        if not alert_exists(alerts_conn, "Excessive New Processes", newest):
            if not recent_alert_exists(alerts_conn, "Excessive New Processes", 120):
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
    """
    Detect realistic privilege escalation attempts instead of normal sudo use.
    """
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE (
            LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%failed password%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%user not in sudoers%'
            OR LOWER(message) LIKE '%incorrect password%'
            OR LOWER(message) LIKE '%permission denied%'
            OR LOWER(message) LIKE '%pam_unix(sudo:auth)%'
            OR LOWER(message) LIKE '%sudo:%'
        )
        AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    if len(rows) >= 3:
        newest = rows[0][0]

        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            if not recent_alert_exists(alerts_conn, "Privilege Escalation Attempt", 60):
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
    """Detect rapid escalation of high-severity events without self-spamming."""
    cur = alerts_conn.cursor()

    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE (severity='high' OR severity='critical')
          AND rule_name != 'Event Escalation'
          AND timestamp >= datetime('now', '-1 minutes')
        """
    )

    result = cur.fetchone()
    count = result["count"] if result else 0

    if count >= EVENT_ESCALATION_THRESHOLD:
        if not recent_alert_exists(alerts_conn, "Event Escalation", 10):
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
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid AS event_id
        FROM network_activity
        ORDER BY rowid DESC
        LIMIT 100
        """
    )

    rows = cur.fetchall()

    if len(rows) >= NETWORK_ACTIVITY_THRESHOLD:
        newest = rows[0]["event_id"]

        if not alert_exists(alerts_conn, "Abnormal Network Activity", newest):
            create_alert(
                alerts_conn,
                "Abnormal Network Activity",
                "medium",
                f"{len(rows)} network events detected",
                newest,
            )


# --------------------------
# File Modification Detection
# --------------------------

def check_file_modifications(logs_conn, alerts_conn):
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id
        FROM file_integrity
        WHERE action IN ('write', 'unlink', 'rename', 'chmod')
        ORDER BY id DESC
        LIMIT 100
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
                f"{len(rows)} file modifications detected",
                newest,
            )


# --------------------------
# Suspicious Port Activity
# --------------------------

def check_suspicious_ports(logs_conn, alerts_conn):
    """Detect suspicious connections to high-risk ports."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid, dest_port, dest_ip
        FROM network_activity
        WHERE dest_port IN (4444, 5555, 6666, 8888, 9999)
        ORDER BY rowid DESC
        LIMIT 10
        """
    )

    rows = cur.fetchall()

    if rows:
        newest = rows[0]["rowid"]

        if not alert_exists(alerts_conn, "Suspicious Port Activity", newest):
            if not recent_alert_exists(alerts_conn, "Suspicious Port Activity", 30):
                create_alert(
                    alerts_conn,
                    "Suspicious Port Activity",
                    "high",
                    f"Connection detected on suspicious port {rows[0]['dest_port']}",
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
    main()
AUTHORIZED_DB_USER = "ec2-user"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def connect_db():
    """Connect to the logs database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def connect_alerts_db():
    """Connect to the separate alerts database."""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    create_alerts_table(conn)
    return conn


def create_alerts_table(conn):
    """Create alerts table if it doesn't exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            event_ref INTEGER
        )
        """
    )
    conn.commit()


def create_alert(alerts_conn, rule_name, severity, description, event_ref=None):
    """Insert a new alert."""
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
    """Check if exact event_ref alert already exists."""
    if event_ref is None:
        return False

    cur = alerts_conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM alerts
        WHERE rule_name = ? AND event_ref = ?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


def recent_alert_exists(alerts_conn, rule_name, seconds=60, description_contains=None):
    """Return True if a similar alert was created recently."""
    cur = alerts_conn.cursor()

    if description_contains:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND description LIKE ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"%{description_contains}%", f"-{seconds} seconds"),
        )
    else:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"-{seconds} seconds"),
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
            if not recent_alert_exists(alerts_conn, "Brute Force Login", 120):
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
        if not recent_alert_exists(alerts_conn, "Database Integrity", 10):
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
        desc = f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}"
        if not recent_alert_exists(alerts_conn, "Database Access Control", 10, owner):
            create_alert(
                alerts_conn,
                "Database Access Control",
                "high",
                desc,
            )

    if mode != EXPECTED_DB_MODE:
        desc = f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}"
        if not recent_alert_exists(alerts_conn, "Database Permission Error", 10, oct(mode)):
            create_alert(
                alerts_conn,
                "Database Permission Error",
                "high",
                desc,
            )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(logs_conn, alerts_conn):
    """Detect any connections to honeypot IPs."""
    cur = logs_conn.cursor()

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
            if not recent_alert_exists(alerts_conn, "Honeypot Access", 10):
                create_alert(
                    alerts_conn,
                    "Honeypot Access",
                    "critical",
                    f"Connection to honeypot detected. {len(rows)} event(s) detected",
                    newest,
                )


# --------------------------
# File Hash Verification
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def check_file_integrity(logs_conn, alerts_conn):
    """Detect modifications to critical system files using logged events."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE (
            LOWER(message) LIKE '%/etc/passwd%'
            OR LOWER(message) LIKE '%/etc/shadow%'
            OR LOWER(message) LIKE '%/etc/sudoers%'
            OR LOWER(message) LIKE '%/etc/ssh/sshd_config%'
            OR LOWER(message) LIKE '%authorized_keys%'
        )
        AND (
            LOWER(message) LIKE '%write%'
            OR LOWER(message) LIKE '%modify%'
            OR LOWER(message) LIKE '%chmod%'
            OR LOWER(message) LIKE '%delete%'
            OR LOWER(message) LIKE '%rename%'
        )
        AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    if rows:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "File Integrity Violation", newest):
            if not recent_alert_exists(alerts_conn, "File Integrity Violation", 10):
                create_alert(
                    alerts_conn,
                    "File Integrity Violation",
                    "critical",
                    f"Modification detected on critical system file ({len(rows)} events)",
                    newest,
                )

# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn):
    """Detect new suspicious processes."""
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
            if not recent_alert_exists(alerts_conn, "Excessive New Processes", 120):
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
    """
    Detect realistic privilege escalation attempts instead of normal sudo use.
    """
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE (
            LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%failed password%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%user not in sudoers%'
            OR LOWER(message) LIKE '%incorrect password%'
            OR LOWER(message) LIKE '%permission denied%'
            OR LOWER(message) LIKE '%pam_unix(sudo:auth)%'
            OR LOWER(message) LIKE '%sudo:%'
        )
        AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    if len(rows) >= 3:
        newest = rows[0][0]

        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            if not recent_alert_exists(alerts_conn, "Privilege Escalation Attempt", 60):
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
    """Detect rapid escalation of high-severity events without self-spamming."""
    cur = alerts_conn.cursor()

    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE (severity='high' OR severity='critical')
          AND rule_name != 'Event Escalation'
          AND timestamp >= datetime('now', '-1 minutes')
        """
    )

    result = cur.fetchone()
    count = result["count"] if result else 0

    if count >= EVENT_ESCALATION_THRESHOLD:
        if not recent_alert_exists(alerts_conn, "Event Escalation", 10):
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
    """Detect unusual network activity."""
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
            if not recent_alert_exists(alerts_conn, "Abnormal Network Activity", 120):
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
    """Detect excessive file modifications."""
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
            if not recent_alert_exists(alerts_conn, "Excessive File Modifications", 120):
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
    """Detect suspicious connections to high-risk ports."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid, dest_port, dest_ip
        FROM network_activity
        WHERE dest_port IN (4444, 5555, 6666, 8888, 9999)
        ORDER BY rowid DESC
        LIMIT 10
        """
    )

    rows = cur.fetchall()

    if rows:
        newest = rows[0]["rowid"]

        if not alert_exists(alerts_conn, "Suspicious Port Activity", newest):
            if not recent_alert_exists(alerts_conn, "Suspicious Port Activity", 30):
                create_alert(
                    alerts_conn,
                    "Suspicious Port Activity",
                    "high",
                    f"Connection detected on suspicious port {rows[0]['dest_port']}",
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
    """Connect to the logs database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def connect_alerts_db():
    """Connect to the separate alerts database."""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    create_alerts_table(conn)
    return conn


def create_alerts_table(conn):
    """Create alerts table if it doesn't exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            event_ref INTEGER
        )
        """
    )
    conn.commit()


def create_alert(alerts_conn, rule_name, severity, description, event_ref=None):
    """Insert a new alert."""
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
    """Check if exact event_ref alert already exists."""
    if event_ref is None:
        return False

    cur = alerts_conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM alerts
        WHERE rule_name = ? AND event_ref = ?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


def recent_alert_exists(alerts_conn, rule_name, seconds=60, description_contains=None):
    """Return True if a similar alert was created recently."""
    cur = alerts_conn.cursor()

    if description_contains:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND description LIKE ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"%{description_contains}%", f"-{seconds} seconds"),
        )
    else:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"-{seconds} seconds"),
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
            if not recent_alert_exists(alerts_conn, "Brute Force Login", 120):
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
        if not recent_alert_exists(alerts_conn, "Database Integrity", 10):
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
        desc = f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}"
        if not recent_alert_exists(alerts_conn, "Database Access Control", 10, owner):
            create_alert(
                alerts_conn,
                "Database Access Control",
                "high",
                desc,
            )

    if mode != EXPECTED_DB_MODE:
        desc = f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}"
        if not recent_alert_exists(alerts_conn, "Database Permission Error", 10, oct(mode)):
            create_alert(
                alerts_conn,
                "Database Permission Error",
                "high",
                desc,
            )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(logs_conn, alerts_conn):
    """Detect any connections to honeypot IPs."""
    cur = logs_conn.cursor()

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
            if not recent_alert_exists(alerts_conn, "Honeypot Access", 10):
                create_alert(
                    alerts_conn,
                    "Honeypot Access",
                    "critical",
                    f"Connection to honeypot detected. {len(rows)} event(s) detected",
                    newest,
                )


# --------------------------
# File Hash Verification
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def check_file_integrity(logs_conn, alerts_conn):
    """Detect modifications to critical system files using logged events."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE (
            LOWER(message) LIKE '%/etc/passwd%'
            OR LOWER(message) LIKE '%/etc/shadow%'
            OR LOWER(message) LIKE '%/etc/sudoers%'
            OR LOWER(message) LIKE '%/etc/ssh/sshd_config%'
            OR LOWER(message) LIKE '%authorized_keys%'
        )
        AND (
            LOWER(message) LIKE '%write%'
            OR LOWER(message) LIKE '%modify%'
            OR LOWER(message) LIKE '%chmod%'
            OR LOWER(message) LIKE '%delete%'
            OR LOWER(message) LIKE '%rename%'
        )
        AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    if rows:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "File Integrity Violation", newest):
            if not recent_alert_exists(alerts_conn, "File Integrity Violation", 10):
                create_alert(
                    alerts_conn,
                    "File Integrity Violation",
                    "critical",
                    f"Modification detected on critical system file ({len(rows)} events)",
                    newest,
                )

# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn):
    """Detect new suspicious processes."""
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
            if not recent_alert_exists(alerts_conn, "Excessive New Processes", 120):
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
    """
    Detect realistic privilege escalation attempts instead of normal sudo use.
    """
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE (
            LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%failed password%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%user not in sudoers%'
            OR LOWER(message) LIKE '%incorrect password%'
            OR LOWER(message) LIKE '%permission denied%'
            OR LOWER(message) LIKE '%pam_unix(sudo:auth)%'
            OR LOWER(message) LIKE '%sudo:%'
        )
        AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    if len(rows) >= 3:
        newest = rows[0][0]

        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            if not recent_alert_exists(alerts_conn, "Privilege Escalation Attempt", 60):
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
    """Detect rapid escalation of high-severity events without self-spamming."""
    cur = alerts_conn.cursor()

    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE (severity='high' OR severity='critical')
          AND rule_name != 'Event Escalation'
          AND timestamp >= datetime('now', '-1 minutes')
        """
    )

    result = cur.fetchone()
    count = result["count"] if result else 0

    if count >= EVENT_ESCALATION_THRESHOLD:
        if not recent_alert_exists(alerts_conn, "Event Escalation", 10):
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
    """Detect unusual network activity."""
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
            if not recent_alert_exists(alerts_conn, "Abnormal Network Activity", 120):
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
    """Detect excessive file modifications."""
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
            if not recent_alert_exists(alerts_conn, "Excessive File Modifications", 120):
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
    """Detect suspicious connections to high-risk ports."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid AS event_id, local_address, remote_address, pid, process_name
        FROM network_activity
        ORDER BY rowid DESC
        LIMIT 100
        """
    )

    rows = cur.fetchall()

    matches = []
    for row in rows:
        local_addr = (row["local_address"] or "").lower()
        remote_addr = (row["remote_address"] or "").lower()

        for port in SUSPICIOUS_PORTS:
            if local_addr.endswith(f":{port}") or remote_addr.endswith(f":{port}"):
                matches.append((row, port))
                break

    if matches:
        newest = matches[0][0]["event_id"]
        port = matches[0][1]

        if not alert_exists(alerts_conn, "Suspicious Port Activity", newest):
            if not recent_alert_exists(alerts_conn, "Suspicious Port Activity", 30):
                create_alert(
                    alerts_conn,
                    "Suspicious Port Activity",
                    "high",
                    f"Connection detected on suspicious port {port}",
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
    main()
AUTHORIZED_DB_USER = "ec2-user"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def connect_db():
    """Connect to the logs database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def connect_alerts_db():
    """Connect to the separate alerts database."""
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    create_alerts_table(conn)
    return conn


def create_alerts_table(conn):
    """Create alerts table if it doesn't exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            event_ref INTEGER
        )
        """
    )
    conn.commit()


def create_alert(alerts_conn, rule_name, severity, description, event_ref=None):
    """Insert a new alert."""
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
    """Check if exact event_ref alert already exists."""
    if event_ref is None:
        return False

    cur = alerts_conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM alerts
        WHERE rule_name = ? AND event_ref = ?
        LIMIT 1
        """,
        (rule_name, event_ref),
    )
    return cur.fetchone() is not None


def recent_alert_exists(alerts_conn, rule_name, seconds=60, description_contains=None):
    """Return True if a similar alert was created recently."""
    cur = alerts_conn.cursor()

    if description_contains:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND description LIKE ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"%{description_contains}%", f"-{seconds} seconds"),
        )
    else:
        cur.execute(
            """
            SELECT 1
            FROM alerts
            WHERE rule_name = ?
              AND timestamp >= datetime('now', ?)
            LIMIT 1
            """,
            (rule_name, f"-{seconds} seconds"),
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
            if not recent_alert_exists(alerts_conn, "Brute Force Login", 120):
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
        if not recent_alert_exists(alerts_conn, "Database Integrity", 10):
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
        desc = f"Database owned by {owner}, expected {AUTHORIZED_DB_USER}"
        if not recent_alert_exists(alerts_conn, "Database Access Control", 10, owner):
            create_alert(
                alerts_conn,
                "Database Access Control",
                "high",
                desc,
            )

    if mode != EXPECTED_DB_MODE:
        desc = f"Database permissions {oct(mode)} expected {oct(EXPECTED_DB_MODE)}"
        if not recent_alert_exists(alerts_conn, "Database Permission Error", 10, oct(mode)):
            create_alert(
                alerts_conn,
                "Database Permission Error",
                "high",
                desc,
            )


# --------------------------
# Honeypot Connection Detection
# --------------------------

def check_honeypot_access(logs_conn, alerts_conn):
    """Detect any connections to honeypot IPs."""
    cur = logs_conn.cursor()

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
            if not recent_alert_exists(alerts_conn, "Honeypot Access", 10):
                create_alert(
                    alerts_conn,
                    "Honeypot Access",
                    "critical",
                    f"Connection to honeypot detected. {len(rows)} event(s) detected",
                    newest,
                )


# --------------------------
# File Hash Verification
# --------------------------

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def check_file_integrity(logs_conn, alerts_conn):
    """Detect modifications to critical system files using logged events."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE (
            LOWER(message) LIKE '%/etc/passwd%'
            OR LOWER(message) LIKE '%/etc/shadow%'
            OR LOWER(message) LIKE '%/etc/sudoers%'
            OR LOWER(message) LIKE '%/etc/ssh/sshd_config%'
            OR LOWER(message) LIKE '%authorized_keys%'
        )
        AND (
            LOWER(message) LIKE '%write%'
            OR LOWER(message) LIKE '%modify%'
            OR LOWER(message) LIKE '%chmod%'
            OR LOWER(message) LIKE '%delete%'
            OR LOWER(message) LIKE '%rename%'
        )
        AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    if rows:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "File Integrity Violation", newest):
            if not recent_alert_exists(alerts_conn, "File Integrity Violation", 10):
                create_alert(
                    alerts_conn,
                    "File Integrity Violation",
                    "critical",
                    f"Modification detected on critical system file ({len(rows)} events)",
                    newest,
                )

# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn):
    """Detect new suspicious processes."""
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
            if not recent_alert_exists(alerts_conn, "Excessive New Processes", 120):
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
    """
    Detect realistic privilege escalation attempts instead of normal sudo use.
    """
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE (
            LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%failed password%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%user not in sudoers%'
            OR LOWER(message) LIKE '%incorrect password%'
            OR LOWER(message) LIKE '%permission denied%'
            OR LOWER(message) LIKE '%pam_unix(sudo:auth)%'
            OR LOWER(message) LIKE '%sudo:%'
        )
        AND timestamp > datetime('now', '-5 minutes')
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()

    if len(rows) >= 3:
        newest = rows[0][0]

        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            if not recent_alert_exists(alerts_conn, "Privilege Escalation Attempt", 60):
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
    """Detect rapid escalation of high-severity events without self-spamming."""
    cur = alerts_conn.cursor()

    cur.execute(
        """
        SELECT COUNT(*) as count
        FROM alerts
        WHERE (severity='high' OR severity='critical')
          AND rule_name != 'Event Escalation'
          AND timestamp >= datetime('now', '-1 minutes')
        """
    )

    result = cur.fetchone()
    count = result["count"] if result else 0

    if count >= EVENT_ESCALATION_THRESHOLD:
        if not recent_alert_exists(alerts_conn, "Event Escalation", 10):
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
    """Detect unusual network activity."""
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
            if not recent_alert_exists(alerts_conn, "Abnormal Network Activity", 120):
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
    """Detect excessive file modifications."""
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
            if not recent_alert_exists(alerts_conn, "Excessive File Modifications", 120):
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
    """Detect suspicious connections to high-risk ports."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid, dest_port, dest_ip
        FROM network_activity
        WHERE dest_port IN (4444, 5555, 6666, 8888, 9999)
        ORDER BY rowid DESC
        LIMIT 10
        """
    )

    rows = cur.fetchall()

    if rows:
        newest = rows[0]["rowid"]

        if not alert_exists(alerts_conn, "Suspicious Port Activity", newest):
            if not recent_alert_exists(alerts_conn, "Suspicious Port Activity", 30):
                create_alert(
                    alerts_conn,
                    "Suspicious Port Activity",
                    "high",
                    f"Connection detected on suspicious port {rows[0]['dest_port']}",
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
    main()
