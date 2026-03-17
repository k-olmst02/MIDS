#!/usr/bin/env python3
import os
import pwd
import sqlite3
import stat
import time
import json
from datetime import datetime

DB_PATH = "/var/lib/hids_collector/logs.db"
ALERTS_DB_PATH = "/var/lib/hids_collector/alerts.db"
STATE_FILE = "/var/lib/hids_collector/rule_engine_state.json"
CHECK_INTERVAL = 5

# Rule Thresholds
BRUTE_FORCE_THRESHOLD = 5
NEW_PROCESS_THRESHOLD = 10
NETWORK_ACTIVITY_THRESHOLD = 20
FILE_MOD_THRESHOLD = 10
EVENT_ESCALATION_THRESHOLD = 3

# Honeypot Configuration
HONEYPOT_IPS = ["192.168.1.100"]
HONEYPOT_PORTS = [22, 80, 443, 3306]

# Critical System Files
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
]

# Authorized Users
AUTHORIZED_DB_USER = "ec2-user"
EXPECTED_DB_MODE = 0o640

# Suspicious Ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999]


def load_state():
    """Load last processed rowids from state file."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "events": 0,
        "processes": 0,
        "file_integrity": 0,
        "network_activity": 0
    }


def save_state(state):
    """Save last processed rowids to state file."""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[ERROR] Failed to save state: {e}")


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
    print(f"[ALERT] {rule_name}: {description}")


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

def check_brute_force(logs_conn, alerts_conn, state):
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE rowid > ?
        AND (
            LOWER(message) LIKE '%failed%'
            OR LOWER(message) LIKE '%authentication failure%'
            OR LOWER(message) LIKE '%invalid user%'
            OR LOWER(message) LIKE '%failed password%'
        )
        ORDER BY id DESC
        LIMIT 25
        """,
        (state["events"],)
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

    if rows:
        state["events"] = max(state["events"], max(row["id"] for row in rows))


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

def check_honeypot_access(logs_conn, alerts_conn, state):
    """Detect connections to honeypot IPs or ports from network_activity."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid AS event_id, local_address, remote_address, pid, process_name
        FROM network_activity
        WHERE rowid > ?
        ORDER BY rowid DESC
        LIMIT 100
        """,
        (state["network_activity"],)
    )

    rows = cur.fetchall()

    matches = []
    for row in rows:
        local_addr = (row["local_address"] or "").lower()
        remote_addr = (row["remote_address"] or "").lower()

        if any(ip.lower() in local_addr or ip.lower() in remote_addr for ip in HONEYPOT_IPS):
            matches.append(row)
            continue

        if any(local_addr.endswith(f":{p}") or remote_addr.endswith(f":{p}") for p in HONEYPOT_PORTS):
            matches.append(row)

    if matches:
        newest = matches[0]["event_id"]
        if not alert_exists(alerts_conn, "Honeypot Access", newest):
            if not recent_alert_exists(alerts_conn, "Honeypot Access", 30):
                create_alert(
                    alerts_conn,
                    "Honeypot Access",
                    "critical",
                    f"Connection to honeypot detected ({len(matches)} event(s))",
                    newest,
                )

    if rows:
        state["network_activity"] = max(state["network_activity"], max(row["event_id"] for row in rows))

# --------------------------
# File Integrity Detection
# --------------------------

def check_file_integrity(logs_conn, alerts_conn, state):
    """Detect activity on critical files from file_integrity table."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, path, action
        FROM file_integrity
        WHERE rowid > ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (state["file_integrity"],)
    )

    rows = cur.fetchall()

    for row in rows:
        if row["path"] in CRITICAL_FILES:
            newest = row["id"]
            desc = f"Critical file activity detected: {row['action']} on {row['path']}"

            if not alert_exists(alerts_conn, "File Integrity Violation", newest):
                if not recent_alert_exists(alerts_conn, "File Integrity Violation", 30, row["path"]):
                    create_alert(
                        alerts_conn,
                        "File Integrity Violation",
                        "critical",
                        desc,
                        newest,
                    )
            break

    if rows:
        state["file_integrity"] = max(state["file_integrity"], max(row["id"] for row in rows))


# --------------------------
# New Process Detection
# --------------------------

def check_new_processes(logs_conn, alerts_conn, state):
    """Detect bursts of process creation from processes table."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid AS event_id, pid, username, command
        FROM processes
        WHERE rowid > ?
        ORDER BY rowid DESC
        LIMIT 100
        """,
        (state["processes"],)
    )

    rows = cur.fetchall()

    if len(rows) >= NEW_PROCESS_THRESHOLD:
        newest = rows[0]["event_id"]
        if not alert_exists(alerts_conn, "Excessive New Processes", newest):
            if not recent_alert_exists(alerts_conn, "Excessive New Processes", 120):
                create_alert(
                    alerts_conn,
                    "Excessive New Processes",
                    "medium",
                    f"Detected {len(rows)} recent process events",
                    newest,
                )

    if rows:
        state["processes"] = max(state["processes"], max(row["event_id"] for row in rows))


# --------------------------
# Privilege Escalation Detection
# --------------------------

def check_privilege_escalation(logs_conn, alerts_conn, state):
    """
    Detect realistic privilege escalation attempts instead of normal sudo use.
    """
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, message
        FROM events
        WHERE rowid > ?
        AND (
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
        """,
        (state["events"],)
    )

    rows = cur.fetchall()

    if len(rows) >= 3:
        newest = rows[0]["id"]

        if not alert_exists(alerts_conn, "Privilege Escalation Attempt", newest):
            if not recent_alert_exists(alerts_conn, "Privilege Escalation Attempt", 60):
                create_alert(
                    alerts_conn,
                    "Privilege Escalation Attempt",
                    "high",
                    f"Potential privilege escalation detected. {len(rows)} event(s)",
                    newest,
                )

    if rows:
        state["events"] = max(state["events"], max(row["id"] for row in rows))


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

def check_network_anomalies(logs_conn, alerts_conn, state):
    """Detect unusual network activity from network_activity table."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid AS event_id, local_address, remote_address, pid, process_name
        FROM network_activity
        WHERE rowid > ?
        ORDER BY rowid DESC
        LIMIT 100
        """,
        (state["network_activity"],)
    )

    rows = cur.fetchall()

    if len(rows) >= NETWORK_ACTIVITY_THRESHOLD:
        newest = rows[0]["event_id"]
        if not alert_exists(alerts_conn, "Abnormal Network Activity", newest):
            if not recent_alert_exists(alerts_conn, "Abnormal Network Activity", 120):
                create_alert(
                    alerts_conn,
                    "Abnormal Network Activity",
                    "medium",
                    f"High network activity detected: {len(rows)} recent network events",
                    newest,
                )

    if rows:
        state["network_activity"] = max(state["network_activity"], max(row["event_id"] for row in rows))
# --------------------------
# File Modification Detection
# --------------------------

def check_file_modifications(logs_conn, alerts_conn, state):
    """Detect excessive file modifications from file_integrity table."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT id, path, action
        FROM file_integrity
        WHERE rowid > ?
        AND action IN ('write', 'modify', 'delete', 'rename', 'chmod')
        ORDER BY id DESC
        LIMIT 100
        """,
        (state["file_integrity"],)
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

    if rows:
        state["file_integrity"] = max(state["file_integrity"], max(row["id"] for row in rows))


# --------------------------
# Suspicious Port Activity
# --------------------------

def check_suspicious_ports(logs_conn, alerts_conn, state):
    """Detect suspicious connections to high-risk ports from network_activity."""
    cur = logs_conn.cursor()

    cur.execute(
        """
        SELECT rowid AS event_id, local_address, remote_address, pid, process_name
        FROM network_activity
        WHERE rowid > ?
        ORDER BY rowid DESC
        LIMIT 100
        """,
        (state["network_activity"],)
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

    if rows:
        state["network_activity"] = max(state["network_activity"], max(row["event_id"] for row in rows))


# --------------------------
# Main Loop
# --------------------------

def main():
    print("Rule engine started")
    print("Logs database: " + DB_PATH)
    print("Alerts database: " + ALERTS_DB_PATH)
    print("State file: " + STATE_FILE)
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

    state = load_state()

    while True:
        try:
            logs_conn = connect_db()
            alerts_conn = connect_alerts_db()

            check_brute_force(logs_conn, alerts_conn, state)
            check_db_permissions(logs_conn, alerts_conn)
            check_honeypot_access(logs_conn, alerts_conn, state)
            check_file_integrity(logs_conn, alerts_conn, state)
            check_new_processes(logs_conn, alerts_conn, state)
            check_privilege_escalation(logs_conn, alerts_conn, state)
            check_event_escalation(logs_conn, alerts_conn)
            check_network_anomalies(logs_conn, alerts_conn, state)
            check_file_modifications(logs_conn, alerts_conn, state)
            check_suspicious_ports(logs_conn, alerts_conn, state)

            logs_conn.close()
            alerts_conn.close()

            save_state(state)

        except Exception as e:
            print(f"[RULE ENGINE ERROR] {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
