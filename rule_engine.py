#!/usr/bin/env python3
import os
import pwd
import sqlite3
import stat
import time
from datetime import datetime

DB_PATH = "/var/lib/hids_collector/logs.db"
CHECK_INTERVAL = 5

BRUTE_FORCE_THRESHOLD = 5
AUTHORIZED_DB_USER = "c0nn13"
EXPECTED_DB_MODE = 0o640


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
# Main Loop
# --------------------------

def main():
    print("Rule engine started")

    while True:
        try:
            conn = connect_db()

            check_brute_force(conn)
            check_db_permissions(conn)

            conn.close()

        except Exception as e:
            print(f"[RULE ENGINE ERROR] {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()