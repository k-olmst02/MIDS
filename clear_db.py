import sqlite3
import os

LOGS_DB = "logs.db"
ALERTS_DB = "alerts.db"

def clear_database(db_path, table_name):
    if not os.path.exists(db_path):
        print(f"File not found: {db_path}")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        print(f"Clearing table '{table_name}' in {os.path.basename(db_path)}...")
        cursor.execute(f"DELETE FROM {table_name};")

        print(f"Vacuuming {os.path.basename(db_path)}...")
        cursor.execute("VACUUM;")

        conn.commit()
        conn.close()
        print(f"Successfully cleared {os.path.basename(db_path)}.\n")

    except sqlite3.Error as e:
        print(f"SQLite error in {db_path}: {e}")

if __name__ == "__main__":
    clear_database(LOGS_DB, "events")
    clear_database(ALERTS_DB, "alerts")