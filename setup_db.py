import sqlite3
import os

def initialize_database():
    db_name = "logs.db"

    print(f"Initializing database: {db_name}...")

    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        cursor.execute("PRAGMA foreign_keys = ON;")

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          source TEXT,
          message TEXT
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS processes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          pid INTEGER NOT NULL,
          ppid INTEGER,
          username TEXT,
          command TEXT,
          hash TEXT
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_integrity (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          path TEXT NOT NULL,
          action TEXT NOT NULL,
          old_hash TEXT,
          new_hash TEXT
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_activity (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          local_address TEXT,
          remote_address TEXT,
          pid INTEGER,
          process_name TEXT
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          severity TEXT NOT NULL,
          category TEXT,
          description TEXT NOT NULL,
          related_pid INTEGER,
          related_file TEXT,
          related_network TEXT
        );
        """)

        print("Creating indexes...")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processes_time ON processes(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON file_integrity(path);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_time ON network_activity(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_remote ON network_activity(remote_address);")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_network_dedup ON network_activity(local_address, remote_address, pid);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")

        conn.commit()
        print("Database setup successfully!")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    initialize_database()