import sqlite3
from pathlib import Path

DB_PATH = "logs.db" #change to db file name

def gui_can_access_db():
    try: #connects or creates file if file doesn't exist
        conn = sqlite3.connect(DB_PATH) 
        conn.execute("SELECT 1")  #connection test
        conn.close()
        return True
    except Exception:
        return False


if __name__ == "__main__":
    ok = gui_can_access_db()
    print("DB access:", "Connected" if ok else "Failed Connection")
    print("DB file exists:", Path(DB_PATH).exists())
