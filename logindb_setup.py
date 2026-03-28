import sqlite3, hashlib

def database_setup():
    connect = sqlite3.connect("logininfo.db")
    cursor = connect.cursor()
    
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS logininfo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL)"""
    )
    
    #Admin user for our demonstration
    username = "admin"
    password = "mids123"
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        cursor.execute("INSERT INTO logininfo (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        connect.commit()
        print("Inserted admin user into database")
    except sqlite3.IntegrityError:
        print("User already exists")
        
    connect.close()
    
__name__ == "__main__"
database_setup()
    