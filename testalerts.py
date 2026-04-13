import sqlite3

conn = sqlite3.connect("logs.db")
cursor = conn.cursor()

# 1. Simulate a Brute Force (Multiple failed logins or events)
for i in range(10):
    cursor.execute("""
        INSERT INTO events (event_type, severity, source, message) 
        VALUES ('USER_LOGIN', 'high', 'auditd', 'res=failed user=root')
    """)

# 2. Simulate Critical File Access
cursor.execute("""
    INSERT INTO file_integrity (path, action) 
    VALUES ('/etc/shadow', 'write')
""")

# 3. Simulate Honeypot Network Activity
cursor.execute("""
    INSERT INTO network_activity (remote_address, pid, process_name) 
    VALUES ('192.168.1.100', 9999, 'ncat')
""")

conn.commit()
conn.close()
print("Test data injected into logs.db")