import socket
import sqlite3

DB_PATH = "mids.db"

HOST = "0.0.0.0"
PORT = 22


def get_db():
    return sqlite3.connect(DB_PATH)


def log_event(source_ip, source_port, raw_data=""):
    conn = get_db()
    cursor = conn.cursor()

    # Insert honeypot event
    cursor.execute("""
        INSERT INTO honeypot_events
        (source_ip, source_port, destination_port, protocol, raw_data)
        VALUES (?, ?, ?, 'TCP', ?)
    """, (source_ip, source_port, PORT, raw_data))

    event_id = cursor.lastrowid

    # Create alert
    cursor.execute("""
        INSERT INTO alerts
        (event_id, alert_type, severity, message)
        VALUES (?, ?, ?, ?)
    """, (
        event_id,
        "SSH Honeypot Connection",
        "high",
        f"SSH honeypot connection attempt from {source_ip}:{source_port}"
    ))

    conn.commit()
    conn.close()


def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[INFO] SSH Honeypot listening on port {PORT}")

    while True:
        client, addr = server.accept()

        source_ip, source_port = addr
        raw_data = ""

        try:
            # Send fake SSH banner
            client.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")

            data = client.recv(1024)
            if data:
                raw_data = data.decode(errors="ignore")

        except Exception as e:
            raw_data = str(e)

        finally:
            log_event(source_ip, source_port, raw_data)
            client.close()


if __name__ == "__main__":
    start_honeypot()
