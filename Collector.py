#!/usr/bin/env python3
import io
import json
import logging
import os
import getpass
try:
    import pwd
    current_user = pwd.getpwuid(os.getuid()).pw_name
except ImportError:
    current_user = getpass.getuser()
import re
import sqlite3
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if os.name == 'nt':
    STATE_DIR = "."
    AUDIT_LOG = "auditlogs/audit.log"
else:
    AUDIT_LOG = "/var/log/audit/audit.log"
    STATE_DIR = os.path.join(BASE_DIR, "hids_collector")

OFFSET_FILE = os.path.join(STATE_DIR, "audit.offset")
DB_PATH = os.path.join(BASE_DIR, "logs.db")
SLEEP, WAIT, FILE_WIN, PROC_WIN = 1.0, 1.5, 30, 10
MAX_LINES_PER_CYCLE = 1000
O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND = 1, 2, 64, 512, 1024

TYPE_RE = re.compile(r"^type=([A-Z_]+)\s")
MSG_RE = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\):")
KV_RE = re.compile(r'(\w+)=("([^"\\]|\\.)*"|\S+)')
SYSCALL_NAME = {"59": "execve", "2": "open", "257": "open", "1": "write", "87": "unlink", "263": "unlink",
                "82": "rename", "264": "rename", "90": "chmod", "268": "chmod", "42": "connect",
                "43": "accept", "49": "bind", "288": "accept"}
FILE_ACTIONS, NET_ACTIONS = {"open", "write", "unlink", "rename", "chmod"}, {"connect", "accept", "bind"}
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


#Parse key values
def get_kv(line):
    out = {}
    for k, v, _ in KV_RE.findall(line):
        out[k] = v[1:-1] if v.startswith('"') and v.endswith('"') else v
    return out


#Parse audit header
def get_head(line):
    tm, mm = TYPE_RE.search(line), MSG_RE.search(line)
    typ = tm.group(1) if tm else "UNKNOWN"
    return (typ, None, None) if not mm else (typ, float(mm.group(1)), int(mm.group(2)))


#Map syscall name
def get_sys(raw):
    return "" if not raw else (SYSCALL_NAME.get(raw, raw) if raw.isdigit() else raw.lower())


#Map uid user
def get_user(uid):
    try:
        return "" if uid in (None, "") else pwd.getpwuid(int(uid)).pw_name
    except Exception:
        return str(uid)


#Decode socket address
def get_addr(hex_s):
    if not hex_s:
        return ""
    try:
        data = bytes.fromhex("".join(c for c in hex_s if c in "0123456789abcdefABCDEF"))
    except Exception:
        return hex_s
    if len(data) < 8:
        return hex_s
    fam = data[0] | (data[1] << 8)
    if fam == 2 and len(data) >= 8:
        return f"{'.'.join(str(x) for x in data[4:8])}:{(data[2] << 8) | data[3]}"
    return hex_s


def parse_int(value):
    if value in (None, ""):
        return None
    try:
        return int(str(value), 0)
    except Exception:
        return None


def normalize_file_action(syscall_name, flags):
    if syscall_name != "open":
        return syscall_name
    if flags is None:
        return syscall_name
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND):
        return "write"
    return syscall_name


class Collector:
    #Setup collector state
    def __init__(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        self.conn = self.open_db()
        self.my_pid = str(os.getpid())
        self.off = 0
        self.ino = 0
        self.fp = None
        self.buf = {}
        self.file_seen = {}
        self.proc_seen = {}
        self.last_save = 0.0
        try:
            with io.open(OFFSET_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                self.off = int(d.get("offset", 0))
                self.ino = int(d.get("inode", 0))
        except Exception:
            pass

    #Open database connection
    def open_db(self):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        self.ensure_schema(conn)
        return conn

    #Ensure required tables and indexes exist
    def ensure_schema(self, conn):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              event_type TEXT NOT NULL,
              severity TEXT NOT NULL,
              source TEXT,
              message TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS processes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              pid INTEGER NOT NULL,
              ppid INTEGER,
              username TEXT,
              command TEXT,
              hash TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_integrity (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              path TEXT NOT NULL,
              action TEXT NOT NULL,
              old_hash TEXT,
              new_hash TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS network_activity (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              local_address TEXT,
              remote_address TEXT,
              pid INTEGER,
              process_name TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_processes_time ON processes(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_file_time ON file_integrity(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_net_time ON network_activity(timestamp);")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_network_dedup ON network_activity(local_address, remote_address, pid);")
        conn.commit()

    #Save read offset
    def save_off(self, force=False):
        now = time.time()
        if not force and now - self.last_save < 2:
            return
        with io.open(OFFSET_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump({"offset": self.off, "inode": self.ino, "ts": now}, f)
        os.replace(OFFSET_FILE + ".tmp", OFFSET_FILE)
        self.last_save = now

    #Open audit log
    def open_log(self):
        try:
            st = os.stat(AUDIT_LOG)
        except PermissionError as e:
            logging.error("permission denied reading audit log %s (%s)", AUDIT_LOG, e)
            return False
        except FileNotFoundError:
            return False
        rot = self.ino and st.st_ino != self.ino
        shr = self.off > st.st_size
        if self.fp is None or rot or shr:
            if self.fp:
                self.fp.close()
            try:
                self.fp = io.open(AUDIT_LOG, "r", encoding="utf-8", errors="replace")
            except PermissionError as e:
                logging.error("permission denied opening audit log %s (%s)", AUDIT_LOG, e)
                self.fp = None
                return False
            self.ino = st.st_ino
            if rot or shr:
                self.off = 0
            self.fp.seek(self.off)
            if self.off == 0:
                self.fp.seek(0, 2)
                self.off = self.fp.tell()
            logging.info("audit open inode=%s off=%s", self.ino, self.off)
            self.save_off(True)
        return True

    #Store process row
    def put_proc(self, ev):
        cmd = ev.get("cmdline", "").strip() or ev.get("exe", "") or ev.get("comm", "")
        pid = int(ev.get("pid") or 0)
        key = (pid, cmd)
        now = time.time()
        if now - self.proc_seen.get(key, 0) < PROC_WIN:
            return
        self.proc_seen[key] = now
        ppid = int(ev.get("ppid") or 0) if ev.get("ppid") else None
        user = get_user(ev.get("uid"))
        cmd_hash = str(abs(hash(cmd)))
        self.conn.execute(
            "INSERT INTO processes(pid, ppid, username, command, hash) VALUES (?, ?, ?, ?, ?)",
            (pid, ppid, user, cmd, cmd_hash),
        )

    #Store file row
    def put_file(self, ev):
        act = ev.get("syscall", "")
        now = time.time()
        for path in ev.get("paths", []):
            key = (path, act)
            if now - self.file_seen.get(key, 0) < FILE_WIN:
                continue
            self.file_seen[key] = now
            self.conn.execute(
                "INSERT INTO file_integrity(path, action, old_hash, new_hash) VALUES (?, ?, ?, ?)",
                (path, act, None, None),
            )

    #Store network row
    def put_net(self, ev):
        act = ev.get("syscall", "")
        pid = int(ev.get("pid") or 0)
        pname = ev.get("comm", "") or ev.get("exe", "")
        for addr in ev.get("sockaddrs", []):
            laddr, raddr = (addr, "") if act == "bind" else ("", addr)
            self.conn.execute(
                "INSERT OR IGNORE INTO network_activity(local_address, remote_address, pid, process_name) VALUES (?, ?, ?, ?)",
                (laddr, raddr, pid, pname),
            )

    #Store generic row
    def put_evt(self, typ, msg):
        self.conn.execute(
            "INSERT INTO events(event_type, severity, source, message) VALUES (?, 'info', 'auditd', ?)",
            (typ, msg[:4000])
        )

    #Route grouped event
    def flush_ev(self, ev):
        types = ev.get("types", set())
        sc = ev.get("syscall", "")
        done = False
        if "EXECVE" in types or sc == "execve":
            self.put_proc(ev)
            done = True
        if sc in FILE_ACTIONS and ev.get("paths"):
            self.put_file(ev)
            done = True
        if sc in NET_ACTIONS and ev.get("sockaddrs"):
            self.put_net(ev)
            done = True
        if not done:
            self.put_evt(",".join(sorted(types)) or "UNKNOWN", "".join(ev.get("raw", [])))

    #Process audit line
    def add_line(self, line):
        typ, _ts, serial = get_head(line)
        if f"pid={self.my_pid}" in line:
            return
        if typ in ["PROCTITLE", "CWD", "AVC"] or "syscall=0" in line or "syscall=89" in line:
            return
        if serial is None:
            self.put_evt(typ, line)
            return
        ev = self.buf.get(serial)
        if ev is None:
            ev = {"raw": [], "types": set(), "last": time.time(), "paths": [], "sockaddrs": []}
            self.buf[serial] = ev
        ev["last"] = time.time()
        ev["types"].add(typ)
        ev["raw"].append(line)
        kv = get_kv(line)
        if typ == "SYSCALL":
            raw_syscall = get_sys(kv.get("syscall", ""))
            flag_arg = kv.get("a1", "") if raw_syscall == "open" else kv.get("a2", "")
            ev["syscall"], ev["pid"], ev["ppid"], ev["uid"], ev["exe"], ev["comm"] = (
                normalize_file_action(raw_syscall, parse_int(flag_arg)), kv.get("pid", ""), kv.get("ppid", ""),
                kv.get("uid", ""), kv.get("exe", ""), kv.get("comm", "")
            )
        elif typ == "EXECVE":
            argc = int(kv.get("argc", "0") or "0")
            ev["cmdline"] = " ".join(kv.get(f"a{i}", "") for i in range(argc) if kv.get(f"a{i}", ""))
        elif typ == "PATH":
            if kv.get("name", ""):
                ev["paths"].append(kv["name"])
        elif typ == "SOCKADDR":
            if kv.get("saddr", ""):
                ev["sockaddrs"].append(get_addr(kv["saddr"]))

    #Flush pending groups
    def flush_buf(self, force=False):
        now = time.time()
        done = []
        for serial, ev in self.buf.items():
            if force or (now - ev["last"]) >= WAIT:
                self.flush_ev(ev)
                done.append(serial)
        for serial in done:
            del self.buf[serial]
        return len(done)

    #Run main loop
    def run(self):
        logging.info("collector started")
        try:
            while True:
                try:
                    if self.open_log():
                        has_new = False
                        lines_processed = 0
                        while lines_processed < MAX_LINES_PER_CYCLE:
                            line = self.fp.readline()
                            if not line:
                                break
                            has_new = True
                            self.off = self.fp.tell()
                            self.add_line(line)
                            lines_processed += 1
                        flushed = self.flush_buf(False)
                        if has_new or flushed:
                            self.conn.commit()
                            self.save_off(False)
                except sqlite3.Error:
                    logging.exception("collector database error; reconnecting")
                    try:
                        self.conn.close()
                    except Exception:
                        pass
                    self.conn = self.open_db()
                except Exception:
                    logging.exception("collector loop error")
                time.sleep(SLEEP)
        except KeyboardInterrupt:
            logging.info("collector stopping")
        finally:
            self.flush_buf(True)
            self.conn.commit()
            self.save_off(True)
            if self.fp:
                self.fp.close()
            self.conn.close()


if __name__ == "__main__":
    Collector().run()
