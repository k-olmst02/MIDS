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
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if os.name == 'nt':
    STATE_DIR = "."
    AUDIT_LOG = "auditlogs/audit.log"
else:
    AUDIT_LOG = "/var/log/audit/audit.log"
    STATE_DIR = os.path.join(BASE_DIR, "hids_collector")

OFFSET_FILE = os.path.join(STATE_DIR, "audit.offset")
DB_PATH = "logs.db"
SLEEP, WAIT, FILE_WIN, PROC_WIN = 1.0, 1.5, 30, 10
MAX_LINES_PER_CYCLE = 1000

TYPE_RE = re.compile(r"^type=([A-Z_]+)\s")
MSG_RE = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\):")
KV_RE = re.compile(r'(\w+)=("([^"\\]|\\.)*"|\S+)')
SYSCALL_NAME = {"59": "execve", "2": "open", "257": "open", "1": "write", "87": "unlink", "263": "unlink",
                "82": "rename", "264": "rename", "90": "chmod", "268": "chmod", "42": "connect",
                "43": "accept", "49": "bind"}
FILE_ACTIONS, NET_ACTIONS = {"open", "write", "unlink", "rename", "chmod"}, {"connect", "accept", "bind"}
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# #region agent log
def _dbg_write(payload: dict):
    try:
        payload.setdefault("sessionId", "173715")
        payload.setdefault("timestamp", int(time.time() * 1000))
        with io.open("debug-173715.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass
# #endregion


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


class Collector:
    #Setup collector state
    def __init__(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        self.conn = sqlite3.connect(f"file:{DB_PATH}?mode=rw", uri=True)
        self.my_pid = str(os.getpid())
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        need = {"events", "processes", "file_integrity", "network_activity"}
        found = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('events','processes','file_integrity','network_activity')"
        ).fetchall()}
        miss = sorted(need - found)
        if miss:
            raise RuntimeError(f"Missing tables: {', '.join(miss)}")
        self.off = 0
        self.ino = 0
        self.fp = None
        self.buf = {}
        self.file_seen = {}
        self.proc_seen = {}
        self.last_save = 0.0

        # #region agent log
        self._dbg_run_id = os.environ.get("MIDS_DEBUG_RUN_ID", "pre-fix")
        self._dbg_last = time.time()
        self._dbg = {
            "lines_total": 0,
            "lines_kept": 0,
            "drop_self_pid": 0,
            "drop_type": Counter(),
            "drop_syscall": Counter(),
            "kept_type": Counter(),
            "kept_syscall": Counter(),
            "kept_comm": Counter(),
            "kept_exe": Counter(),
            "kept_path_prefix": Counter(),
        }
        _dbg_write({
            "runId": self._dbg_run_id,
            "hypothesisId": "A",
            "location": "Collector.py:__init__",
            "message": "collector init",
            "data": {
                "audit_log": AUDIT_LOG,
                "state_dir": STATE_DIR,
                "max_lines_per_cycle": MAX_LINES_PER_CYCLE,
                "wait_s": WAIT,
                "sleep_s": SLEEP,
                "file_win_s": FILE_WIN,
                "proc_win_s": PROC_WIN,
            },
        })
        # #endregion
        try:
            with io.open(OFFSET_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                self.off = int(d.get("offset", 0))
                self.ino = int(d.get("inode", 0))
        except Exception:
            pass

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
        except FileNotFoundError:
            return False
        rot = self.ino and st.st_ino != self.ino
        shr = self.off > st.st_size
        if self.fp is None or rot or shr:
            if self.fp:
                self.fp.close()
            self.fp = io.open(AUDIT_LOG, "r", encoding="utf-8", errors="replace")
            self.ino = st.st_ino
            if rot or shr:
                self.off = 0
            self.fp.seek(self.off)
            if self.off == 0:
                self.fp.seek(0, 2)
                self.off = self.fp.tell()
            logging.info("audit open inode=%s off=%s", self.ino, self.off)
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
        # #region agent log
        self._dbg["lines_total"] += 1
        # #endregion
        typ, _ts, serial = get_head(line)
        if f"pid={self.my_pid}" in line:
            # #region agent log
            self._dbg["drop_self_pid"] += 1
            # #endregion
            return
        if typ in ["PROCTITLE", "CWD", "AVC"] or "syscall=0" in line or "syscall=89" in line:
            # #region agent log
            self._dbg["drop_type"][typ] += 1
            if "syscall=0" in line:
                self._dbg["drop_syscall"]["0"] += 1
            if "syscall=89" in line:
                self._dbg["drop_syscall"]["89"] += 1
            # #endregion
            return
        if serial is None:
            self.put_evt(typ, line)
            # #region agent log
            self._dbg["lines_kept"] += 1
            self._dbg["kept_type"][typ] += 1
            # #endregion
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
            ev["syscall"], ev["pid"], ev["ppid"], ev["uid"], ev["exe"], ev["comm"] = (
                get_sys(kv.get("syscall", "")), kv.get("pid", ""), kv.get("ppid", ""),
                kv.get("uid", ""), kv.get("exe", ""), kv.get("comm", "")
            )
            # #region agent log
            self._dbg["lines_kept"] += 1
            self._dbg["kept_type"][typ] += 1
            if ev.get("syscall"):
                self._dbg["kept_syscall"][ev["syscall"]] += 1
            if ev.get("comm"):
                self._dbg["kept_comm"][ev["comm"]] += 1
            if ev.get("exe"):
                self._dbg["kept_exe"][ev["exe"]] += 1
            # #endregion
        elif typ == "EXECVE":
            argc = int(kv.get("argc", "0") or "0")
            ev["cmdline"] = " ".join(kv.get(f"a{i}", "") for i in range(argc) if kv.get(f"a{i}", ""))
            # #region agent log
            self._dbg["lines_kept"] += 1
            self._dbg["kept_type"][typ] += 1
            # #endregion
        elif typ == "PATH":
            if kv.get("name", ""):
                ev["paths"].append(kv["name"])
                # #region agent log
                self._dbg["lines_kept"] += 1
                self._dbg["kept_type"][typ] += 1
                p = kv["name"]
                pref = "/" + p.strip("/").split("/", 1)[0] if p.startswith("/") else (p.split("\\", 1)[0] if p else "")
                if pref:
                    self._dbg["kept_path_prefix"][pref] += 1
                # #endregion
        elif typ == "SOCKADDR":
            if kv.get("saddr", ""):
                ev["sockaddrs"].append(get_addr(kv["saddr"]))
                # #region agent log
                self._dbg["lines_kept"] += 1
                self._dbg["kept_type"][typ] += 1
                # #endregion

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

    #Run main loop
    def run(self):
        logging.info("collector started")
        try:
            while True:
                if self.open_log():
                    has_new = False
                    lines_processed = 0
                    while lines_processed < MAX_LINES_PER_CYCLE:
                        while True:
                            line = self.fp.readline()
                            if not line:
                                break
                            has_new = True
                            self.off = self.fp.tell()
                            self.add_line(line)
                            lines_processed += 1
                        self.flush_buf(False)
                        if has_new:
                            self.conn.commit()
                            self.save_off(False)

                # #region agent log
                now = time.time()
                if now - self._dbg_last >= 10:
                    self._dbg_last = now
                    _dbg_write({
                        "runId": self._dbg_run_id,
                        "hypothesisId": "B",
                        "location": "Collector.py:run",
                        "message": "volume summary (10s)",
                        "data": {
                            "lines_total": self._dbg["lines_total"],
                            "lines_kept": self._dbg["lines_kept"],
                            "drop_self_pid": self._dbg["drop_self_pid"],
                            "drop_type_top": self._dbg["drop_type"].most_common(5),
                            "drop_syscall_top": self._dbg["drop_syscall"].most_common(5),
                            "kept_type_top": self._dbg["kept_type"].most_common(7),
                            "kept_syscall_top": self._dbg["kept_syscall"].most_common(7),
                            "kept_comm_top": self._dbg["kept_comm"].most_common(7),
                            "kept_exe_top": self._dbg["kept_exe"].most_common(5),
                            "kept_path_prefix_top": self._dbg["kept_path_prefix"].most_common(7),
                            "buf_groups": len(self.buf),
                        },
                    })
                    # reset window stats to keep logs small
                    self._dbg["lines_total"] = 0
                    self._dbg["lines_kept"] = 0
                    self._dbg["drop_self_pid"] = 0
                    self._dbg["drop_type"].clear()
                    self._dbg["drop_syscall"].clear()
                    self._dbg["kept_type"].clear()
                    self._dbg["kept_syscall"].clear()
                    self._dbg["kept_comm"].clear()
                    self._dbg["kept_exe"].clear()
                    self._dbg["kept_path_prefix"].clear()
                # #endregion
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
