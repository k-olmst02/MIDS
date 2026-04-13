import os
import signal
import sys
import json
from PySide6.QtCore import QObject, QProcess


class StartMidsButtonController(QObject):
    def __init__(
        self,
        startMidsButton,
        collector_path="Collector.py",
        rule_engine_path="rule_engine.py",
        pid_file="mids.pid",
        parent=None,
    ):
        super().__init__(parent)
        self.btn = startMidsButton
        self.collector = os.path.abspath(collector_path)
        self.rule_engine = os.path.abspath(rule_engine_path)
        self.pid_file = os.path.abspath(pid_file)
        self.btn.setCheckable(True)
        self.btn.toggled.connect(self.toggle_collector)

    def toggle_collector(self, checked):
        if checked:
            ok1, pid1 = QProcess.startDetached(sys.executable, [self.collector])
            ok2, pid2 = QProcess.startDetached(sys.executable, [self.rule_engine])
            if ok1 and pid1 and ok2 and pid2:
                self.save_pid(pid1, pid2)
            else:
                if ok1 and pid1:
                    self.stop_process(pid1)
                if ok2 and pid2:
                    self.stop_process(pid2)
                self.btn.setChecked(False)
        else:
            self.stop_collector()

    def save_pid(self, collector_pid, rule_engine_pid):
        with open(self.pid_file, "w", encoding="utf-8") as f:
            json.dump(
                {"collector": int(collector_pid), "rule_engine": int(rule_engine_pid)},
                f,
            )

    def load_pid(self):
        try:
            with open(self.pid_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "collector": int(data["collector"]),
                    "rule_engine": int(data["rule_engine"]),
                }
        except Exception:
            return None

    def stop_collector(self):
        pids = self.load_pid()
        if not pids:
            return
        self.stop_process(pids.get("collector"))
        self.stop_process(pids.get("rule_engine"))
        try:
            os.remove(self.pid_file)
        except Exception:
            pass

    def stop_process(self, pid):
        if not pid:
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
