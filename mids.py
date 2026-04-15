from dashboard import Ui_MainWindow
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QHeaderView, QVBoxLayout
from PySide6.QtGui import QColor, QIcon, QPixmap, QPainter, QFont
from templates.logs_template import logsTemplate
from templates.alerts_template import alertsTemplate
from PySide6.QtCore import QTimer, QProcess, Qt, QMargins
from PySide6.QtCharts import QChart, QChartView, QBarSet, QBarSeries, QBarCategoryAxis, QValueAxis
import sqlite3
import io
import json
import os
import time

class MySideBar(QMainWindow, Ui_MainWindow):
    def __init__(self, username = "Default_Admin"):
        super().__init__()
        self.setupUi(self)

        # #region agent log
        self._dbg_run_id = os.environ.get("MIDS_DEBUG_RUN_ID", "pre-fix")
        def _dbg_write(payload: dict):
            try:
                payload.setdefault("sessionId", "173715")
                payload.setdefault("timestamp", int(time.time() * 1000))
                with io.open("debug-173715.log", "a", encoding="utf-8") as f:
                    f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            except Exception:
                pass
        self._dbg_write = _dbg_write
        self._dbg_write({
            "runId": self._dbg_run_id,
            "hypothesisId": "Q1",
            "location": "mids.py:__init__",
            "message": "GUI init",
            "data": {},
        })
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(lambda: self._stop_subprocesses("aboutToQuit"))
        # #endregion
        
        main_layout = self.dashboard_page.layout()
        if main_layout:
            main_layout.setRowStretch(0, 3)
            main_layout.setRowStretch(1, 2)
            main_layout.setColumnStretch(0, 1)
            main_layout.setColumnStretch(1, 1)
        
        self.init_attack_chart()
        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self.update_attack_data)
        self.chart_timer.start(20000)
        
        self.process = QProcess(self)
        self.process.finished.connect(self.on_process_finished)
        self.rule_engine_process = QProcess(self)
        self.rule_engine_process.finished.connect(self.on_process_finished)

        # #region agent log
        for name, proc in [("collector", self.process), ("rule_engine", self.rule_engine_process)]:
            proc.started.connect(lambda n=name: self._dbg_write({
                "runId": self._dbg_run_id,
                "hypothesisId": "Q1",
                "location": "mids.py:QProcess",
                "message": "process started",
                "data": {"name": n},
            }))
            proc.errorOccurred.connect(lambda err, n=name: self._dbg_write({
                "runId": self._dbg_run_id,
                "hypothesisId": "Q2",
                "location": "mids.py:QProcess",
                "message": "process error",
                "data": {"name": n, "error": int(err)},
            }))
            proc.finished.connect(lambda code, status, n=name: self._dbg_write({
                "runId": self._dbg_run_id,
                "hypothesisId": "Q1",
                "location": "mids.py:QProcess",
                "message": "process finished",
                "data": {"name": n, "exitCode": int(code), "exitStatus": int(status)},
            }))
        # #endregion
        
        if hasattr(self, 'user_label'):
            self.user_label.setText(f"{username}")
        self.setWindowTitle("Michigan Intrusion Detection System")
        self.setWindowIcon(QIcon("images/midslogonobg.png"))
        
        if hasattr(self, 'datContainer'):
            layout = QVBoxLayout(self.datContainer)
            layout.addWidget(self.dashboardAlertsTable)
            
        if hasattr(self, 'recentEvents'):
            layout = QVBoxLayout(self.recentEvents)
            layout.addWidget(self.recentEventsTable)
        
        self.icon_name_widget.setHidden(True)
        
        self.startMidsButton.toggled.connect(self.button_toggle)
        
        self.alerts_db_path = "alerts.db"
        self.db_path = "logs.db"
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.auto_update)
        self.timer.start(2000)
        
        self.dashboard_1.clicked.connect(self.switch_to_dashboardPage)
        self.dashboard_2.clicked.connect(self.switch_to_dashboardPage)
        
        self.alerts_1.clicked.connect(self.switch_to_alertsPage)
        self.alerts_2.clicked.connect(self.switch_to_alertsPage)
        
        self.logs_1.clicked.connect(self.switch_to_logsPage)
        self.logs_2.clicked.connect(self.switch_to_logsPage)
        
        self.configuration_1.clicked.connect(self.switch_to_configurationPage)
        self.configuration_2.clicked.connect(self.switch_to_configurationPage)
        
        self.logsWidget = logsTemplate()
        self.logsTableView.setModel(self.logsWidget)
        self.recentEventsTable.setModel(self.logsWidget)
        
        self.alertsWidget = alertsTemplate()
        self.alertsTableView.setModel(self.alertsWidget)
        self.dashboardAlertsTable.setModel(self.alertsWidget)
        
        header = self.dashboardAlertsTable.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        
        lHeader = self.logsTableView.horizontalHeader()
        lHeader.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        lHeader.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        lHeader.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        lHeader.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        lHeader.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        lHeader.setSectionResizeMode(5, QHeaderView.Stretch)
        
        aHeader = self.alertsTableView.horizontalHeader()
        aHeader.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        aHeader.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        aHeader.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        aHeader.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        aHeader.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        aHeader.setSectionResizeMode(5, QHeaderView.Stretch)
        
        rHeader = self.recentEventsTable.horizontalHeader()
        rHeader.setSectionResizeMode(QHeaderView.Stretch)
        
        self.dashboardAlertsTable.setColumnHidden(1, True)
        self.dashboardAlertsTable.setColumnHidden(4, True)
      
    def on_process_finished(self, *args):
        if self.process.state() == QProcess.NotRunning and self.rule_engine_process.state() == QProcess.NotRunning:
            self.startMidsButton.setChecked(False)

    # #region agent log
    def _stop_subprocesses(self, reason: str):
        self._dbg_write({
            "runId": self._dbg_run_id,
            "hypothesisId": "Q1",
            "location": "mids.py:_stop_subprocesses",
            "message": "stopping subprocesses",
            "data": {
                "reason": reason,
                "collector_state": int(self.process.state()),
                "rule_engine_state": int(self.rule_engine_process.state()),
            },
        })
        for name, proc in [("collector", self.process), ("rule_engine", self.rule_engine_process)]:
            if proc.state() != QProcess.NotRunning:
                proc.terminate()
                proc.waitForFinished(2000)
                if proc.state() != QProcess.NotRunning:
                    proc.kill()
                    proc.waitForFinished(2000)
            self._dbg_write({
                "runId": self._dbg_run_id,
                "hypothesisId": "Q1",
                "location": "mids.py:_stop_subprocesses",
                "message": "subprocess stopped state",
                "data": {"name": name, "state": int(proc.state())},
            })
    # #endregion

    def closeEvent(self, event):
        self._stop_subprocesses("closeEvent")
        super().closeEvent(event)
        
    def button_toggle(self, checked):
        if checked:
            # #region agent log
            self._dbg_write({
                "runId": self._dbg_run_id,
                "hypothesisId": "Q3",
                "location": "mids.py:button_toggle",
                "message": "start requested",
                "data": {},
            })
            # #endregion
            self.process.setProcessChannelMode(QProcess.ForwardedChannels)
            self.rule_engine_process.setProcessChannelMode(QProcess.ForwardedChannels)
            self.process.start("python", ["Collector.py"])
            if not self.process.waitForStarted():
                    print("Failed to start process:", self.process.errorString())
                    # #region agent log
                    self._dbg_write({
                        "runId": self._dbg_run_id,
                        "hypothesisId": "Q2",
                        "location": "mids.py:button_toggle",
                        "message": "collector failed to start",
                        "data": {"error": self.process.errorString()},
                    })
                    # #endregion
            self.rule_engine_process.start("python", ["rule_engine.py"])
        else:
            # #region agent log
            self._dbg_write({
                "runId": self._dbg_run_id,
                "hypothesisId": "Q1",
                "location": "mids.py:button_toggle",
                "message": "stop requested",
                "data": {},
            })
            # #endregion
            self._stop_subprocesses("toggle_off")
            
             
        
    def switch_to_dashboardPage(self):
        self.stackedWidget.setCurrentIndex(0)
        
    def switch_to_alertsPage(self):
        self.stackedWidget.setCurrentIndex(3)
        
    def switch_to_logsPage(self):
        self.stackedWidget.setCurrentIndex(1)
        
    def switch_to_configurationPage(self):
        self.stackedWidget.setCurrentIndex(2)
        
    def auto_update(self):
        if hasattr(self, 'logsWidget'):
            self.logsWidget.fetch_from_db(self.db_path)
        if hasattr(self, 'alertsWidget'):
            self.alertsWidget.fetch_alerts(self.alerts_db_path)
            
    def init_attack_chart(self):
        self.chart = QChart()
        self.chart.setTitle("Threat Distribution")
        self.chart.setAnimationOptions(QChart.SeriesAnimations)
        
        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        
        self.chart_layout = QVBoxLayout(self.attackChart)
        self.chart_layout.addWidget(self.chart_view)
        self.chart.layout().setContentsMargins(0, 0, 0, 0)
        self.chart.setMargins(QMargins(5, 5, 5, 30))
        self.chart.setBackgroundRoundness(0)
        
        
        
    def update_attack_data(self):
        try:
            conn = sqlite3.connect("alerts.db")
            cursor = conn.cursor()
            cursor.execute("SELECT rule_name, COUNT(*) FROM alerts GROUP BY rule_name")
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Database error in chart: {e}")
            return

        if not results:
            return
        
        bar_set = QBarSet("Alerts")
        categories = []
        
        #Name shortening
        for category, count in results:
            bar_set.append(count)
            cat_name = category if category else "Other"
            categories.append(cat_name)
            
        self.chart.removeAllSeries()
        series = QBarSeries()
        series.append(bar_set)
        self.chart.addSeries(series)
        
        #Labels
        for axis in self.chart.axes():
            self.chart.removeAxis(axis)
        
        font = QFont("Arial", 8)
        axis_x = QBarCategoryAxis()
        axis_x.setLabelsFont(font)
        axis_x.append(categories)
        #axis_x.setLabelsAngle(-90)
        self.chart.addAxis(axis_x, Qt.AlignBottom)
        series.attachAxis(axis_x)
        axis_x.setLabelsVisible(True)
        
        axis_y = QValueAxis()
        max_val = max([r[1] for r in results]) if results else 5
        axis_y.setRange(0, max_val + 1)
        axis_y.setLabelFormat("%d")
        self.chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_y)