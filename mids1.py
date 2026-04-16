from dashboard import Ui_MainWindow
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QHeaderView, QVBoxLayout
from PySide6.QtGui import QColor, QIcon, QPixmap, QPainter, QFont
from templates.logs_template import logsTemplate
from templates.alerts_template import alertsTemplate
from PySide6.QtCore import QTimer, QProcess, Qt, QMargins
from PySide6.QtCharts import QChart, QChartView, QBarSet, QBarSeries, QBarCategoryAxis, QValueAxis
import sqlite3
import os
import sys

class MySideBar(QMainWindow, Ui_MainWindow):
    def __init__(self, username = "Default_Admin"):
        super().__init__()
        self.setupUi(self)
        
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

        self.process = None
        self.rule_engine_process = None
        
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
        
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.base_dir = base_dir
        self.collector_path = os.path.join(base_dir, "Collector.py")
        self.rule_engine_path = os.path.join(base_dir, "rule_engine.py")
        self.alerts_db_path = os.path.join(base_dir, "alerts.db")
        self.db_path = os.path.join(base_dir, "logs.db")
        self._create_managed_processes()
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.auto_update)
        self.timer.start(2000)
        
        self.dashboard_1.clicked.connect(self.switch_to_dashboardPage)
        self.dashboard_2.clicked.connect(self.switch_to_dashboardPage)
        
        self.alerts_1.clicked.connect(self.switch_to_alertsPage)
        self.alerts_2.clicked.connect(self.switch_to_alertsPage)
        
        self.logs_1.clicked.connect(self.switch_to_logsPage)
        self.logs_2.clicked.connect(self.switch_to_logsPage)
        
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

    def _build_process(self, script_path, label):
        process = QProcess(self)
        process.setProgram(sys.executable)
        process.setArguments([script_path])
        process.setWorkingDirectory(self.base_dir)
        process.setProcessChannelMode(QProcess.ForwardedChannels)
        process.finished.connect(self.on_process_finished)
        process.errorOccurred.connect(
            lambda error, name=label, proc=process: print(
                f"{name} process error ({error}): {proc.errorString()}"
            )
        )
        return process

    def _create_managed_processes(self):
        self.process = self._build_process(self.collector_path, "Collector")
        self.rule_engine_process = self._build_process(self.rule_engine_path, "Rule engine")

    def _ensure_stopped(self, process, label):
        if process is None or process.state() == QProcess.NotRunning:
            return

        process.terminate()
        if not process.waitForFinished(3000):
            print(f"{label} did not stop gracefully; killing it.")
            process.kill()
            process.waitForFinished(3000)

    def _start_process(self, process, label):
        if process.state() != QProcess.NotRunning:
            print(f"{label} is already running.")
            return True

        process.start()
        if not process.waitForStarted(3000):
            print(f"Failed to start {label}: {process.errorString()}")
            return False
        return True
      
    def on_process_finished(self):
        if self.process.state() == QProcess.NotRunning and self.rule_engine_process.state() == QProcess.NotRunning:
            self.startMidsButton.setChecked(False)
        
    def button_toggle(self, checked):
        if checked:
            self._ensure_stopped(self.process, "Collector")
            self._ensure_stopped(self.rule_engine_process, "Rule engine")
            self._create_managed_processes()

            collector_started = self._start_process(self.process, "Collector")
            rule_engine_started = self._start_process(self.rule_engine_process, "Rule engine")

            if not (collector_started and rule_engine_started):
                self._ensure_stopped(self.process, "Collector")
                self._ensure_stopped(self.rule_engine_process, "Rule engine")
                self.startMidsButton.blockSignals(True)
                self.startMidsButton.setChecked(False)
                self.startMidsButton.blockSignals(False)
        else:
            self._ensure_stopped(self.process, "Collector")
            self._ensure_stopped(self.rule_engine_process, "Rule engine")
            
             
        
    def switch_to_dashboardPage(self):
        self.stackedWidget.setCurrentIndex(0)
        
    def switch_to_alertsPage(self):
        self.stackedWidget.setCurrentIndex(3)
        
    def switch_to_logsPage(self):
        self.stackedWidget.setCurrentIndex(1)
        
        
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
