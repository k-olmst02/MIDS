from dashboard import Ui_MainWindow
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QHeaderView
from PySide6.QtGui import QColor, QIcon
from templates.logs_template import logsTemplate
from templates.alerts_template import alertsTemplate
from PySide6.QtCore import QTimer
class MySideBar(QMainWindow, Ui_MainWindow):
    def __init__(self, username = "Default_Admin"):
        super().__init__()
        self.setupUi(self)
        if hasattr(self, 'user_label'):
            self.user_label.setText(f"{username}")
        self.setWindowTitle("Michigan Intrusion Detection System")
        self.setWindowIcon(QIcon("images/midslogonobg.png"))
        
        self.icon_name_widget.setHidden(True)
        
        lHeader = self.logsTableView.horizontalHeader()
        lHeader.setSectionResizeMode(QHeaderView.Stretch)
        
        aHeader = self.alertsTableView.horizontalHeader()
        aHeader.setSectionResizeMode(QHeaderView.Stretch)
        
        self.alerts_db_path = "/var/lib/hids_collector/alerts.db"
        self.db_path = "/var/lib/hids_collector/logs.db"
        
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
        
        self.alertsWidget = alertsTemplate()
        self.alertsTableView.setModel(self.alertsWidget)
        
        
        
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
        
        