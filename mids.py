from dashboard import Ui_MainWindow
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton
from PySide6.QtGui import QColor, QIcon
class MySideBar(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle("Michigan Intrusion Detection System")
        self.setWindowIcon(QIcon("images/midslogonobg.png"))
        
        self.icon_name_widget.setHidden(True)
        
        self.dashboard_1.clicked.connect(self.switch_to_dashboardPage)
        self.dashboard_2.clicked.connect(self.switch_to_dashboardPage)
        
        self.alerts_1.clicked.connect(self.switch_to_alertsPage)
        self.alerts_2.clicked.connect(self.switch_to_alertsPage)
        
        self.logs_1.clicked.connect(self.switch_to_logsPage)
        self.logs_2.clicked.connect(self.switch_to_logsPage)
        
        self.configuration_1.clicked.connect(self.switch_to_configurationPage)
        self.configuration_2.clicked.connect(self.switch_to_configurationPage)
        
    def switch_to_dashboardPage(self):
        self.stackedWidget.setCurrentIndex(0)
        
    def switch_to_alertsPage(self):
        self.stackedWidget.setCurrentIndex(3)
        
    def switch_to_logsPage(self):
        self.stackedWidget.setCurrentIndex(1)
        
    def switch_to_configurationPage(self):
        self.stackedWidget.setCurrentIndex(2)