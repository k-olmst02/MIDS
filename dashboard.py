# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'dashboard.ui'
##
## Created by: Qt User Interface Compiler version 6.10.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QGridLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QMainWindow, QPushButton,
    QSizePolicy, QSpacerItem, QStackedWidget, QTableView,
    QVBoxLayout, QWidget)
import resources_rc

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(1058, 744)
        MainWindow.setStyleSheet(u"background-color: rgb(245, 250, 254);")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.gridLayout = QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName(u"gridLayout")
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.main_dashboard = QWidget(self.centralwidget)
        self.main_dashboard.setObjectName(u"main_dashboard")
        self.verticalLayout_5 = QVBoxLayout(self.main_dashboard)
        self.verticalLayout_5.setObjectName(u"verticalLayout_5")
        self.header_widget = QWidget(self.main_dashboard)
        self.header_widget.setObjectName(u"header_widget")
        self.horizontalLayout_3 = QHBoxLayout(self.header_widget)
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.menu = QPushButton(self.header_widget)
        self.menu.setObjectName(u"menu")
        self.menu.setMinimumSize(QSize(0, 0))
        self.menu.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.menu.setStyleSheet(u"border:none;")
        icon = QIcon()
        icon.addFile(u":/images/dropdownicon.png", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.menu.setIcon(icon)
        self.menu.setIconSize(QSize(20, 20))
        self.menu.setCheckable(True)

        self.horizontalLayout_3.addWidget(self.menu)

        self.horizontalSpacer = QSpacerItem(266, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer)

        self.label_2 = QLabel(self.header_widget)
        self.label_2.setObjectName(u"label_2")
        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        self.label_2.setFont(font)

        self.horizontalLayout_3.addWidget(self.label_2)

        self.horizontalSpacer_2 = QSpacerItem(266, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_2)

        self.startMidsButton = QPushButton(self.header_widget)
        self.startMidsButton.setObjectName(u"startMidsButton")
        self.startMidsButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.startMidsButton.setMouseTracking(False)
        self.startMidsButton.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.startMidsButton.setStyleSheet(u"border:none;")
        icon1 = QIcon()
        icon1.addFile(u"images/rsjej5atftjgrf35hrt2iam5b6-ed3e8950b4d6aaea6266056b674605a0.png", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        icon1.addFile(u"images/pause-button-outline-red-icon.webp", QSize(), QIcon.Mode.Normal, QIcon.State.On)
        self.startMidsButton.setIcon(icon1)
        self.startMidsButton.setIconSize(QSize(27, 27))
        self.startMidsButton.setCheckable(True)

        self.horizontalLayout_3.addWidget(self.startMidsButton)


        self.verticalLayout_5.addWidget(self.header_widget)

        self.stackedWidget = QStackedWidget(self.main_dashboard)
        self.stackedWidget.setObjectName(u"stackedWidget")
        self.stackedWidget.setStyleSheet(u"background-color: rgb(255, 255, 255);")
        self.dashboard_page = QWidget()
        self.dashboard_page.setObjectName(u"dashboard_page")
        self.gridLayout_2 = QGridLayout(self.dashboard_page)
        self.gridLayout_2.setObjectName(u"gridLayout_2")
        self.groupBox_2 = QGroupBox(self.dashboard_page)
        self.groupBox_2.setObjectName(u"groupBox_2")
        self.verticalLayout_9 = QVBoxLayout(self.groupBox_2)
        self.verticalLayout_9.setObjectName(u"verticalLayout_9")
        self.attackChart = QWidget(self.groupBox_2)
        self.attackChart.setObjectName(u"attackChart")

        self.verticalLayout_9.addWidget(self.attackChart)


        self.gridLayout_2.addWidget(self.groupBox_2, 0, 1, 1, 1)

        self.datContainer = QGroupBox(self.dashboard_page)
        self.datContainer.setObjectName(u"datContainer")
        self.dashboardAlertsTable = QTableView(self.datContainer)
        self.dashboardAlertsTable.setObjectName(u"dashboardAlertsTable")
        self.dashboardAlertsTable.setGeometry(QRect(11, 27, 381, 291))
        self.dashboardAlertsTable.setAutoFillBackground(False)

        self.gridLayout_2.addWidget(self.datContainer, 0, 0, 1, 1)

        self.recentEvents = QGroupBox(self.dashboard_page)
        self.recentEvents.setObjectName(u"recentEvents")
        self.recentEventsTable = QTableView(self.recentEvents)
        self.recentEventsTable.setObjectName(u"recentEventsTable")
        self.recentEventsTable.setGeometry(QRect(100, 60, 256, 192))

        self.gridLayout_2.addWidget(self.recentEvents, 1, 0, 1, 2)

        self.stackedWidget.addWidget(self.dashboard_page)
        self.logs_page = QWidget()
        self.logs_page.setObjectName(u"logs_page")
        self.verticalLayout_6 = QVBoxLayout(self.logs_page)
        self.verticalLayout_6.setObjectName(u"verticalLayout_6")
        self.logsTableView = QTableView(self.logs_page)
        self.logsTableView.setObjectName(u"logsTableView")

        self.verticalLayout_6.addWidget(self.logsTableView)

        self.stackedWidget.addWidget(self.logs_page)
        self.configuration_page = QWidget()
        self.configuration_page.setObjectName(u"configuration_page")
        self.label_7 = QLabel(self.configuration_page)
        self.label_7.setObjectName(u"label_7")
        self.label_7.setGeometry(QRect(280, 280, 241, 41))
        font1 = QFont()
        font1.setFamilies([u"Roboto"])
        font1.setPointSize(20)
        self.label_7.setFont(font1)
        self.stackedWidget.addWidget(self.configuration_page)
        self.alerts_page = QWidget()
        self.alerts_page.setObjectName(u"alerts_page")
        self.verticalLayout_7 = QVBoxLayout(self.alerts_page)
        self.verticalLayout_7.setObjectName(u"verticalLayout_7")
        self.alertsTableView = QTableView(self.alerts_page)
        self.alertsTableView.setObjectName(u"alertsTableView")

        self.verticalLayout_7.addWidget(self.alertsTableView)

        self.stackedWidget.addWidget(self.alerts_page)

        self.verticalLayout_5.addWidget(self.stackedWidget)


        self.gridLayout.addWidget(self.main_dashboard, 0, 2, 1, 1)

        self.icon_widget = QWidget(self.centralwidget)
        self.icon_widget.setObjectName(u"icon_widget")
        self.icon_widget.setStyleSheet(u"QWidget{\n"
"	background-color: rgb(69, 157, 229);\n"
"}\n"
"\n"
"QPushButton{\n"
"	color:black;\n"
"	height:30px;\n"
"	border:none;\n"
"	border-radius:10px;\n"
"}\n"
"\n"
"QPushButton:checked{\n"
"	background-color:#f5fafe;\n"
"	font-weight:bold;\n"
"}")
        self.verticalLayout_3 = QVBoxLayout(self.icon_widget)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.sidebar_logo = QLabel(self.icon_widget)
        self.sidebar_logo.setObjectName(u"sidebar_logo")
        self.sidebar_logo.setMinimumSize(QSize(40, 40))
        self.sidebar_logo.setMaximumSize(QSize(40, 40))
        self.sidebar_logo.setPixmap(QPixmap(u":/images/midslogonobg.png"))
        self.sidebar_logo.setScaledContents(True)

        self.horizontalLayout.addWidget(self.sidebar_logo)


        self.verticalLayout_3.addLayout(self.horizontalLayout)

        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setSpacing(15)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(-1, 15, -1, -1)
        self.dashboard_1 = QPushButton(self.icon_widget)
        self.dashboard_1.setObjectName(u"dashboard_1")
        self.dashboard_1.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        icon2 = QIcon(QIcon.fromTheme(u"go-home"))
        self.dashboard_1.setIcon(icon2)
        self.dashboard_1.setCheckable(True)
        self.dashboard_1.setAutoExclusive(True)

        self.verticalLayout.addWidget(self.dashboard_1)

        self.alerts_1 = QPushButton(self.icon_widget)
        self.alerts_1.setObjectName(u"alerts_1")
        self.alerts_1.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        icon3 = QIcon(QIcon.fromTheme(u"dialog-warning"))
        self.alerts_1.setIcon(icon3)
        self.alerts_1.setCheckable(True)
        self.alerts_1.setAutoExclusive(True)

        self.verticalLayout.addWidget(self.alerts_1)

        self.logs_1 = QPushButton(self.icon_widget)
        self.logs_1.setObjectName(u"logs_1")
        self.logs_1.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        icon4 = QIcon(QIcon.fromTheme(u"accessories-dictionary"))
        self.logs_1.setIcon(icon4)
        self.logs_1.setCheckable(True)
        self.logs_1.setAutoExclusive(True)

        self.verticalLayout.addWidget(self.logs_1)


        self.verticalLayout_3.addLayout(self.verticalLayout)

        self.verticalSpacer = QSpacerItem(20, 452, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_3.addItem(self.verticalSpacer)

        self.pushButton_6 = QPushButton(self.icon_widget)
        self.pushButton_6.setObjectName(u"pushButton_6")
        self.pushButton_6.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        icon5 = QIcon(QIcon.fromTheme(u"system-shutdown"))
        self.pushButton_6.setIcon(icon5)
        self.pushButton_6.setCheckable(True)

        self.verticalLayout_3.addWidget(self.pushButton_6)


        self.gridLayout.addWidget(self.icon_widget, 0, 0, 1, 1)

        self.icon_name_widget = QWidget(self.centralwidget)
        self.icon_name_widget.setObjectName(u"icon_name_widget")
        self.icon_name_widget.setStyleSheet(u"QWidget{\n"
"	background-color: rgb(69, 157, 229);\n"
"}\n"
"\n"
"QPushButton{\n"
"	color:black;\n"
"	text-align:left;\n"
"	height:30px;\n"
"	border:none;\n"
"	padding-left:10px;\n"
"	border-top-left-radius:10px;\n"
"	border-bottom-left-radius:10px;\n"
"}\n"
"\n"
"QPushButton:checked{\n"
"	background-color:#f5fafe;\n"
"	font-weight:bold;\n"
"}\n"
"")
        self.verticalLayout_4 = QVBoxLayout(self.icon_name_widget)
        self.verticalLayout_4.setObjectName(u"verticalLayout_4")
        self.verticalLayout_4.setContentsMargins(-1, -1, 0, -1)
        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalLayout_2.setContentsMargins(-1, -1, 50, -1)
        self.label = QLabel(self.icon_name_widget)
        self.label.setObjectName(u"label")
        self.label.setMinimumSize(QSize(40, 40))
        self.label.setMaximumSize(QSize(40, 40))
        self.label.setPixmap(QPixmap(u":/images/midslogonobg.png"))
        self.label.setScaledContents(True)

        self.horizontalLayout_2.addWidget(self.label)

        self.label_3 = QLabel(self.icon_name_widget)
        self.label_3.setObjectName(u"label_3")
        font2 = QFont()
        font2.setFamilies([u"Roboto"])
        font2.setPointSize(12)
        font2.setBold(True)
        self.label_3.setFont(font2)

        self.horizontalLayout_2.addWidget(self.label_3)


        self.verticalLayout_4.addLayout(self.horizontalLayout_2)

        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setSpacing(15)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(-1, 15, -1, -1)
        self.dashboard_2 = QPushButton(self.icon_name_widget)
        self.dashboard_2.setObjectName(u"dashboard_2")
        self.dashboard_2.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.dashboard_2.setIcon(icon2)
        self.dashboard_2.setCheckable(True)
        self.dashboard_2.setAutoExclusive(True)

        self.verticalLayout_2.addWidget(self.dashboard_2)

        self.alerts_2 = QPushButton(self.icon_name_widget)
        self.alerts_2.setObjectName(u"alerts_2")
        self.alerts_2.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.alerts_2.setIcon(icon3)
        self.alerts_2.setCheckable(True)
        self.alerts_2.setAutoExclusive(True)

        self.verticalLayout_2.addWidget(self.alerts_2)

        self.logs_2 = QPushButton(self.icon_name_widget)
        self.logs_2.setObjectName(u"logs_2")
        self.logs_2.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.logs_2.setIcon(icon4)
        self.logs_2.setCheckable(True)
        self.logs_2.setAutoExclusive(True)

        self.verticalLayout_2.addWidget(self.logs_2)


        self.verticalLayout_4.addLayout(self.verticalLayout_2)

        self.verticalSpacer_2 = QSpacerItem(20, 452, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout_4.addItem(self.verticalSpacer_2)

        self.pushButton_12 = QPushButton(self.icon_name_widget)
        self.pushButton_12.setObjectName(u"pushButton_12")
        self.pushButton_12.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.pushButton_12.setIcon(icon5)
        self.pushButton_12.setCheckable(True)

        self.verticalLayout_4.addWidget(self.pushButton_12)


        self.gridLayout.addWidget(self.icon_name_widget, 0, 1, 1, 1)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.menu.toggled.connect(self.icon_widget.setHidden)
        self.menu.toggled.connect(self.icon_name_widget.setVisible)
        self.logs_1.toggled.connect(self.logs_2.setChecked)
        self.alerts_1.toggled.connect(self.alerts_2.setChecked)
        self.dashboard_1.toggled.connect(self.dashboard_2.setChecked)
        self.dashboard_2.toggled.connect(self.dashboard_1.setChecked)
        self.alerts_2.toggled.connect(self.alerts_1.setChecked)
        self.logs_2.toggled.connect(self.logs_1.setChecked)
        self.pushButton_6.toggled.connect(MainWindow.close)
        self.pushButton_12.toggled.connect(MainWindow.close)

        self.stackedWidget.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.menu.setText("")
        self.label_2.setText(QCoreApplication.translate("MainWindow", u"Michigan Intrusion Detection System", None))
        self.startMidsButton.setText("")
        self.groupBox_2.setTitle(QCoreApplication.translate("MainWindow", u"Threat Distribution", None))
        self.datContainer.setTitle(QCoreApplication.translate("MainWindow", u"Live Alert Feed", None))
        self.recentEvents.setTitle(QCoreApplication.translate("MainWindow", u"Recent Events", None))
        self.label_7.setText(QCoreApplication.translate("MainWindow", u"Configuration Page", None))
        self.sidebar_logo.setText("")
        self.dashboard_1.setText("")
        self.alerts_1.setText("")
        self.logs_1.setText("")
        self.pushButton_6.setText("")
        self.label.setText("")
        self.label_3.setText(QCoreApplication.translate("MainWindow", u"MIDS", None))
        self.dashboard_2.setText(QCoreApplication.translate("MainWindow", u"Dashboard", None))
        self.alerts_2.setText(QCoreApplication.translate("MainWindow", u"Alerts", None))
        self.logs_2.setText(QCoreApplication.translate("MainWindow", u"Logs", None))
        self.pushButton_12.setText(QCoreApplication.translate("MainWindow", u"Sign Out", None))
    # retranslateUi

