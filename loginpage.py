import sys, hashlib, sqlite3
from PySide6.QtWidgets import QApplication, QMainWindow, QGraphicsDropShadowEffect, QMessageBox
from PySide6.QtUiTools import QUiLoader
from PySide6.QtGui import QColor, QIcon
from PySide6.QtCore import Qt
from mids import MySideBar

app = QApplication(sys.argv)
loader = QUiLoader()

#Load UI
window = loader.load("mainwindow.ui", None)

#Window Title
window.setWindowTitle("Michigan Intrusion Detection System")

#Window Icon
window.setWindowIcon(QIcon("images/midslogonobg.png"))

#Hide bottom bar
window.statusBar().hide()

#No Resizing
window.setFixedSize(window.size())

#Drop shadow for title
text_shadow = QGraphicsDropShadowEffect(window.midsText)
text_shadow.setBlurRadius(8)
text_shadow.setColor(QColor(0, 0, 0, 100))
text_shadow.setOffset(2, 2)
window.midsText.setGraphicsEffect(text_shadow)

#Drop Shadow For panels
shadow = QGraphicsDropShadowEffect(window.rightPanel)
shadow.setBlurRadius(20)
shadow.setColor(QColor(0, 0, 0, 80))
shadow.setOffset(-8, 0)
window.rightPanel.setGraphicsEffect(shadow)

#Hashing and login
def hashing(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login():
    username = window.usernameEntryBox.text()
    password = window.passwordEntryBox.text()
    
    if not username or not password:
        QMessageBox.warning(window, "Input Error", "Please enter both a username and password.")
    
    try:
        attempt = hashing(password)
        
        connect = sqlite3.connect("logininfo.db")
        cursor = connect.cursor()
        cursor.execute("SELECT password_hash FROM logininfo WHERE username = ?", (username,))
        result = cursor.fetchone()
        connect.close()
    
        if result and result[0] == attempt:
            QMessageBox.information(window, "Login Success", f"Welcome back, {username}.")
            
            global dashboard
            dashboard = MySideBar(username)
            
            dashboard.show()
            window.close()
        else: 
            QMessageBox.critical(window, "Login Failed", "Incorrect username or password.")
    except sqlite3.Error as e:
        QMessageBox.critical(window, "Database Error", f"Could not connect to database: {e}")
window.loginButton.clicked.connect(login)

window.show()
app.exec()
