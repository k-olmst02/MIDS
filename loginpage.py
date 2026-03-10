import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QGraphicsDropShadowEffect
from PySide6.QtUiTools import QUiLoader
from PySide6.QtGui import QColor, QIcon
from PySide6.QtCore import Qt

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



window.show()
app.exec()
