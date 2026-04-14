from PySide6.QtCore import Qt, QAbstractTableModel
from PySide6.QtGui import QColor
import sqlite3

class alertsTemplate(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._data = []
        self._headers = ["ID", "Timestamp", "Rule Name", "Severity", "Source", "Description"]
    
    def rowCount(self, index = None):
        return len(self._data)
    
    def columnCount(self, index = None):
        return len(self._headers)
    
    def data(self, index, role):
        if not index.isValid():
            return None
        
        if role == Qt.DisplayRole:
            return str(self._data[index.row()][index.column()])
        
        if role == Qt.ForegroundRole:
            severity = str(self._data[index.row()][index.column()]).lower()
            if severity in ['critical', 'high']:
                return QColor(Qt.red)
            if severity in ['medium']:
                return QColor(255, 165, 0)
        return None
            
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._headers[section]
        return None
    
        
    def fetch_alerts(self, db_path):
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT id, timestamp, rule_name, severity, source, description FROM alerts ORDER BY id DESC")
            self.beginResetModel()
            self._data = cursor.fetchall()
            self.endResetModel()
            conn.close()
            
        except Exception as e:
            print(f"Alerts Database error: {e}")