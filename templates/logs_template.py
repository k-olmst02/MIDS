from PySide6.QtCore import Qt, QAbstractTableModel
from PySide6.QtGui import QColor
import sqlite3

class logsTemplate(QAbstractTableModel):
    def __init__(self, data = None, headers = None):
        super().__init__()
        self._data = data or []
        self._headers = headers or ["ID", "Time", "Type", "Severity", "Source", "Message"]
    
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
            value = str(self._data[index.row()][index.column()]).lower()
            if value in ['critical', 'alert', 'error', 'unlink']:
                return QColor(Qt.red)
            if value in ['warning', 'chmod', 'rename']:
                return QColor(Qt.yellow)
            
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._headers[section]
        return None
    
    def update_data(self, new_data):
        self.beginResetModel()
        self._data = new_data
        self.endResetModel()
        
    def fetch_from_db(self, db_path):
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT id, timestamp, event_type, severity, source, message FROM events ORDER BY id DESC LIMIT 100")
            rows = cursor.fetchall()
            conn.close()
            self.update_data(rows)
        except Exception as e:
            print(f"Database error: {e}")