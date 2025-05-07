"#!/usr/bin/env python3
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget
from src.ui.main_window import MainWindow

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setApplicationName('Cypher Security Toolkit')
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
"
