#!/usr/bin/env python3
import sys
from PyQt5.QtWidgets import QApplication
from src.ui.main_window import MainWindow

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setApplicationName('Cypher Security Toolkit')
    app.setStyle('Fusion')  # Use Fusion style for a modern look across platforms
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())
