#!/usr/bin/env python3
import sys
import argparse

def main():
    """Main entry point for the Cypher Security Toolkit."""
    # Check if we should run in CLI mode
    if len(sys.argv) > 1:
        # CLI mode
        from src.cli.cli_parser import run_cli
        run_cli()
    else:
        # GUI mode
        from PyQt5.QtWidgets import QApplication
        from src.ui.main_window import MainWindow
        
        app = QApplication(sys.argv)
        app.setApplicationName('Cypher Security Toolkit')
        app.setStyle('Fusion')  # Use Fusion style for a modern look across platforms
        
        window = MainWindow()
        window.show()
        
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()
