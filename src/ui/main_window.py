import threading
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout, QApplication, 
                           QMessageBox, QSplashScreen, QLabel, QProgressBar, QToolBar, 
                           QAction, QStatusBar, QPushButton, QHBoxLayout, QFrame)
from PyQt5.QtCore import Qt, QTimer, QEvent, QThread, pyqtSignal, QObject, QSize
from PyQt5.QtGui import QPixmap, QIcon, QFont, QColor, QPalette
import traceback
import sys
import os
import gc  # Import garbage collector

# Import tab classes but don't instantiate them in the background thread
from src.ui.network_tab import NetworkToolsTab
from src.ui.crypto_tab import CryptoToolsTab
from src.ui.system_tab import SystemToolsTab
from src.ui.web_domain_tab import WebDomainTab
from src.ui.web_pentest_tab import WebPentestTab
from src.ui.malware_tab import MalwareTab
from src.utils.theme_manager import ThemeManager, AnimatedWidget

# Global exception hook to catch unhandled exceptions
def exception_hook(exctype, value, tb):
    """Global function to catch unhandled exceptions."""
    error_message = ''.join(traceback.format_exception(exctype, value, tb))
    QMessageBox.critical(None, "Error", 
                         f"An unexpected error occurred:\n\n{str(value)}\n\n"
                         f"Please report this issue. Full details have been printed to the console.")
    print(error_message)
    # Still call the original exception hook
    sys.__excepthook__(exctype, value, tb)

# Set the exception hook
sys.excepthook = exception_hook

class UIInitThread(QThread):
    """Thread to initialize UI tabs in background to speed up startup"""
    init_progress = pyqtSignal(int, str)
    init_complete = pyqtSignal()  # Signal that initialization is complete
    
    def run(self):
        try:
            # Don't create GUI elements in the thread, just emit signals
            # to update progress
            self.init_progress.emit(20, "Initializing Network Tools...")
            # Simulate work without creating Qt objects
            QThread.msleep(100)
            
            self.init_progress.emit(40, "Initializing Crypto Tools...")
            QThread.msleep(100)
            
            self.init_progress.emit(60, "Initializing System Tools...")
            QThread.msleep(100)
            
            self.init_progress.emit(70, "Initializing Web Domain Tools...")
            QThread.msleep(100)
            
            self.init_progress.emit(80, "Initializing Web Pentest Tools...")
            QThread.msleep(100)
            
            self.init_progress.emit(90, "Initializing Malware Analysis Tools...")
            QThread.msleep(100)
            
            self.init_progress.emit(100, "Ready!")
            
            # Signal that initialization is complete
            self.init_complete.emit()
            
        except Exception as e:
            print(f"Error during UI initialization: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Cypher Security Toolkit')
        self.setMinimumSize(900, 700)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)  # Remove margins for full-width header
        
        # Create modern header with logo and theme toggle
        header = QWidget()
        header.setObjectName("headerWidget")
        header.setMinimumHeight(60)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(15, 5, 15, 5)
        
        # App logo (using a styled label as placeholder)
        logo_label = QLabel("C")
        logo_label.setObjectName("appLogo")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setFixedSize(40, 40)
        logo_label.setStyleSheet("""
            background-color: #3498db;
            color: white;
            border-radius: 20px;
            font-size: 22px;
            font-weight: bold;
        """)
        
        # App name with custom styling
        app_name = QLabel("Cypher Security Toolkit")
        app_name.setObjectName("appName")
        font = app_name.font()
        font.setPointSize(12)
        font.setBold(True)
        app_name.setFont(font)
        
        # Add version label
        version_label = QLabel("v1.0")
        version_label.setObjectName("versionLabel")
        version_label.setStyleSheet("color: #666;")
        
        # Layout for logo and title
        title_layout = QHBoxLayout()
        title_layout.addWidget(logo_label)
        title_layout.addSpacing(10)
        title_layout.addWidget(app_name)
        title_layout.addSpacing(5)
        title_layout.addWidget(version_label)
        title_layout.addStretch(1)
        
        header_layout.addLayout(title_layout)
        
        # Theme toggle button with icon instead of text
        self.theme_toggle_btn = QPushButton()
        self.theme_toggle_btn.setObjectName("themeToggle")
        self.theme_toggle_btn.setToolTip("Switch between light and dark themes")
        self.theme_toggle_btn.setFixedSize(40, 40)
        self.theme_toggle_btn.setCursor(Qt.PointingHandCursor)
        self.theme_toggle_btn.clicked.connect(self.toggle_theme)
        
        # Help button
        help_btn = QPushButton("Help")
        help_btn.setFixedWidth(80)
        help_btn.setCursor(Qt.PointingHandCursor)
        help_btn.clicked.connect(self.show_help)
        
        # Add buttons to header
        header_layout.addWidget(self.theme_toggle_btn)
        header_layout.addSpacing(10)
        header_layout.addWidget(help_btn)
        
        # Add a separator line below the header
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("background-color: #cccccc;")
        
        # Add header and separator to main layout
        main_layout.addWidget(header)
        main_layout.addWidget(separator)
        
        # Create tab widget with cached content
        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)  # Enable scrolling for many tabs
        self.tabs.setDocumentMode(True)  # Cleaner look
        self.tabs.setMovable(True)  # Allow reordering tabs
        
        # Enable tab content caching to improve switching performance
        self.tabs.setTabsClosable(False)
        
        # Connect tab changed signal
        self.tabs.currentChanged.connect(self.on_tab_changed)
        
        # Add tabs to main layout
        main_layout.addWidget(self.tabs)
        
        # Initialize tab instances (will be populated later in the main thread)
        self.network_tab = None
        self.crypto_tab = None
        self.system_tab = None
        self.web_domain_tab = None
        self.web_pentest_tab = None
        self.malware_tab = None
        
        # Create and start initialization thread
        self.init_thread = UIInitThread()
        self.init_thread.init_progress.connect(self.update_init_progress)
        self.init_thread.init_complete.connect(self.create_tabs_in_main_thread)
        
        # Set up a timer to process events - use a more optimized approach
        self.event_timer = QTimer(self)
        self.event_timer.timeout.connect(self.process_pending_events)
        self.event_timer.start(50)  # 50ms instead of 100ms for smoother UI
        
        # Memory optimization timer - run garbage collection periodically
        self.gc_timer = QTimer(self)
        self.gc_timer.timeout.connect(self.optimize_memory)
        self.gc_timer.start(60000)  # Run every minute
        
        # Initialize the active tab
        self.current_tab_index = 0
        
        # Start initialization thread
        self.init_thread.start()
        
        # Initialize theme manager
        self.theme_manager = ThemeManager.instance()
        
        # Apply theme based on saved preference
        self.update_theme_button()
        self.theme_manager.apply_theme()
    
    def apply_styling(self):
        """Apply styling to the application for better visuals and performance"""
        # Get the QApplication instance and apply stylesheet to it
        app = QApplication.instance()
        app.setStyleSheet("""
            /* Some basic styling for better user experience */
            QMainWindow {
                background-color: #f5f5f5;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e1e1e1;
                padding: 6px 12px;
                margin-right: 2px;
                border: 1px solid #cccccc;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom-color: white;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            /* Optimizations for table widgets */
            QTableWidget {
                gridline-color: #d3d3d3;
                alternate-background-color: #f9f9f9;
            }
            QProgressBar {
                border: 1px solid #cccccc;
                border-radius: 3px;
                background-color: #f5f5f5;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                width: 10px;
                margin: 0px;
            }
        """)
    
    def update_init_progress(self, value, message):
        """Update initialization progress (placeholder - implement proper splash screen if needed)"""
        print(f"Loading: {value}% - {message}")
    
    def create_tabs_in_main_thread(self):
        """Create all tab objects in the main thread to avoid Qt threading issues"""
        try:
            # Create tab instances in the main thread
            self.network_tab = NetworkToolsTab()
            self.crypto_tab = CryptoToolsTab()
            self.system_tab = SystemToolsTab()
            self.web_domain_tab = WebDomainTab()
            self.web_pentest_tab = WebPentestTab()
            self.malware_tab = MalwareTab()
            
            # Now add tabs to tab widget (also in main thread)
            self.finalize_init()
            
        except Exception as e:
            print(f"Error creating UI elements: {str(e)}")
            traceback.print_exc()
    
    def finalize_init(self):
        """Finalize UI initialization by adding tabs to the widget"""
        # Create tab icons for better visual navigation
        network_icon = QIcon.fromTheme("network-wired", QIcon())  # Fallback to empty icon if not found
        crypto_icon = QIcon.fromTheme("security-high", QIcon())
        system_icon = QIcon.fromTheme("computer", QIcon())
        web_icon = QIcon.fromTheme("web-browser", QIcon())
        pentest_icon = QIcon.fromTheme("system-search", QIcon())
        malware_icon = QIcon.fromTheme("dialog-warning", QIcon())
        
        # If theme icons not available, use text-based icons (emojis)
        if network_icon.isNull():
            network_icon = self.create_text_icon("🌐")
        if crypto_icon.isNull():
            crypto_icon = self.create_text_icon("🔒")
        if system_icon.isNull():
            system_icon = self.create_text_icon("💻")
        if web_icon.isNull():
            web_icon = self.create_text_icon("🌍")
        if pentest_icon.isNull():
            pentest_icon = self.create_text_icon("🔍")
        if malware_icon.isNull():
            malware_icon = self.create_text_icon("🦠")
        
        # Add tabs to tab widget with icons
        if self.network_tab:
            self.tabs.addTab(self.network_tab, network_icon, 'Network Tools')
        if self.crypto_tab:
            self.tabs.addTab(self.crypto_tab, crypto_icon, 'Crypto Tools')
        if self.system_tab:
            self.tabs.addTab(self.system_tab, system_icon, 'System Tools')
        if self.web_domain_tab:
            self.tabs.addTab(self.web_domain_tab, web_icon, 'Web & Domain')
        if self.web_pentest_tab:
            self.tabs.addTab(self.web_pentest_tab, pentest_icon, 'Web Pentest')
        if self.malware_tab:
            self.tabs.addTab(self.malware_tab, malware_icon, 'Malware Analysis')
        
        # Set initial tab style
        self.update_tab_style()
        
    def create_text_icon(self, text):
        """Create a simple icon from text/emoji"""
        # Create a pixmap
        pixmap = QPixmap(24, 24)
        pixmap.fill(Qt.transparent)
        
        # Create a painter to draw on the pixmap
        from PyQt5.QtGui import QPainter, QColor
        painter = QPainter(pixmap)
        painter.setPen(QColor(0, 0, 0))
        painter.setFont(QFont("Arial", 14))
        painter.drawText(pixmap.rect(), Qt.AlignCenter, text)
        painter.end()
        
        return QIcon(pixmap)
        
    def update_tab_style(self):
        """Update tab appearance based on current theme"""
        current_theme = self.theme_manager.get_current_theme()
        
        # Set tab size policy to make tabs more comfortable
        self.tabs.setIconSize(QSize(16, 16))
        
        # Add some margin to tab bar if needed
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                padding: 8px 16px;
                margin-right: 4px;
            }
        """)
    
    def process_pending_events(self):
        """Process pending events to keep UI responsive, but limit to avoid high CPU usage"""
        # Process events with proper flags that exist in PyQt5
        QApplication.processEvents()
    
    def optimize_memory(self):
        """Periodically optimize memory usage"""
        # Force garbage collection to clean up unused objects
        gc.collect()
    
    def on_tab_changed(self, index):
        """Handle tab changes with proper resource management."""
        if self.current_tab_index == index:
            return  # No change
            
        previous_index = self.current_tab_index
        self.current_tab_index = index
        
        # Log the tab change for debugging
        print(f"Switching from tab {previous_index} to tab {index}")
        
        # Get the actual tab widgets
        previous_tab = self.tabs.widget(previous_index) 
        current_tab = self.tabs.widget(index)
        
        # Call any cleanup methods on the previous tab if it exists
        if previous_tab and hasattr(previous_tab, 'cleanup'):
            try:
                previous_tab.cleanup()
            except Exception as e:
                print(f"Error cleaning up previous tab: {str(e)}")
        
        # Ensure the new tab is properly initialized if it has an initialization method
        if current_tab and hasattr(current_tab, 'initialize'):
            try:
                current_tab.initialize()
            except Exception as e:
                print(f"Error initializing current tab: {str(e)}")
        
        # Force a show event on the current tab to ensure it's properly displayed
        if current_tab:
            try:
                # Simulate a show event by calling showEvent directly
                if hasattr(current_tab, 'showEvent'):
                    # Create a dummy event
                    from PyQt5.QtGui import QShowEvent
                    current_tab.showEvent(QShowEvent())
                    print(f"Manually triggered showEvent on tab {index}")
            except Exception as e:
                print(f"Error triggering show event: {str(e)}")
        
        # Process events to keep UI responsive
        QApplication.processEvents()
        
    def animate_tab_transition(self, prev_index, new_index):
        """Create a smooth animation when switching between tabs"""
        # Only animate if we have an animation manager
        if not hasattr(self, 'anim'):
            self.anim = AnimatedWidget(self)
            
        # Determine the direction based on tab indices
        direction = "left" if new_index > prev_index else "right"
        
        # Apply a subtle fade effect to the current content
        current_widget = self.tabs.currentWidget()
        if current_widget:
            # Quick fade in animation for the new tab
            self.anim.fade_in(current_widget, 200)
            
            # Also apply a gentle scale animation
            self.anim.quick_scale(current_widget, 0.98, 150)
    
    def event(self, event):
        """Override event processing to keep UI responsive."""
        # Handle only specific events to avoid UI lag
        if event.type() in (QEvent.Close, QEvent.WindowActivate):
            QApplication.processEvents()
            
        # Let the parent class handle the event normally
        return super().event(event)
    
    def closeEvent(self, event):
        """Clean up resources when closing the application."""
        # Stop any running timers
        if hasattr(self, 'event_timer') and self.event_timer.isActive():
            self.event_timer.stop()
        
        if hasattr(self, 'gc_timer') and self.gc_timer.isActive():
            self.gc_timer.stop()
            
        # Stop timers and threads in tabs
        try:
            if hasattr(self, 'system_tab') and self.system_tab:
                # Stop process monitoring
                if hasattr(self.system_tab, 'process_timer') and self.system_tab.process_timer.isActive():
                    self.system_tab.process_timer.stop()
                
                # Stop any running thread
                if hasattr(self.system_tab, 'process_thread') and self.system_tab.process_thread and self.system_tab.process_thread.isRunning():
                    self.system_tab.process_thread.terminate()
                    self.system_tab.process_thread.wait()
            
            # Clean up network tab resources
            if hasattr(self, 'network_tab') and self.network_tab:
                if hasattr(self.network_tab, 'bandwidth_timer') and self.network_tab.bandwidth_timer.isActive():
                    self.network_tab.bandwidth_timer.stop()
                
                if hasattr(self.network_tab, 'netstat_timer') and self.network_tab.netstat_timer.isActive():
                    self.network_tab.netstat_timer.stop()
                
                # Clean up any running threads
                for thread_attr in ['port_thread', 'ping_thread', 'trace_thread', 'arp_thread', 'netstat_thread', 'nmap_thread']:
                    if hasattr(self.network_tab, thread_attr):
                        thread = getattr(self.network_tab, thread_attr)
                        if thread and thread.isRunning():
                            thread.terminate()
                            thread.wait()
            
            # Clean up crypto tab resources
            if hasattr(self, 'crypto_tab') and self.crypto_tab:
                # Call cleanup method if it exists
                if hasattr(self.crypto_tab, 'cleanup'):
                    self.crypto_tab.cleanup()
        except Exception as e:
            print(f"Error during cleanup: {str(e)}")
        
        # Run garbage collection to clean up memory
        gc.collect()
        
        # Accept the close event
        event.accept()
    
    def toggle_theme(self):
        """Toggle between light and dark themes with animation"""
        # Get current theme and target theme
        current_theme = self.theme_manager.get_current_theme()
        target_theme = "dark" if current_theme == "light" else "light"
        
        # Get theme colors
        current_bg = self.theme_manager.current_theme["background"]
        target_bg = self.theme_manager.DARK_THEME["background"] if target_theme == "dark" else self.theme_manager.LIGHT_THEME["background"]
        
        # Create a fade out animation
        self.anim = AnimatedWidget(self)
        fade_out = self.anim.fade_out(self.centralWidget(), 200)
        
        # Toggle the theme when fade out completes
        fade_out.finished.connect(lambda: self._complete_theme_toggle(target_theme))
    
    def _complete_theme_toggle(self, target_theme):
        """Complete theme toggle animation after fade out"""
        # Toggle the theme using the theme manager
        self.theme_manager.toggle_theme()
        
        # Update the button text based on current theme
        self.update_theme_button()
        
        # Create fade in animation
        fade_in = self.anim.fade_in(self.centralWidget(), 300)
        
        # Apply subtle animations to other UI elements
        self.anim.quick_scale(self.tabs, 0.98, 200)
        
        # Animate the logo with a pulse
        logo = self.findChild(QLabel, "appLogo") 
        if logo:
            self.anim.pulse(logo, 400)
        
    def update_theme_button(self):
        """Update the theme toggle button with icon based on current theme"""
        current_theme = self.theme_manager.get_current_theme()
        if current_theme == "light":
            self.theme_toggle_btn.setToolTip("Switch to Dark Theme")
            self.theme_toggle_btn.setText("🌙")  # Moon emoji for dark mode
            self.theme_toggle_btn.setStyleSheet("""
                QPushButton#themeToggle {
                    border-radius: 20px;
                    background-color: #f0f0f0;
                    border: 1px solid #ddd;
                    font-size: 16px;
                }
                QPushButton#themeToggle:hover {
                    background-color: #e0e0e0;
                }
            """)
        else:
            self.theme_toggle_btn.setToolTip("Switch to Light Theme")
            self.theme_toggle_btn.setText("☀️")  # Sun emoji for light mode
            self.theme_toggle_btn.setStyleSheet("""
                QPushButton#themeToggle {
                    border-radius: 20px;
                    background-color: #444;
                    border: 1px solid #555;
                    font-size: 16px;
                }
                QPushButton#themeToggle:hover {
                    background-color: #555;
                }
            """)
    
    def show_help(self):
        """Show help dialog with information about the Cypher Security Toolkit"""
        help_text = """
<h3>Cypher Security Toolkit</h3>
<p>This toolkit provides a collection of security and network analysis tools:</p>

<b>Network Tools:</b>
<ul>
<li>Port Scanner - Scan for open ports on a target host</li>
<li>Ping & Traceroute - Test connectivity and trace network routes</li>
<li>ARP Scanner - Discover devices on your local network</li>
<li>Netstat - Monitor network connections</li>
<li>Bandwidth Monitor - Track network usage</li>
<li>Nmap Scanner - Advanced network scanning</li>
</ul>

<b>Crypto Tools:</b>
<ul>
<li>Hash Generator - Generate secure hashes</li>
<li>File Encryption - Protect files with encryption</li>
<li>Password Strength - Evaluate password security</li>
</ul>

<b>System Tools:</b>
<ul>
<li>Process Monitor - Track system processes</li>
<li>File Integrity Checker - Verify file integrity</li>
</ul>

<b>Web & Domain Tools:</b>
<ul>
<li>DNS Lookup - Query DNS records</li>
<li>WHOIS Lookup - Retrieve domain information</li>
</ul>

<b>Web Pentest Tools:</b>
<ul>
<li>Header Analyzer - Check HTTP security headers</li>
<li>Subdomain Scanner - Find subdomains</li>
<li>XSS Scanner - Test for cross-site scripting</li>
</ul>

<b>Malware Analysis:</b>
<ul>
<li>Malware Hash Checker - Verify file hashes against malware databases</li>
<li>Static Analysis - Analyze files for suspicious characteristics</li>
</ul>

<p>For more information and documentation, visit our GitHub repository.</p>
"""
        
        QMessageBox.information(self, "Cypher Security Toolkit Help", help_text)
