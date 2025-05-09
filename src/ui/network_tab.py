from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel, QPushButton, 
                          QLineEdit, QTextEdit, QGroupBox, QComboBox, QTabWidget, 
                          QHBoxLayout, QTableWidget, QTableWidgetItem, QSpinBox, QProgressBar,
                          QCheckBox, QFileDialog, QHeaderView)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
import os
import time

from src.tools.network.port_scanner import PortScanner
from src.tools.network.ping_utility import PingUtility
from src.tools.network.traceroute import Traceroute
from src.tools.network.arp_scanner import ARPScanner
from src.tools.network.netstat_utility import NetstatUtility
from src.tools.network.bandwidth_monitor import BandwidthMonitor
from src.tools.network.nmap_scanner import NmapScanner
from src.tools.network.packet_sniffer import PacketSniffer
from src.tools.network.wireless_scanner import WirelessScanner


class PortScanThread(QThread):
    """Thread for port scanning without blocking UI."""
    update_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, int, int)  # current, total, open_count
    
    def __init__(self, target, start_port, end_port, timeout=1):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        
    def run(self):
        try:
            scanner = PortScanner()
            
            def progress_callback(port, service, is_open):
                current = port - self.start_port + 1
                total = self.end_port - self.start_port + 1
                # Count open ports in the results
                open_count = len([p for p in range(self.start_port, port + 1) 
                                 if scanner.scan_single_port(self.target, p)])
                self.progress_signal.emit(current, total, open_count)
            
            # Run the scan with progress updates
            results = scanner.scan(
                self.target, 
                self.start_port, 
                self.end_port, 
                self.timeout,
                progress_callback
            )
            
            self.update_signal.emit(results)
        except Exception as e:
            self.update_signal.emit({"error": str(e)})


class PingThread(QThread):
    """Thread for ping operations without blocking UI."""
    update_signal = pyqtSignal(dict)
    
    def __init__(self, target, count):
        super().__init__()
        self.target = target
        self.count = count
        
    def run(self):
        try:
            ping_util = PingUtility()
            results = ping_util.ping(self.target, self.count)
            self.update_signal.emit(results)
        except Exception as e:
            self.update_signal.emit({"error": str(e)})


class TracerouteThread(QThread):
    """Thread for traceroute operations without blocking UI."""
    update_signal = pyqtSignal(list)
    
    def __init__(self, target, max_hops):
        super().__init__()
        self.target = target
        self.max_hops = max_hops
        
    def run(self):
        try:
            traceroute = Traceroute()
            results = traceroute.trace(self.target, self.max_hops)
            self.update_signal.emit(results)
        except Exception as e:
            self.update_signal.emit([{"error": str(e)}])


class ArpScanThread(QThread):
    """Thread for ARP scanning without blocking UI."""
    update_signal = pyqtSignal(dict)
    
    def __init__(self, network):
        super().__init__()
        self.network = network
        
    def run(self):
        try:
            scanner = ARPScanner()
            results = scanner.scan(self.network)
            self.update_signal.emit(results)
        except Exception as e:
            self.update_signal.emit({"error": str(e)})


class NetstatThread(QThread):
    """Thread for netstat operations without blocking UI."""
    update_signal = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        
    def run(self):
        try:
            netstat = NetstatUtility()
            results = netstat.get_connections()
            self.update_signal.emit(results)
        except Exception as e:
            self.update_signal.emit([{"error": str(e)}])


class NmapScanThread(QThread):
    """Thread for Nmap scanning without blocking UI."""
    update_signal = pyqtSignal(dict)
    
    def __init__(self, target, ports, args):
        super().__init__()
        self.target = target
        self.ports = ports
        self.args = args
        
    def run(self):
        try:
            scanner = NmapScanner()
            results = scanner.scan(self.target, self.args)
            self.update_signal.emit(results)
        except Exception as e:
            self.update_signal.emit({"error": str(e)})


class PacketSnifferThread(QThread):
    """Thread for packet sniffing without blocking UI."""
    packet_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)
    stopped_signal = pyqtSignal()
    
    def __init__(self, interface=None, protocols=None, ips=None, ports=None):
        super().__init__()
        self.interface = interface
        self.protocols = protocols or []
        self.ips = ips or []
        self.ports = ports or []
        self.sniffer = None
        
    def run(self):
        try:
            self.sniffer = PacketSniffer(self.interface)
            
            # Apply filters if provided
            if self.protocols or self.ips or self.ports:
                self.sniffer.set_filter(protocols=self.protocols, ips=self.ips, ports=self.ports)
            
            # Define callback to emit signals
            def packet_callback(packet):
                self.packet_signal.emit(packet)
            
            # Start sniffing with no timeout (will run until stopped)
            self.sniffer.start(callback=packet_callback)
            
            # Keep thread running until sniffer is stopped
            while self.sniffer.running:
                self.msleep(100)
                
            self.stopped_signal.emit()
            
        except Exception as e:
            self.error_signal.emit(str(e))
    
    def stop(self):
        if self.sniffer:
            self.sniffer.stop()


class WirelessScanThread(QThread):
    """Thread for wireless network scanning without blocking UI."""
    update_signal = pyqtSignal(list)
    error_signal = pyqtSignal(str)
    
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.scanner = WirelessScanner()
        
    def run(self):
        try:
            # Get interfaces if none specified
            if not self.interface:
                interfaces = self.scanner.get_interfaces()
                if interfaces:
                    self.interface = interfaces[0]
                else:
                    self.error_signal.emit("No wireless interfaces found")
                    return
            
            # Scan for networks
            networks = self.scanner.scan(self.interface)
            self.update_signal.emit(networks)
        except Exception as e:
            self.error_signal.emit(str(e))


class NetworkToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        
        # Create main layout
        self.layout = QVBoxLayout(self)
        
        # Create a tab widget for network tools
        self.tabs = QTabWidget()
        
        # Create individual tool tabs
        self.port_scanner_tab = self._create_port_scanner_tab()
        self.ping_traceroute_tab = self._create_ping_traceroute_tab()
        self.arp_scanner_tab = self._create_arp_scanner_tab()
        self.netstat_tab = self._create_netstat_tab()
        self.bandwidth_tab = self._create_bandwidth_tab()
        self.nmap_tab = self._create_nmap_tab()
        self.packet_sniffer_tab = self._create_packet_sniffer_tab()
        self.wireless_scanner_tab = self._create_wireless_scanner_tab()
        
        # Add tool tabs to tab widget
        self.tabs.addTab(self.port_scanner_tab, "Port Scanner")
        self.tabs.addTab(self.ping_traceroute_tab, "Ping & Traceroute")
        self.tabs.addTab(self.arp_scanner_tab, "ARP Scanner")
        self.tabs.addTab(self.netstat_tab, "Netstat")
        self.tabs.addTab(self.bandwidth_tab, "Bandwidth Monitor")
        self.tabs.addTab(self.nmap_tab, "Nmap Scanner")
        self.tabs.addTab(self.packet_sniffer_tab, "Packet Sniffer")
        self.tabs.addTab(self.wireless_scanner_tab, "Wi-Fi Scanner")
        
        # Add tab widget to main layout
        self.layout.addWidget(self.tabs)
        
        # Initialize objects for network tools
        self.port_scanner = PortScanner()
        self.ping_utility = PingUtility()
        self.traceroute = Traceroute()
        self.arp_scanner = ARPScanner()
        self.netstat_utility = NetstatUtility()
        self.bandwidth_monitor = BandwidthMonitor()
        self.nmap_scanner = NmapScanner()
        
        # Initialize timers with longer intervals
        self.netstat_timer = QTimer()
        self.netstat_timer.timeout.connect(self.refresh_netstat)
        self.netstat_timer.setInterval(5000)  # 5 seconds instead of 2
        
        self.bandwidth_timer = QTimer()
        self.bandwidth_timer.timeout.connect(self.update_bandwidth)
        
        # Initialize thread objects
        self.port_thread = None
        self.ping_thread = None
        self.trace_thread = None
        self.arp_thread = None
        self.netstat_thread = None
        self.nmap_thread = None
        self.packet_thread = None
        self.wifi_thread = None
        
        # Flag to prevent multiple thread launches
        self.netstat_updating = False
        
        # Initialize animation manager
        from src.utils.theme_manager import AnimatedWidget
        self.anim = AnimatedWidget(self)
        
        # Initialize loading spinners (we'll create them when needed)
        self.port_spinner = None
        self.ping_spinner = None
        self.trace_spinner = None
        self.arp_spinner = None
        self.netstat_spinner = None
        self.nmap_spinner = None
    
    def _create_port_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input section
        input_group = QGroupBox("Target Configuration")
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Target:"), 0, 0)
        self.port_target_input = QLineEdit()
        self.port_target_input.setPlaceholderText("Enter IP address or hostname (e.g., 192.168.1.1)")
        input_layout.addWidget(self.port_target_input, 0, 1, 1, 3)
        
        input_layout.addWidget(QLabel("Port Range:"), 1, 0)
        self.start_port_input = QSpinBox()
        self.start_port_input.setRange(1, 65535)
        self.start_port_input.setValue(1)
        input_layout.addWidget(self.start_port_input, 1, 1)
        
        input_layout.addWidget(QLabel("to"), 1, 2)
        self.end_port_input = QSpinBox()
        self.end_port_input.setRange(1, 65535)
        self.end_port_input.setValue(1024)
        input_layout.addWidget(self.end_port_input, 1, 3)
        
        self.scan_button = QPushButton("Scan Ports")
        self.scan_button.clicked.connect(self.scan_ports)
        input_layout.addWidget(self.scan_button, 2, 0, 1, 4)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Progress bar
        self.port_progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.port_progress = QProgressBar()
        self.port_progress.setRange(0, 100)
        self.port_progress.setValue(0)
        progress_layout.addWidget(self.port_progress)
        
        self.port_progress_label = QLabel("Ready")
        progress_layout.addWidget(self.port_progress_label)
        
        self.port_progress_group.setLayout(progress_layout)
        layout.addWidget(self.port_progress_group)
        
        # Results section
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.port_results = QTextEdit()
        self.port_results.setReadOnly(True)
        results_layout.addWidget(self.port_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab

    def _create_ping_traceroute_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create a tab widget for ping and traceroute
        tools_tabs = QTabWidget()
        
        # Ping tab
        ping_tab = QWidget()
        ping_layout = QVBoxLayout(ping_tab)
        
        ping_config = QGroupBox("Ping Configuration")
        ping_config_layout = QGridLayout()
        
        ping_config_layout.addWidget(QLabel("Target:"), 0, 0)
        self.ping_target_input = QLineEdit()
        self.ping_target_input.setPlaceholderText("Enter IP address or hostname")
        ping_config_layout.addWidget(self.ping_target_input, 0, 1)
        
        ping_config_layout.addWidget(QLabel("Count:"), 1, 0)
        self.ping_count_input = QSpinBox()
        self.ping_count_input.setRange(1, 100)
        self.ping_count_input.setValue(4)
        ping_config_layout.addWidget(self.ping_count_input, 1, 1)
        
        self.ping_button = QPushButton("Ping")
        self.ping_button.clicked.connect(self.ping_target)
        ping_config_layout.addWidget(self.ping_button, 2, 0, 1, 2)
        
        ping_config.setLayout(ping_config_layout)
        ping_layout.addWidget(ping_config)
        
        ping_results_group = QGroupBox("Ping Results")
        ping_results_layout = QVBoxLayout()
        self.ping_results = QTextEdit()
        self.ping_results.setReadOnly(True)
        ping_results_layout.addWidget(self.ping_results)
        ping_results_group.setLayout(ping_results_layout)
        ping_layout.addWidget(ping_results_group)
        
        # Traceroute tab
        trace_tab = QWidget()
        trace_layout = QVBoxLayout(trace_tab)
        
        trace_config = QGroupBox("Traceroute Configuration")
        trace_config_layout = QGridLayout()
        
        trace_config_layout.addWidget(QLabel("Target:"), 0, 0)
        self.trace_target_input = QLineEdit()
        self.trace_target_input.setPlaceholderText("Enter IP address or hostname")
        trace_config_layout.addWidget(self.trace_target_input, 0, 1)
        
        trace_config_layout.addWidget(QLabel("Max Hops:"), 1, 0)
        self.trace_hops_input = QSpinBox()
        self.trace_hops_input.setRange(1, 64)
        self.trace_hops_input.setValue(30)
        trace_config_layout.addWidget(self.trace_hops_input, 1, 1)
        
        self.trace_button = QPushButton("Trace Route")
        self.trace_button.clicked.connect(self.trace_target)
        trace_config_layout.addWidget(self.trace_button, 2, 0, 1, 2)
        
        trace_config.setLayout(trace_config_layout)
        trace_layout.addWidget(trace_config)
        
        trace_results_group = QGroupBox("Traceroute Results")
        trace_results_layout = QVBoxLayout()
        self.trace_results = QTextEdit()
        self.trace_results.setReadOnly(True)
        trace_results_layout.addWidget(self.trace_results)
        trace_results_group.setLayout(trace_results_layout)
        trace_layout.addWidget(trace_results_group)
        
        # Add tabs to the tools tab widget
        tools_tabs.addTab(ping_tab, "Ping")
        tools_tabs.addTab(trace_tab, "Traceroute")
        
        layout.addWidget(tools_tabs)
        
        return tab
        
    def _create_arp_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input section
        input_group = QGroupBox("ARP Scan Configuration")
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Network (CIDR):"), 0, 0)
        self.arp_network_input = QLineEdit()
        self.arp_network_input.setPlaceholderText("e.g., 192.168.1.0/24")
        input_layout.addWidget(self.arp_network_input, 0, 1)
        
        self.arp_scan_button = QPushButton("Scan Network")
        self.arp_scan_button.clicked.connect(self.scan_arp)
        input_layout.addWidget(self.arp_scan_button, 1, 0, 1, 2)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Discovered Devices")
        results_layout = QVBoxLayout()
        
        self.arp_results = QTableWidget()
        self.arp_results.setColumnCount(3)
        self.arp_results.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Hostname"])
        self.arp_results.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.arp_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab
    
    def _create_netstat_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Control section
        control_group = QGroupBox("Netstat Controls")
        control_layout = QHBoxLayout()
        
        self.netstat_refresh_button = QPushButton("Refresh")
        self.netstat_refresh_button.clicked.connect(self.refresh_netstat)
        control_layout.addWidget(self.netstat_refresh_button)
        
        self.netstat_auto_refresh = QPushButton("Auto Refresh")
        self.netstat_auto_refresh.setCheckable(True)
        self.netstat_auto_refresh.clicked.connect(self.toggle_netstat_refresh)
        control_layout.addWidget(self.netstat_auto_refresh)
        
        control_layout.addWidget(QLabel("Filter:"))
        self.netstat_filter = QComboBox()
        self.netstat_filter.addItems(["All Connections", "Listening Only", "Established Only"])
        self.netstat_filter.currentIndexChanged.connect(self.update_netstat)
        control_layout.addWidget(self.netstat_filter)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Results section
        results_group = QGroupBox("Network Connections")
        results_layout = QVBoxLayout()
        
        self.netstat_results = QTableWidget()
        self.netstat_results.setColumnCount(5)
        self.netstat_results.setHorizontalHeaderLabels(["Protocol", "Local Address", "Remote Address", "State", "Process"])
        self.netstat_results.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.netstat_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab

    def _create_bandwidth_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Control section
        control_group = QGroupBox("Bandwidth Monitor Controls")
        control_layout = QHBoxLayout()
        
        self.bandwidth_start_button = QPushButton("Start Monitoring")
        self.bandwidth_start_button.clicked.connect(self.toggle_bandwidth_monitoring)
        control_layout.addWidget(self.bandwidth_start_button)
        
        control_layout.addWidget(QLabel("Update Interval (seconds):"))
        self.bandwidth_interval = QSpinBox()
        self.bandwidth_interval.setRange(1, 10)
        self.bandwidth_interval.setValue(1)
        control_layout.addWidget(self.bandwidth_interval)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Results section
        results_group = QGroupBox("Bandwidth Usage")
        results_layout = QVBoxLayout()
        
        self.bandwidth_results = QTableWidget()
        self.bandwidth_results.setColumnCount(3)
        self.bandwidth_results.setHorizontalHeaderLabels(["Interface", "Download", "Upload"])
        self.bandwidth_results.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.bandwidth_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab
    
    def _create_nmap_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input section
        input_group = QGroupBox("Nmap Scan Configuration")
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Target:"), 0, 0)
        self.nmap_target_input = QLineEdit()
        self.nmap_target_input.setPlaceholderText("IP, hostname, or CIDR (e.g., 192.168.1.0/24)")
        input_layout.addWidget(self.nmap_target_input, 0, 1, 1, 3)
        
        input_layout.addWidget(QLabel("Ports:"), 1, 0)
        self.nmap_ports_input = QLineEdit()
        self.nmap_ports_input.setPlaceholderText("e.g., 22,80,443 or 1-1024")
        input_layout.addWidget(self.nmap_ports_input, 1, 1, 1, 3)
        
        input_layout.addWidget(QLabel("Scan Type:"), 2, 0)
        self.nmap_scan_type = QComboBox()
        self.nmap_scan_type.addItems([
            "Basic (-sV)", 
            "Intense (-sV -T4)",
            "Version Detection (-sV --version-all)",
            "Comprehensive (-sV -sC -A -T4)",
            "Stealth (-sS -T2)"
        ])
        input_layout.addWidget(self.nmap_scan_type, 2, 1, 1, 3)
        
        self.nmap_scan_button = QPushButton("Start Scan")
        self.nmap_scan_button.clicked.connect(self.start_nmap_scan)
        input_layout.addWidget(self.nmap_scan_button, 3, 0, 1, 4)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.nmap_results = QTextEdit()
        self.nmap_results.setReadOnly(True)
        results_layout.addWidget(self.nmap_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab

    def _create_packet_sniffer_tab(self):
        """Create the packet sniffer tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Control section
        control_group = QGroupBox("Packet Sniffer Configuration")
        control_layout = QGridLayout()
        
        # Interface selection
        control_layout.addWidget(QLabel("Network Interface:"), 0, 0)
        self.packet_interface = QComboBox()
        self.packet_interface.addItem("Auto-detect")
        
        # Populate interfaces (we'll do this in showEvent)
        control_layout.addWidget(self.packet_interface, 0, 1, 1, 3)
        
        # Protocol filter
        control_layout.addWidget(QLabel("Protocol Filter:"), 1, 0)
        self.packet_protocol = QComboBox()
        self.packet_protocol.addItems(["All Protocols", "TCP", "UDP", "ICMP"])
        control_layout.addWidget(self.packet_protocol, 1, 1)
        
        # IP filter
        control_layout.addWidget(QLabel("IP Filter:"), 2, 0)
        self.packet_ip = QLineEdit()
        self.packet_ip.setPlaceholderText("Optional: Filter by IP address")
        control_layout.addWidget(self.packet_ip, 2, 1, 1, 3)
        
        # Port filter
        control_layout.addWidget(QLabel("Port Filter:"), 3, 0)
        self.packet_port = QSpinBox()
        self.packet_port.setRange(0, 65535)
        self.packet_port.setValue(0)
        self.packet_port.setSpecialValueText("None")
        control_layout.addWidget(self.packet_port, 3, 1)
        
        # Save to file option
        control_layout.addWidget(QLabel("Save to File:"), 4, 0)
        self.packet_save = QCheckBox("Save captured packets to file")
        control_layout.addWidget(self.packet_save, 4, 1)
        
        self.packet_file = QPushButton("Select File...")
        self.packet_file.setEnabled(False)
        self.packet_file.clicked.connect(self.select_packet_file)
        control_layout.addWidget(self.packet_file, 4, 2)
        
        # Connect checkbox to enable/disable file button
        self.packet_save.stateChanged.connect(
            lambda state: self.packet_file.setEnabled(state == Qt.Checked)
        )
        
        # Start/Stop buttons
        self.packet_start = QPushButton("Start Capturing")
        self.packet_start.clicked.connect(self.start_packet_capture)
        control_layout.addWidget(self.packet_start, 5, 0, 1, 2)
        
        self.packet_clear = QPushButton("Clear Results")
        self.packet_clear.clicked.connect(self.clear_packet_results)
        control_layout.addWidget(self.packet_clear, 5, 2, 1, 2)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Packet display
        results_group = QGroupBox("Captured Packets")
        results_layout = QVBoxLayout()
        
        self.packet_count = QLabel("No packets captured yet")
        results_layout.addWidget(self.packet_count)
        
        self.packet_results = QTextEdit()
        self.packet_results.setReadOnly(True)
        results_layout.addWidget(self.packet_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Store the output file path
        self.packet_output_file = None
        self.packet_output_handle = None
        
        return tab

    def _create_wireless_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input section
        input_group = QGroupBox("Wi-Fi Scanner Configuration")
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.wifi_interface_input = QComboBox()
        self.wifi_interface_input.addItem("Auto-detect")
        input_layout.addWidget(self.wifi_interface_input, 0, 1, 1, 3)
        
        self.wifi_scan_button = QPushButton("Scan Networks")
        self.wifi_scan_button.clicked.connect(self.scan_wifi)
        input_layout.addWidget(self.wifi_scan_button, 1, 0, 1, 4)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Discovered Networks")
        results_layout = QVBoxLayout()
        
        self.wifi_results = QTableWidget()
        self.wifi_results.setColumnCount(4)
        self.wifi_results.setHorizontalHeaderLabels(["SSID", "BSSID", "Channel", "Signal"])
        self.wifi_results.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.wifi_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab

    # Port scanner functions
    def scan_ports(self):
        target = self.port_target_input.text()
        start_port = self.start_port_input.value()
        end_port = self.end_port_input.value()
        
        if not target:
            self.port_results.setText("Please enter a target IP address or hostname.")
            return
        
        if start_port > end_port:
            self.port_results.setText("Start port must be less than or equal to end port.")
            return
        
        # Disable scan button and reset progress
        self.scan_button.setEnabled(False)
        self.port_progress.setValue(0)
        self.port_results.setText(f"Scanning {target} for open ports from {start_port} to {end_port}...\n")
        self.port_progress_label.setText("Initializing scan...")
        
        # Create loading spinner animation
        if self.port_spinner:
            self.port_spinner.stop()
        self.port_spinner = self.anim.loading_spinner(self.port_results, 30)
        self.port_spinner.move(self.port_results.width() // 2 - 15, 80)
        self.port_spinner.show()
        
        # Create button click animation
        self.anim.button_click_effect(self.scan_button)
        
        # Create and start the thread
        self.port_thread = PortScanThread(target, start_port, end_port)
        self.port_thread.update_signal.connect(self.handle_port_scan_results)
        self.port_thread.progress_signal.connect(self.update_port_scan_progress)
        self.port_thread.start()
    
    def update_port_scan_progress(self, current, total, open_count):
        """Update the progress bar and label during port scan."""
        percentage = int((current / total) * 100)
        self.port_progress.setValue(percentage)
        self.port_progress_label.setText(
            f"Scanning port {current} of {total} ({percentage}%) - {open_count} open ports found"
        )
    
    def handle_port_scan_results(self, results):
        """Handle port scan completion."""
        self.scan_button.setEnabled(True)
        self.port_progress.setValue(100)
        self.port_progress_label.setText("Scan complete")
        
        # Stop the spinner animation
        if self.port_spinner:
            self.port_spinner.stop()
            self.port_spinner = None
            
        # Apply a success animation to the results area
        self.anim.fade_in(self.port_results, 300)
        
        if isinstance(results, dict) and "error" in results:
            self.port_results.setText(f"Error: {results['error']}")
        elif not results:
            self.port_results.setText(
                f"No open ports found on {self.port_target_input.text()} "
                f"in range {self.start_port_input.value()}-{self.end_port_input.value()}."
            )
        else:
            result_text = f"Open ports on {self.port_target_input.text()}:\n\n"
            result_text += "Port\tService\n"
            result_text += "----\t-------\n"
            
            for port, service in sorted(results.items()):
                result_text += f"{port}\t{service}\n"
            
            self.port_results.setText(result_text)
    
    # Ping functions
    def ping_target(self):
        target = self.ping_target_input.text()
        count = self.ping_count_input.value()
        
        if not target:
            self.ping_results.setText("Please enter a target IP address or hostname.")
            return
        
        self.ping_button.setEnabled(False)
        self.ping_results.setText(f"Pinging {target} with {count} packets...\n\n")
        
        # Add loading spinner and button animation
        if self.ping_spinner:
            self.ping_spinner.stop()
        self.ping_spinner = self.anim.loading_spinner(self.ping_results, 30)
        self.ping_spinner.move(self.ping_results.width() // 2 - 15, 80)
        self.ping_spinner.show()
        
        # Animate button click
        self.anim.button_click_effect(self.ping_button)
        
        # Create and start the thread
        self.ping_thread = PingThread(target, count)
        self.ping_thread.update_signal.connect(self.handle_ping_results)
        self.ping_thread.start()
    
    def handle_ping_results(self, results):
        """Handle ping operation completion."""
        self.ping_button.setEnabled(True)
        
        # Stop and remove the spinner
        if self.ping_spinner:
            self.ping_spinner.stop()
            self.ping_spinner = None
            
        # Apply a fade-in animation to the results
        self.anim.fade_in(self.ping_results, 300)
        
        if "error" in results:
            self.ping_results.setText(f"Error: {results['error']}")
            return
            
        # Format ping results
        output = f"Ping results for {self.ping_target_input.text()}:\n\n"
        output += f"Packets sent: {results['sent']}\n"
        output += f"Packets received: {results['received']}\n"
        output += f"Packet loss: {results['loss']}%\n\n"
        
        if results['times']:
            output += f"Minimum RTT: {min(results['times']):.2f} ms\n"
            output += f"Maximum RTT: {max(results['times']):.2f} ms\n"
            output += f"Average RTT: {sum(results['times']) / len(results['times']):.2f} ms\n\n"
            
        output += "Individual responses:\n"
        for i, resp in enumerate(results.get('responses', [])):
            output += f"  {i+1}: {resp}\n"
            
        self.ping_results.setText(output)
    
    # Traceroute functions
    def trace_target(self):
        target = self.trace_target_input.text()
        max_hops = self.trace_hops_input.value()
        
        if not target:
            self.trace_results.setText("Please enter a target IP address or hostname.")
            return
        
        self.trace_button.setEnabled(False)
        self.trace_results.setText(f"Tracing route to {target} with maximum {max_hops} hops...\n\n")
        
        # Add loading spinner and button animation
        if self.trace_spinner:
            self.trace_spinner.stop()
        self.trace_spinner = self.anim.loading_spinner(self.trace_results, 30)
        self.trace_spinner.move(self.trace_results.width() // 2 - 15, 80)
        self.trace_spinner.show()
        
        # Animate button click
        self.anim.button_click_effect(self.trace_button)
        
        # Create and start the thread
        self.trace_thread = TracerouteThread(target, max_hops)
        self.trace_thread.update_signal.connect(self.handle_trace_results)
        self.trace_thread.start()
    
    def handle_trace_results(self, results):
        """Handle traceroute operation completion."""
        self.trace_button.setEnabled(True)
        
        # Stop and remove the spinner
        if self.trace_spinner:
            self.trace_spinner.stop()
            self.trace_spinner = None
            
        # Apply a fade-in animation to the results
        self.anim.fade_in(self.trace_results, 300)
        
        if results and "error" in results[0]:
            self.trace_results.setText(f"Error: {results[0]['error']}")
            return
            
        # Format traceroute results
        output = f"Traceroute to {self.trace_target_input.text()}:\n\n"
        output += f"{'Hop':<5} {'IP':<20} {'RTT (ms)':<15} {'Hostname':<30}\n"
        output += "-" * 70 + "\n"
        
        for hop in results:
            output += f"{hop['hop']:<5} {hop['ip']:<20} {hop['rtt']:<15.2f} {hop['hostname']:<30}\n"
            
        self.trace_results.setText(output)
    
    # ARP scanner functions
    def scan_arp(self):
        network = self.arp_network_input.text()
        
        if not network:
            # Set a message in the table
            self.arp_results.setRowCount(1)
            self.arp_results.setItem(0, 0, QTableWidgetItem("Please enter a network in CIDR notation (e.g., 192.168.1.0/24)"))
            self.arp_results.setSpan(0, 0, 1, 3)
            return
        
        self.arp_scan_button.setEnabled(False)
        self.arp_results.setRowCount(1)
        self.arp_results.setItem(0, 0, QTableWidgetItem(f"Scanning network {network} for devices..."))
        self.arp_results.setSpan(0, 0, 1, 3)
        
        # Add loading spinner and button animation
        if self.arp_spinner:
            self.arp_spinner.stop()
        self.arp_spinner = self.anim.loading_spinner(self.arp_results, 30)
        self.arp_spinner.move(self.arp_results.width() // 2 - 15, 
                             self.arp_results.height() // 2 - 15)
        self.arp_spinner.show()
        
        # Animate button click
        self.anim.button_click_effect(self.arp_scan_button)
        
        # Create and start the thread
        self.arp_thread = ArpScanThread(network)
        self.arp_thread.update_signal.connect(self.handle_arp_results)
        self.arp_thread.start()
    
    def handle_arp_results(self, results):
        """Handle ARP scan completion."""
        self.arp_scan_button.setEnabled(True)
        
        # Stop and remove the spinner
        if self.arp_spinner:
            self.arp_spinner.stop()
            self.arp_spinner = None
        
        if isinstance(results, dict) and "error" in results:
            self.arp_results.setRowCount(1)
            self.arp_results.setItem(0, 0, QTableWidgetItem(f"Error: {results['error']}"))
            self.arp_results.setSpan(0, 0, 1, 3)
        elif not results:
            self.arp_results.setRowCount(1)
            self.arp_results.setItem(0, 0, QTableWidgetItem(f"No devices found on network {self.arp_network_input.text()}."))
            self.arp_results.setSpan(0, 0, 1, 3)
        else:
            # Display results in table with a fade-in animation
            self.arp_results.setRowCount(len(results))
            self.arp_results.clearSpans()  # Remove any span
            
            # Hide table temporarily for animation
            self.arp_results.setVisible(False)
            
            for i, device in enumerate(results):
                self.arp_results.setItem(i, 0, QTableWidgetItem(device.get('ip', '')))
                self.arp_results.setItem(i, 1, QTableWidgetItem(device.get('mac', '')))
                self.arp_results.setItem(i, 2, QTableWidgetItem(''))  # No hostname in results
            
            # Show table with fade-in animation
            self.arp_results.setVisible(True)
            self.anim.fade_in(self.arp_results, 300)
    
    # Netstat functions
    def refresh_netstat(self):
        """Refresh netstat data using a thread."""
        # Prevent multiple simultaneous refreshes
        if self.netstat_updating:
            return
            
        self.netstat_updating = True
        self.netstat_refresh_button.setEnabled(False)
        
        # Create and start the thread
        self.netstat_thread = NetstatThread()
        self.netstat_thread.update_signal.connect(self.handle_netstat_results)
        self.netstat_thread.start()
    
    def update_netstat(self):
        """Called when the filter changes to refresh the netstat view with the current filter."""
        self.refresh_netstat()
    
    def toggle_netstat_refresh(self, checked):
        if checked:
            self.netstat_timer.start()  # Using interval set in __init__
            self.netstat_auto_refresh.setText("Stop Auto Refresh")
        else:
            self.netstat_timer.stop()
            self.netstat_auto_refresh.setText("Auto Refresh")
    
    def handle_netstat_results(self, connections):
        """Handle netstat data update."""
        self.netstat_refresh_button.setEnabled(True)
        self.netstat_updating = False
        
        try:
            if isinstance(connections, list) and connections and "error" in connections[0]:
                self.netstat_results.setRowCount(1)
                self.netstat_results.setItem(0, 0, QTableWidgetItem(f"Error: {connections[0]['error']}"))
                self.netstat_results.setSpan(0, 0, 1, 5)
                return
            
            # Filter connections based on selected filter
            filter_index = self.netstat_filter.currentIndex()
            if filter_index == 1:  # Listening Only
                connections = [conn for conn in connections if conn.get("state") in ["LISTEN", "LISTENING"]]
            elif filter_index == 2:  # Established Only
                connections = [conn for conn in connections if conn.get("state") == "ESTABLISHED"]
            
            if not connections:
                self.netstat_results.setRowCount(1)
                self.netstat_results.setItem(0, 0, QTableWidgetItem("No connections match the selected filter."))
                self.netstat_results.setSpan(0, 0, 1, 5)
                return
            
            # Display results in table
            self.netstat_results.setRowCount(len(connections))
            self.netstat_results.clearSpans()  # Remove any span
            
            for i, conn in enumerate(connections):
                if not isinstance(conn, dict):
                    continue
                    
                self.netstat_results.setItem(i, 0, QTableWidgetItem(conn.get("proto", "")))
                self.netstat_results.setItem(i, 1, QTableWidgetItem(conn.get("local_address", "")))
                self.netstat_results.setItem(i, 2, QTableWidgetItem(conn.get("remote_address", "")))
                self.netstat_results.setItem(i, 3, QTableWidgetItem(conn.get("state", "")))
                
                process = ""
                if "pid" in conn and "process" in conn:
                    process = f"{conn['pid']} ({conn['process']})"
                self.netstat_results.setItem(i, 4, QTableWidgetItem(process))
                
        except Exception as e:
            self.netstat_results.setRowCount(1)
            self.netstat_results.setItem(0, 0, QTableWidgetItem(f"Error: {str(e)}"))
            self.netstat_results.setSpan(0, 0, 1, 5)
    
    # Bandwidth monitor functions
    def toggle_bandwidth_monitoring(self):
        if self.bandwidth_start_button.text() == "Start Monitoring":
            interval = self.bandwidth_interval.value()
            
            if self.bandwidth_monitor.start_monitoring(interval, self.update_bandwidth_callback):
                self.bandwidth_start_button.setText("Stop Monitoring")
                self.bandwidth_timer.start(interval * 1000)
        else:
            self.bandwidth_monitor.stop_monitoring()
            self.bandwidth_timer.stop()
            self.bandwidth_start_button.setText("Start Monitoring")
    
    def update_bandwidth(self):
        # This function is called by the timer
        # The actual updates are handled by the callback
        pass
    
    def update_bandwidth_callback(self, stats):
        """Callback function for bandwidth monitor updates."""
        try:
            if not stats:
                self.bandwidth_results.setRowCount(1)
                self.bandwidth_results.setItem(0, 0, QTableWidgetItem("No network interfaces detected."))
                self.bandwidth_results.setSpan(0, 0, 1, 3)
                return
            
            # Display results in table
            self.bandwidth_results.setRowCount(len(stats))
            self.bandwidth_results.clearSpans()  # Remove any span
            
            for i, (interface, data) in enumerate(stats.items()):
                self.bandwidth_results.setItem(i, 0, QTableWidgetItem(interface))
                self.bandwidth_results.setItem(i, 1, QTableWidgetItem(data.get("download", "0 B/s")))
                self.bandwidth_results.setItem(i, 2, QTableWidgetItem(data.get("upload", "0 B/s")))
                
        except Exception as e:
            self.bandwidth_results.setRowCount(1)
            self.bandwidth_results.setItem(0, 0, QTableWidgetItem(f"Error: {str(e)}"))
            self.bandwidth_results.setSpan(0, 0, 1, 3)
    
    # Nmap scanner functions
    def start_nmap_scan(self):
        target = self.nmap_target_input.text()
        ports = self.nmap_ports_input.text()
        
        if not target:
            self.nmap_results.setText("Please enter a target IP address, hostname, or network range.")
            return
        
        # Get the selected scan type arguments
        scan_type = self.nmap_scan_type.currentText()
        if "Basic" in scan_type:
            args = "-sV"
        elif "Intense" in scan_type:
            args = "-sV -T4"
        elif "Version" in scan_type:
            args = "-sV --version-all"
        elif "Comprehensive" in scan_type:
            args = "-sV -sC -A -T4"
        elif "Stealth" in scan_type:
            args = "-sS -T2"
        else:
            args = "-sV"
            
        # Add port specification if provided
        if ports:
            args += f" -p {ports}"
        
        self.nmap_scan_button.setEnabled(False)
        self.nmap_results.setText(f"Starting Nmap scan on {target}...\n\n")
        
        # Add loading spinner and button animation
        if self.nmap_spinner:
            self.nmap_spinner.stop()
        self.nmap_spinner = self.anim.loading_spinner(self.nmap_results, 40)  # Larger spinner for Nmap
        self.nmap_spinner.move(self.nmap_results.width() // 2 - 20, 
                              self.nmap_results.height() // 2 - 20)
        self.nmap_spinner.show()
        
        # Animate button click
        self.anim.button_click_effect(self.nmap_scan_button)
        
        # Create and start the thread
        self.nmap_thread = NmapScanThread(target, ports, args)
        self.nmap_thread.update_signal.connect(self.handle_nmap_results)
        self.nmap_thread.start()
    
    def handle_nmap_results(self, results):
        """Handle Nmap scan completion."""
        self.nmap_scan_button.setEnabled(True)
        
        # Stop loading spinner
        if self.nmap_spinner:
            self.nmap_spinner.stop()
            self.nmap_spinner = None
            
        # Apply fade-in animation to results
        self.anim.fade_in(self.nmap_results, 300)
        
        if "error" in results:
            self.nmap_results.setText(f"Error during scan: {results['error']}")
            # If error, add a shake animation to indicate failure
            self.anim.shake(self.nmap_results)
            return
            
        # Display the raw output directly with success animation
        self.nmap_results.setText(results.get('output', "No scan output returned"))
    
    def select_packet_file(self):
        """Select a file to save packets to."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Packets To", "", "Text Files (*.txt);;All Files (*.*)"
        )
        
        if file_path:
            self.packet_output_file = file_path
            self.packet_file.setText(f"File: {os.path.basename(file_path)}")
        else:
            self.packet_output_file = None
            self.packet_file.setText("Select File...")
    
    def start_packet_capture(self):
        """Start or stop packet capture."""
        if self.packet_start.text() == "Start Capturing":
            # Get interface
            interface = None
            if self.packet_interface.currentIndex() > 0:
                interface = self.packet_interface.currentText()
            
            # Get filters
            protocols = []
            if self.packet_protocol.currentIndex() > 0:  # Not "All Protocols"
                protocols = [self.packet_protocol.currentText()]
            
            ips = []
            if self.packet_ip.text().strip():
                ips = [self.packet_ip.text().strip()]
            
            ports = []
            if self.packet_port.value() > 0:
                ports = [self.packet_port.value()]
            
            # Open output file if needed
            if self.packet_save.isChecked() and self.packet_output_file:
                try:
                    self.packet_output_handle = open(self.packet_output_file, 'w')
                    self.packet_output_handle.write(f"Packet capture started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    self.packet_output_handle.flush()
                except Exception as e:
                    self.packet_results.append(f"Error opening output file: {str(e)}")
                    return
            
            # Create and start the thread
            self.packet_thread = PacketSnifferThread(interface, protocols, ips, ports)
            self.packet_thread.packet_signal.connect(self.handle_packet)
            self.packet_thread.error_signal.connect(self.handle_packet_error)
            self.packet_thread.stopped_signal.connect(self.on_packet_capture_stopped)
            self.packet_thread.start()
            
            # Update UI
            self.packet_start.setText("Stop Capturing")
            self.packet_results.clear()
            self.packet_results.append("Starting packet capture...\n")
            self.packet_count.setText("Packets captured: 0")
            
            # Disable configuration controls during capture
            self.packet_interface.setEnabled(False)
            self.packet_protocol.setEnabled(False)
            self.packet_ip.setEnabled(False)
            self.packet_port.setEnabled(False)
            self.packet_save.setEnabled(False)
            self.packet_file.setEnabled(False)
            
            # Add a spinner animation
            self.packet_spinner = self.anim.loading_spinner(self.packet_results, 30)
            self.packet_spinner.move(self.packet_results.width() - 50, 20)
            self.packet_spinner.show()
        else:
            # Stop the capture
            if self.packet_thread and self.packet_thread.isRunning():
                self.packet_thread.stop()
                self.packet_results.append("\nStopping packet capture...")
    
    def handle_packet(self, packet):
        """Handle a captured packet."""
        # Get packet count from text
        count_text = self.packet_count.text()
        if "captured:" in count_text:
            count = int(count_text.split("captured:")[1].strip())
            count += 1
            self.packet_count.setText(f"Packets captured: {count}")
        
        # Format the packet
        if self.packet_thread and self.packet_thread.sniffer:
            packet_text = self.packet_thread.sniffer.format_packet(packet, include_data=True)
            self.packet_results.append("\n" + "=" * 70)
            self.packet_results.append(packet_text)
            
            # Save to file if needed
            if self.packet_output_handle:
                self.packet_output_handle.write("=" * 70 + "\n")
                self.packet_output_handle.write(packet_text + "\n\n")
                self.packet_output_handle.flush()
    
    def handle_packet_error(self, error_msg):
        """Handle packet capture error."""
        self.packet_results.append(f"\nError: {error_msg}")
        
        # Reset UI
        self.packet_start.setText("Start Capturing")
        self.packet_interface.setEnabled(True)
        self.packet_protocol.setEnabled(True)
        self.packet_ip.setEnabled(True)
        self.packet_port.setEnabled(True)
        self.packet_save.setEnabled(True)
        if self.packet_save.isChecked():
            self.packet_file.setEnabled(True)
            
        # Stop spinner
        if hasattr(self, 'packet_spinner') and self.packet_spinner:
            self.packet_spinner.stop()
            
        # Close file if open
        if self.packet_output_handle:
            self.packet_output_handle.close()
            self.packet_output_handle = None
    
    def on_packet_capture_stopped(self):
        """Called when packet capture is stopped cleanly."""
        self.packet_results.append("\nPacket capture complete.")
        
        # Reset UI
        self.packet_start.setText("Start Capturing")
        self.packet_interface.setEnabled(True)
        self.packet_protocol.setEnabled(True)
        self.packet_ip.setEnabled(True)
        self.packet_port.setEnabled(True)
        self.packet_save.setEnabled(True)
        if self.packet_save.isChecked():
            self.packet_file.setEnabled(True)
            
        # Stop spinner
        if hasattr(self, 'packet_spinner') and self.packet_spinner:
            self.packet_spinner.stop()
            
        # Close file if open
        if self.packet_output_handle:
            self.packet_output_handle.close()
            self.packet_output_handle = None
    
    def clear_packet_results(self):
        """Clear packet capture results."""
        self.packet_results.clear()
        self.packet_count.setText("No packets captured yet")
    
    def showEvent(self, event):
        """Called when the widget is shown."""
        super().showEvent(event)
        
        # Populate packet sniffer interface dropdown
        try:
            # Only populate if it's currently empty
            if self.packet_interface.count() <= 1:
                sniffer = PacketSniffer()
                interfaces = sniffer.get_available_interfaces()
                
                if interfaces:
                    self.packet_interface.clear()
                    self.packet_interface.addItem("Auto-detect")
                    self.packet_interface.addItems(interfaces)
        except Exception as e:
            print(f"Error populating interfaces: {str(e)}")
    
    def cleanup(self):
        """Clean up resources when tab is closed."""
        # Stop packet sniffer if running
        if self.packet_thread and self.packet_thread.isRunning():
            self.packet_thread.stop()
            self.packet_thread.wait()
        
        # Close any open file
        if self.packet_output_handle:
            self.packet_output_handle.close()
            self.packet_output_handle = None
        
        # Call the original cleanup
        if hasattr(super(), 'cleanup'):
            super().cleanup()
    
    def scan_wifi(self):
        """Scan for wireless networks."""
        # Get selected interface
        interface = None
        if self.wifi_interface_input.currentIndex() > 0:
            interface = self.wifi_interface_input.currentText()
        
        # Disable scan button during scan
        self.wifi_scan_button.setEnabled(False)
        
        # Clear and set a message in the table
        self.wifi_results.clearSelection()
        self.wifi_results.setRowCount(1)
        self.wifi_results.setColumnCount(1)
        self.wifi_results.horizontalHeader().setVisible(False)
        self.wifi_results.setItem(0, 0, QTableWidgetItem("Scanning for wireless networks..."))
        self.wifi_results.setSpan(0, 0, 1, 1)
        
        # Add loading spinner and button animation
        wifi_spinner = self.anim.loading_spinner(self.wifi_results, 30)
        wifi_spinner.move(self.wifi_results.width() // 2 - 15, 
                          self.wifi_results.height() // 2 - 15)
        wifi_spinner.show()
        
        # Animate button click
        self.anim.button_click_effect(self.wifi_scan_button)
        
        # Create and start the thread
        self.wifi_thread = WirelessScanThread(interface)
        self.wifi_thread.update_signal.connect(self.handle_wifi_results)
        self.wifi_thread.error_signal.connect(self.handle_wifi_error)
        self.wifi_thread.start()
    
    def handle_wifi_results(self, networks):
        """Handle Wi-Fi scan completion."""
        # Restore the table structure
        self.wifi_results.clearSpans()
        self.wifi_results.setColumnCount(5)  # Added a column for security rating
        self.wifi_results.setHorizontalHeaderLabels(
            ["SSID", "Security", "Signal", "Channel", "Details"]
        )
        self.wifi_results.horizontalHeader().setVisible(True)
        self.wifi_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        # Enable the scan button
        self.wifi_scan_button.setEnabled(True)
        
        if not networks:
            self.wifi_results.setRowCount(1)
            self.wifi_results.setItem(0, 0, QTableWidgetItem("No wireless networks found"))
            self.wifi_results.setSpan(0, 0, 1, 5)
            return
        
        # Display results in table
        self.wifi_results.setRowCount(len(networks))
        
        # Sort networks by signal strength
        networks.sort(key=lambda x: x.get('signal', 0), reverse=True)
        
        # Create scanner for security rating
        scanner = WirelessScanner()
        
        for i, network in enumerate(networks):
            # Basic information
            ssid = network.get('ssid', '<Hidden>')
            security = network.get('security_full', network.get('security', 'Unknown'))
            signal = f"{network.get('signal', 0)}%"
            channel = network.get('channel', 'N/A')
            
            # Create items with tooltip showing details
            ssid_item = QTableWidgetItem(ssid)
            security_item = QTableWidgetItem(security)
            signal_item = QTableWidgetItem(signal)
            channel_item = QTableWidgetItem(str(channel))
            
            # Get security rating
            rating, desc = scanner.get_security_rating(security)
            details_item = QTableWidgetItem(f"Rating: {rating}/5")
            details_item.setToolTip(desc)
            
            # Set tooltip with additional info if available
            bssid = network.get('bssid', 'N/A')
            details = f"BSSID: {bssid}\nSecurity: {security}\nRating: {rating}/5 - {desc}"
            if 'frequency' in network:
                details += f"\nFrequency: {network['frequency']} MHz"
            
            ssid_item.setToolTip(details)
            
            # Color-code security rating
            if rating <= 1:  # Very poor (Open, WEP)
                security_item.setBackground(Qt.red)
            elif rating == 2:  # Poor (WPA1)
                security_item.setBackground(Qt.yellow)
            elif rating == 3:  # Moderate (WPA2-TKIP)
                security_item.setBackground(Qt.cyan)
            elif rating >= 4:  # Good/Excellent (WPA2-AES, WPA3)
                security_item.setBackground(Qt.green)
            
            # Add items to table
            self.wifi_results.setItem(i, 0, ssid_item)
            self.wifi_results.setItem(i, 1, security_item)
            self.wifi_results.setItem(i, 2, signal_item)
            self.wifi_results.setItem(i, 3, channel_item)
            self.wifi_results.setItem(i, 4, details_item)
        
        # Apply a fade-in animation to the table
        self.anim.fade_in(self.wifi_results, 300)
    
    def handle_wifi_error(self, error_msg):
        """Handle Wi-Fi scan error."""
        # Restore the table structure
        self.wifi_results.clearSpans()
        self.wifi_results.setColumnCount(5)
        self.wifi_results.setHorizontalHeaderLabels(
            ["SSID", "Security", "Signal", "Channel", "Details"]
        )
        self.wifi_results.horizontalHeader().setVisible(True)
        
        # Display error message
        self.wifi_results.setRowCount(1)
        self.wifi_results.setItem(0, 0, QTableWidgetItem(f"Error: {error_msg}"))
        self.wifi_results.setSpan(0, 0, 1, 5)
        
        # Enable the scan button
        self.wifi_scan_button.setEnabled(True)
