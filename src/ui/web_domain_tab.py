from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel, QPushButton, 
                          QLineEdit, QTextEdit, QGroupBox, QComboBox, QTableWidget,
                          QTableWidgetItem, QHeaderView, QProgressBar, QHBoxLayout)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class DNSLookupThread(QThread):
    """Thread for DNS lookup operations without blocking the UI."""
    result_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)
    
    def __init__(self, domain, record_type="A"):
        super().__init__()
        self.domain = domain
        self.record_type = record_type
        
    def run(self):
        try:
            from src.tools.web_domain.dns_lookup import DNSLookup
            import json
            
            dns_tool = DNSLookup()
            
            if self.record_type == "ANY":
                # Get all common record types
                results = dns_tool.get_dns_records(self.domain)
            else:
                # Get specific record type
                results = dns_tool.get_dns_records(self.domain, [self.record_type])
            
            # Format the results for display in the UI
            formatted_results = {'records': []}
            
            if 'records' in results and results['records']:
                for record_type, values in results['records'].items():
                    for value in values:
                        formatted_results['records'].append({
                            'type': record_type,
                            'value': value,
                            'ttl': 'N/A'  # TTL isn't directly provided
                        })
            
            self.result_signal.emit(formatted_results)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.error_signal.emit(str(e))


class WhoisLookupThread(QThread):
    """Thread for Whois lookup operations without blocking the UI."""
    result_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
        
    def run(self):
        try:
            from src.tools.web_domain.whois_lookup import WhoisLookup
            import traceback
            
            whois_tool = WhoisLookup()
            result = whois_tool.lookup(self.domain)
            
            # Format result to match the expected format in the UI handler
            formatted_result = {}
            
            if result.get('status') == 'success':
                data = result.get('data', {})
                # Extract raw data for display
                formatted_result['raw'] = data.get('raw_data', 'No raw data available')
                
                # Extract important info for structured display
                formatted_result['info'] = {
                    'domain_name': data.get('domain_name', 'Unknown'),
                    'registrar': data.get('registrar', 'Unknown'),
                    'creation_date': data.get('creation_date', 'Unknown'),
                    'expiration_date': data.get('expiration_date', 'Unknown'),
                    'name_servers': data.get('name_servers', []),
                    'status': data.get('status', []),
                    'registrant_name': data.get('registrant_name', 'Unknown'),
                    'registrant_organization': data.get('registrant_organization', 'Unknown'),
                    'registrant_country': data.get('registrant_country', 'Unknown')
                }
            else:
                error_msg = result.get('error', 'Unknown error')
                self.error_signal.emit(error_msg)
                return
                
            self.result_signal.emit(formatted_result)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.error_signal.emit(str(e))


class WebDomainTab(QWidget):
    def __init__(self):
        super().__init__()
        
        # Create main layout
        self.layout = QVBoxLayout(self)
        
        # Create DNS lookup section
        self.dns_group = self._create_dns_lookup_section()
        self.layout.addWidget(self.dns_group)
        
        # Create WHOIS lookup section
        self.whois_group = self._create_whois_lookup_section()
        self.layout.addWidget(self.whois_group)
        
        # Initialize threads
        self.dns_thread = None
        self.whois_thread = None
        
        # Flag to track if tab is visible
        self.is_visible = False
    
    def _create_dns_lookup_section(self):
        """Create DNS lookup section."""
        group = QGroupBox("DNS Lookup")
        layout = QVBoxLayout()
        
        # Input fields
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Domain:"), 0, 0)
        self.dns_domain_input = QLineEdit()
        self.dns_domain_input.setPlaceholderText("example.com")
        input_layout.addWidget(self.dns_domain_input, 0, 1)
        
        input_layout.addWidget(QLabel("Record Type:"), 1, 0)
        self.dns_record_type = QComboBox()
        self.dns_record_type.addItems(["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "ANY"])
        input_layout.addWidget(self.dns_record_type, 1, 1)
        
        self.dns_lookup_button = QPushButton("Lookup")
        self.dns_lookup_button.clicked.connect(self.perform_dns_lookup)
        input_layout.addWidget(self.dns_lookup_button, 2, 1)
        
        layout.addLayout(input_layout)
        
        # Results table
        self.dns_results_table = QTableWidget(0, 3)
        self.dns_results_table.setHorizontalHeaderLabels(["Record Type", "Value", "TTL"])
        
        # Set column widths
        header = self.dns_results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        
        # Optimize table for performance
        self.dns_results_table.setAlternatingRowColors(True)
        self.dns_results_table.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        self.dns_results_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        
        layout.addWidget(self.dns_results_table)
        
        # Status section
        status_layout = QHBoxLayout()
        
        self.dns_status_label = QLabel("Ready")
        status_layout.addWidget(self.dns_status_label)
        
        self.dns_progress_bar = QProgressBar()
        self.dns_progress_bar.setRange(0, 100)
        self.dns_progress_bar.setValue(0)
        self.dns_progress_bar.setVisible(False)
        status_layout.addWidget(self.dns_progress_bar)
        
        layout.addLayout(status_layout)
        
        group.setLayout(layout)
        return group
    
    def _create_whois_lookup_section(self):
        """Create WHOIS lookup section."""
        group = QGroupBox("WHOIS Lookup")
        layout = QVBoxLayout()
        
        # Input fields
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Domain:"), 0, 0)
        self.whois_domain_input = QLineEdit()
        self.whois_domain_input.setPlaceholderText("example.com")
        input_layout.addWidget(self.whois_domain_input, 0, 1)
        
        self.whois_lookup_button = QPushButton("Lookup")
        self.whois_lookup_button.clicked.connect(self.perform_whois_lookup)
        input_layout.addWidget(self.whois_lookup_button, 1, 1)
        
        layout.addLayout(input_layout)
        
        # Results text area
        self.whois_results = QTextEdit()
        self.whois_results.setReadOnly(True)
        layout.addWidget(self.whois_results)
        
        # Status section
        status_layout = QHBoxLayout()
        
        self.whois_status_label = QLabel("Ready")
        status_layout.addWidget(self.whois_status_label)
        
        self.whois_progress_bar = QProgressBar()
        self.whois_progress_bar.setRange(0, 100)
        self.whois_progress_bar.setValue(0)
        self.whois_progress_bar.setVisible(False)
        status_layout.addWidget(self.whois_progress_bar)
        
        layout.addLayout(status_layout)
        
        group.setLayout(layout)
        return group
    
    def perform_dns_lookup(self):
        """Perform DNS lookup in a separate thread."""
        domain = self.dns_domain_input.text().strip()
        if not domain:
            self.dns_status_label.setText("Error: Please enter a domain name")
            return
        
        record_type = self.dns_record_type.currentText()
        
        # Update UI
        self.dns_lookup_button.setEnabled(False)
        self.dns_status_label.setText(f"Looking up {record_type} records for {domain}...")
        self.dns_progress_bar.setVisible(True)
        self.dns_progress_bar.setValue(30)
        self.dns_results_table.setRowCount(0)
        
        # Start thread
        self.dns_thread = DNSLookupThread(domain, record_type)
        self.dns_thread.result_signal.connect(self.handle_dns_results)
        self.dns_thread.error_signal.connect(self.handle_dns_error)
        self.dns_thread.start()
    
    def handle_dns_results(self, results):
        """Handle DNS lookup results."""
        self.dns_progress_bar.setValue(100)
        
        # Clear previous results
        self.dns_results_table.setRowCount(0)
        
        if 'records' in results and results['records']:
            # Add results to the table
            for record in results['records']:
                row = self.dns_results_table.rowCount()
                self.dns_results_table.insertRow(row)
                
                # Add record type
                type_item = QTableWidgetItem(record.get('type', ''))
                self.dns_results_table.setItem(row, 0, type_item)
                
                # Add value
                value_item = QTableWidgetItem(str(record.get('value', '')))
                self.dns_results_table.setItem(row, 1, value_item)
                
                # Add TTL
                ttl_item = QTableWidgetItem(str(record.get('ttl', '')))
                self.dns_results_table.setItem(row, 2, ttl_item)
            
            self.dns_status_label.setText(f"Found {len(results['records'])} records")
        else:
            self.dns_status_label.setText("No records found")
        
        # Re-enable UI
        self.dns_lookup_button.setEnabled(True)
        self.dns_progress_bar.setVisible(False)
    
    def handle_dns_error(self, error):
        """Handle DNS lookup error."""
        self.dns_status_label.setText(f"Error: {error}")
        self.dns_progress_bar.setValue(0)
        self.dns_progress_bar.setVisible(False)
        self.dns_lookup_button.setEnabled(True)
    
    def perform_whois_lookup(self):
        """Perform WHOIS lookup in a separate thread."""
        domain = self.whois_domain_input.text().strip()
        if not domain:
            self.whois_status_label.setText("Error: Please enter a domain name")
            return
        
        # Update UI
        self.whois_lookup_button.setEnabled(False)
        self.whois_status_label.setText(f"Looking up WHOIS information for {domain}...")
        self.whois_progress_bar.setVisible(True)
        self.whois_progress_bar.setValue(30)
        self.whois_results.clear()
        
        # Start thread
        self.whois_thread = WhoisLookupThread(domain)
        self.whois_thread.result_signal.connect(self.handle_whois_results)
        self.whois_thread.error_signal.connect(self.handle_whois_error)
        self.whois_thread.start()
    
    def handle_whois_results(self, results):
        """Handle WHOIS lookup results."""
        self.whois_progress_bar.setValue(100)
        
        if 'raw' in results:
            # Display raw WHOIS output
            self.whois_results.setText(results['raw'])
            
            # Create a more structured display of important information
            if 'info' in results:
                info = results['info']
                structured_info = ""
                
                # Add key information in a structured format
                for key, value in info.items():
                    if value:  # Only show non-empty values
                        # Convert to string if it's not already
                        if isinstance(value, list):
                            value = ", ".join(str(v) for v in value)
                        
                        structured_info += f"{key.capitalize()}: {value}\n"
                
                if structured_info:
                    self.whois_results.setText(
                        f"=== KEY INFORMATION ===\n"
                        f"{structured_info}\n"
                        f"=== RAW WHOIS DATA ===\n"
                        f"{results['raw']}"
                    )
            
            self.whois_status_label.setText("WHOIS information retrieved successfully")
        else:
            self.whois_results.setText("No WHOIS information available")
            self.whois_status_label.setText("No information found")
        
        # Re-enable UI
        self.whois_lookup_button.setEnabled(True)
        self.whois_progress_bar.setVisible(False)
    
    def handle_whois_error(self, error):
        """Handle WHOIS lookup error."""
        self.whois_status_label.setText(f"Error: {error}")
        self.whois_progress_bar.setValue(0)
        self.whois_progress_bar.setVisible(False)
        self.whois_lookup_button.setEnabled(True)
        
    def cleanup(self):
        """Clean up resources when closing the tab."""
        # Stop any running threads
        if self.dns_thread and self.dns_thread.isRunning():
            self.dns_thread.terminate()
            self.dns_thread.wait()
            
        if self.whois_thread and self.whois_thread.isRunning():
            self.whois_thread.terminate()
            self.whois_thread.wait()
    
    # Add event handlers for tab visibility changes
    def showEvent(self, event):
        """Handle when the tab becomes visible"""
        super().showEvent(event)
        self.is_visible = True
        print("Web Domain tab is now visible")
        
        # Reset any UI elements that need refreshing
        self.dns_status_label.setText("Ready")
        self.whois_status_label.setText("Ready")
        
    def hideEvent(self, event):
        """Handle when the tab becomes hidden"""
        super().hideEvent(event)
        self.is_visible = False
        print("Web Domain tab is now hidden")
        
        # Clean up any ongoing operations
        self.cleanup()
    
    def initialize(self):
        """Initialize or re-initialize the tab when it becomes active."""
        print("Web Domain tab initializing...")
        
        # Reset DNS lookup section
        self.dns_status_label.setText("Ready")
        self.dns_progress_bar.setValue(0)
        self.dns_progress_bar.setVisible(False)
        self.dns_lookup_button.setEnabled(True)
        
        # Reset WHOIS lookup section
        self.whois_status_label.setText("Ready")
        self.whois_progress_bar.setValue(0)
        self.whois_progress_bar.setVisible(False)
        self.whois_lookup_button.setEnabled(True)
        
        # Kill any running threads
        self.cleanup()