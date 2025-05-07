from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel, QPushButton, 
                          QLineEdit, QTextEdit, QGroupBox, QComboBox, QTabWidget, 
                          QHBoxLayout, QFileDialog, QMessageBox, QTableWidget,
                          QTableWidgetItem, QHeaderView, QProgressBar, QCheckBox)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
import os
import time
import json

class ProcessMonitorThread(QThread):
    """Thread for monitoring processes without blocking the UI."""
    update_signal = pyqtSignal(list, str)
    error_signal = pyqtSignal(str)
    
    def __init__(self, filter_text="", sort_by="CPU Usage", limit=30):
        super().__init__() 
        self.filter_text = filter_text
        self.sort_by = sort_by
        self.running = True
        self.limit = limit
        self.cached_processes = []  # Cache for optimization
        self.last_update_time = 0
        
    def run(self):
        try:
            from src.tools.system.process_monitor import ProcessMonitor
            import datetime
            
            monitor = ProcessMonitor()
            
            # Only refresh the data we need for displayed columns to improve performance
            processes = monitor.get_process_list()
            
            # Filter processes
            if self.filter_text:
                processes = [p for p in processes if 
                            (self.filter_text in p.get('name', '').lower() or 
                            self.filter_text in str(p.get('pid', 0)) or 
                            self.filter_text in p.get('username', '').lower())]
            
            # Sort processes
            if self.sort_by == "CPU Usage":
                processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
            elif self.sort_by == "Memory Usage":
                processes.sort(key=lambda x: x.get('memory_percent', 0), reverse=True)
            elif self.sort_by == "Process ID":
                processes.sort(key=lambda x: x.get('pid', 0))
            elif self.sort_by == "Process Name":
                processes.sort(key=lambda x: x.get('name', '').lower())
            
            # Limit to specified number of processes for performance
            processes = processes[:self.limit]
            
            # Cache the processes
            self.cached_processes = processes
            self.last_update_time = time.time()
            
            # Get current time for display
            current_time = datetime.datetime.now().strftime("%H:%M:%S")
            
            # Emit signal with processes and time
            self.update_signal.emit(processes, current_time)
            
        except Exception as e:
            self.error_signal.emit(str(e))

class FileOperationThread(QThread):
    """Thread for file operations without blocking the UI."""
    result_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, str)  # percentage, message
    
    def __init__(self, operation, file_path, output_path=None, password=None):
        super().__init__()
        self.operation = operation  # 'create_baseline', 'verify_integrity', 'encrypt', 'decrypt'
        self.file_path = file_path
        self.output_path = output_path
        self.password = password
        
    def run(self):
        try:
            result = {}
            
            # Update progress (starting)
            self.progress_signal.emit(0, f"Starting {self.operation} operation...")
            
            if self.operation == 'create_baseline':
                from src.tools.system.file_integrity_checker import FileIntegrityChecker
                checker = FileIntegrityChecker()
                
                # Define a custom progress callback to report progress to the UI
                def progress_callback(percentage, message):
                    self.progress_signal.emit(percentage, message)
                
                # Generate baseline
                result = self._create_baseline(checker, progress_callback)
                
            elif self.operation == 'verify_integrity':
                from src.tools.system.file_integrity_checker import FileIntegrityChecker
                checker = FileIntegrityChecker()
                
                # Define a custom progress callback to report progress to the UI
                def progress_callback(percentage, message):
                    self.progress_signal.emit(percentage, message)
                
                # Verify integrity
                result = self._verify_integrity(checker, progress_callback)
                
            elif self.operation == 'encrypt' or self.operation == 'decrypt':
                from src.tools.crypto.file_encryption import FileEncryptionTool
                encryptor = FileEncryptionTool()
                
                if self.operation == 'encrypt':
                    result = encryptor.encrypt_file(
                        self.file_path, 
                        self.password, 
                        method='aes'
                    )
                else:  # decrypt
                    result = encryptor.decrypt_file(
                        self.file_path, 
                        self.password, 
                        method='aes'
                    )
            
            # Add operation info to result
            result['operation'] = self.operation
            
            # Update progress (completing)
            self.progress_signal.emit(100, "Operation completed successfully")
            
            # Emit signal with result
            self.result_signal.emit(result)
            
        except Exception as e:
            import traceback
            traceback.print_exc()  # Print the exception for debugging
            
            # Update progress (error)
            self.progress_signal.emit(0, f"Error: {str(e)}")
            
            self.result_signal.emit({
                'operation': self.operation,
                'error': str(e)
            })
    
    def _create_baseline(self, checker, progress_callback):
        """Create a file integrity baseline.""" 
        # Check if the path is a directory or file
        if os.path.isdir(self.file_path):
            # Add all files in the directory recursively
            total_files = self._count_files(self.file_path)
            found_files = 0
            
            # Create a separate callback that updates progress based on file count
            def directory_progress_callback(file_path):
                nonlocal found_files
                found_files += 1
                percentage = min(int((found_files / total_files) * 100), 99)
                progress_callback(percentage, f"Hashing {file_path}...")
            
            # Process directory (recursively) and gather files
            file_list = []
            for root, _, files in os.walk(self.file_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_list.append(file_path)
                    directory_progress_callback(file_path)
            
            # Initialize the database with the collected files
            db = {}
            for file_path in file_list:
                # Calculate the hash for each file
                hash_info = checker.calculate_file_hash(file_path)
                if 'error' not in hash_info:
                    db[file_path] = hash_info
            
            # Save the database to the output path
            with open(self.output_path, 'w') as f:
                json.dump(db, f, indent=2)
            
            return {
                'success': True,
                'files_processed': len(db),
                'output_path': self.output_path
            }
        else:
            # Calculate hash for single file
            progress_callback(50, f"Hashing {self.file_path}...")
            
            hash_info = checker.calculate_file_hash(self.file_path)
            
            if 'error' in hash_info:
                return {'error': hash_info['error']}
            
            # Save the hash info to the output path
            db = {self.file_path: hash_info}
            
            with open(self.output_path, 'w') as f:
                json.dump(db, f, indent=2)
            
            return {
                'success': True,
                'files_processed': 1,
                'output_path': self.output_path
            }
    
    def _verify_integrity(self, checker, progress_callback):
        """Verify file integrity against a baseline.""" 
        # Load the baseline file
        progress_callback(10, f"Loading baseline from {self.file_path}...")
        
        try:
            with open(self.file_path, 'r') as f:
                baseline_db = json.load(f)
        except Exception as e:
            return {'error': f"Could not load baseline file: {str(e)}"}
        
        # Verify each file in the baseline
        total_files = len(baseline_db)
        progress_callback(20, f"Verifying {total_files} files...")
        
        processed = 0
        changed_files = []
        missing_files = []
        
        for file_path, stored_info in baseline_db.items():
            # Check if file exists
            if not os.path.exists(file_path):
                missing_files.append(file_path)
                progress_callback(
                    20 + int((processed / total_files) * 70),
                    f"File missing: {file_path}"
                )
                processed += 1
                continue
            
            # Calculate current hash
            current_hash_info = checker.calculate_file_hash(file_path)
            
            if 'error' in current_hash_info:
                progress_callback(
                    20 + int((processed / total_files) * 70),
                    f"Error hashing: {file_path} - {current_hash_info['error']}"
                )
                processed += 1
                continue
            
            # Compare hashes
            if current_hash_info['hash'] != stored_info['hash']:
                changed_files.append(file_path)
                progress_callback(
                    20 + int((processed / total_files) * 70),
                    f"Changed file detected: {file_path}"
                )
            
            processed += 1
        
        # Check for new files in the directories from the baseline
        new_files = []
        directories = set()
        
        # Collect directories from baseline
        for file_path in baseline_db.keys():
            dir_path = os.path.dirname(file_path)
            if os.path.isdir(dir_path):
                directories.add(dir_path)
        
        # Check each directory for new files
        progress_callback(90, "Checking for new files...")
        
        for directory in directories:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        if file_path not in baseline_db:
                            new_files.append(file_path)
        
        return {
            'success': True,
            'total_files': total_files,
            'changed_files': changed_files,
            'missing_files': missing_files,
            'new_files': new_files
        }
    
    def _count_files(self, directory):
        """Count total files in a directory tree.""" 
        count = 0
        for root, _, files in os.walk(directory):
            count += len(files)
        return max(count, 1)  # Avoid division by zero

class SystemToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        
        # Initialize timer for process monitoring first
        self.process_timer = QTimer(self)
        self.process_timer.timeout.connect(self.update_process_list)
        
        # Create main layout
        self.layout = QVBoxLayout(self)
        
        # Create a tab widget for system tools
        self.tabs = QTabWidget()
        
        # Create individual tool tabs
        self.process_monitor_tab = self._create_process_monitor_tab()
        self.file_integrity_tab = self._create_file_integrity_tab()
        
        # Add tool tabs to tab widget
        self.tabs.addTab(self.process_monitor_tab, "Process Monitor")
        self.tabs.addTab(self.file_integrity_tab, "File Integrity")
        
        # Add tab widget to main layout
        self.layout.addWidget(self.tabs)
        
        # Initialize process monitoring thread
        self.process_thread = None
        
        # Initialize file operation thread
        self.file_operation_thread = None
        
        # Track if tab is visible to optimize resource usage
        self.is_visible = False
        
        # Initialize visibility change detection
        self.update_visibility()
    
    def update_visibility(self):
        """Update the visibility status and adjust resource usage accordingly"""
        was_visible = self.is_visible
        self.is_visible = self.isVisible()
        
        # If visibility changed from visible to not visible
        if was_visible and not self.is_visible:
            # Stop resource-intensive operations
            if self.process_timer.isActive():
                self.process_timer.stop()
        
        # If visibility changed from not visible to visible
        elif not was_visible and self.is_visible:
            # Only restart if auto-refresh is enabled
            if hasattr(self, 'auto_refresh_checkbox') and self.auto_refresh_checkbox.isChecked():
                if not self.process_timer.isActive():
                    self.update_process_list()
                    self.process_timer.start(3000)  # 3-second refresh
    
    def showEvent(self, event):
        """Handle when the tab becomes visible"""
        super().showEvent(event)
        self.is_visible = True
        print("System tab is now visible")
        
        # Restart timers if needed when tab becomes visible again
        if hasattr(self, 'auto_refresh_checkbox') and self.auto_refresh_checkbox.isChecked():
            if hasattr(self, 'process_timer') and not self.process_timer.isActive():
                print("Restarting process monitoring timer")
                self.update_process_list()
                self.process_timer.start(3000)  # 3-second refresh
        
    def hideEvent(self, event):
        """Handle when the tab becomes hidden"""
        super().hideEvent(event)
        self.is_visible = False
        print("System tab is now hidden")
        
        # Stop timers when tab is hidden to save resources
        if hasattr(self, 'process_timer') and self.process_timer.isActive():
            print("Stopping process monitoring timer")
            self.process_timer.stop()
        
    def _create_process_monitor_tab(self):
        """Create the process monitor tab.""" 
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create controls group
        controls_group = QGroupBox("Controls")
        controls_layout = QGridLayout(controls_group)
        
        # Add filter input
        filter_label = QLabel("Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by process name, PID, or username")
        self.filter_input.textChanged.connect(self.apply_filter)
        controls_layout.addWidget(filter_label, 0, 0)
        controls_layout.addWidget(self.filter_input, 0, 1)
        
        # Add sort option
        sort_label = QLabel("Sort by:")
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["CPU Usage", "Memory Usage", "Process ID", "Process Name"])
        self.sort_combo.currentTextChanged.connect(self.apply_sort)
        controls_layout.addWidget(sort_label, 0, 2)
        controls_layout.addWidget(self.sort_combo, 0, 3)
        
        # Add refresh button and auto-refresh option
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.update_process_list)
        self.auto_refresh_checkbox = QCheckBox("Auto-refresh")
        self.auto_refresh_checkbox.setChecked(True)  # Default to auto-refresh
        self.auto_refresh_checkbox.stateChanged.connect(self.toggle_auto_refresh)
        
        # Add process limit for performance
        limit_label = QLabel("Limit:")
        self.limit_combo = QComboBox()
        self.limit_combo.addItems(["10", "30", "50", "100", "All"])
        self.limit_combo.setCurrentText("30")  # Default to 30 processes
        self.limit_combo.currentTextChanged.connect(self.apply_limit)
        controls_layout.addWidget(limit_label, 1, 0)
        controls_layout.addWidget(self.limit_combo, 1, 1)
        
        controls_layout.addWidget(refresh_button, 1, 2)
        controls_layout.addWidget(self.auto_refresh_checkbox, 1, 3)
        
        layout.addWidget(controls_group)
        
        # Create process list table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["PID", "Process Name", "Username", "CPU %", "Memory %"])
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.setSelectionMode(QTableWidget.SingleSelection)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.setSortingEnabled(False)  # We'll handle sorting ourselves
        
        # Optimize table performance
        self.process_table.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        self.process_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        
        # Set column widths
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # PID
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Process Name
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Username
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # CPU %
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Memory %
        
        layout.addWidget(self.process_table)
        
        # Add status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        # Initialize process monitoring
        self.update_process_list()
        self.process_timer.start(3000)  # 3-second refresh
        
        return tab
    
    def _create_file_integrity_tab(self):
        """Create the file integrity tab.""" 
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create baselines group
        baseline_group = QGroupBox("Create Baseline")
        baseline_layout = QGridLayout(baseline_group)
        
        # Add file selection
        baseline_file_label = QLabel("Select directory or file:")
        self.baseline_file_input = QLineEdit()
        self.baseline_file_input.setReadOnly(True)
        baseline_file_button = QPushButton("Browse...")
        baseline_file_button.clicked.connect(lambda: self.browse_file_or_dir(self.baseline_file_input))
        baseline_layout.addWidget(baseline_file_label, 0, 0)
        baseline_layout.addWidget(self.baseline_file_input, 0, 1)
        baseline_layout.addWidget(baseline_file_button, 0, 2)
        
        # Add output file selection
        baseline_output_label = QLabel("Save baseline to:")
        self.baseline_output_input = QLineEdit()
        self.baseline_output_input.setReadOnly(True)
        baseline_output_button = QPushButton("Browse...")
        baseline_output_button.clicked.connect(lambda: self.browse_output_file(self.baseline_output_input))
        baseline_layout.addWidget(baseline_output_label, 1, 0)
        baseline_layout.addWidget(self.baseline_output_input, 1, 1)
        baseline_layout.addWidget(baseline_output_button, 1, 2)
        
        # Add create button
        create_baseline_button = QPushButton("Create Baseline")
        create_baseline_button.clicked.connect(self.create_baseline)
        baseline_layout.addWidget(create_baseline_button, 2, 0, 1, 3, Qt.AlignCenter)
        
        layout.addWidget(baseline_group)
        
        # Create verification group
        verify_group = QGroupBox("Verify Integrity")
        verify_layout = QGridLayout(verify_group)
        
        # Add baseline file selection
        verify_baseline_label = QLabel("Select baseline file:")
        self.verify_baseline_input = QLineEdit()
        self.verify_baseline_input.setReadOnly(True)
        verify_baseline_button = QPushButton("Browse...")
        verify_baseline_button.clicked.connect(lambda: self.browse_file(self.verify_baseline_input))
        verify_layout.addWidget(verify_baseline_label, 0, 0)
        verify_layout.addWidget(self.verify_baseline_input, 0, 1)
        verify_layout.addWidget(verify_baseline_button, 0, 2)
        
        # Add verify button
        verify_button = QPushButton("Verify Integrity")
        verify_button.clicked.connect(self.verify_integrity)
        verify_layout.addWidget(verify_button, 1, 0, 1, 3, Qt.AlignCenter)
        
        layout.addWidget(verify_group)
        
        # Add progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Add results area
        results_label = QLabel("Results:")
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(results_label)
        layout.addWidget(self.results_text)
        
        return tab
    
    def browse_file_or_dir(self, input_field):
        """Browse for a file or directory.""" 
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if not path:  # User cancelled
            path = QFileDialog.getOpenFileName(self, "Select File")[0]
        if path:
            input_field.setText(path)
    
    def browse_file(self, input_field):
        """Browse for a file.""" 
        path = QFileDialog.getOpenFileName(self, "Select File")[0]
        if path:
            input_field.setText(path)
    
    def browse_output_file(self, input_field):
        """Browse for an output file.""" 
        path = QFileDialog.getSaveFileName(self, "Save File", "", "JSON Files (*.json)")[0]
        if path:
            input_field.setText(path)
    
    def create_baseline(self):
        """Create a file integrity baseline.""" 
        file_path = self.baseline_file_input.text()
        output_path = self.baseline_output_input.text()
        
        if not file_path:
            QMessageBox.warning(self, "Input Required", "Please select a file or directory to create a baseline for.")
            return
        
        if not output_path:
            QMessageBox.warning(self, "Output Required", "Please select where to save the baseline file.")
            return
        
        # Create and start the file operation thread
        self.file_operation_thread = FileOperationThread(
            operation='create_baseline',
            file_path=file_path,
            output_path=output_path
        )
        self.file_operation_thread.progress_signal.connect(self.update_progress)
        self.file_operation_thread.result_signal.connect(self.handle_file_operation_result)
        self.file_operation_thread.start()
    
    def verify_integrity(self):
        """Verify file integrity against a baseline.""" 
        baseline_path = self.verify_baseline_input.text()
        
        if not baseline_path:
            QMessageBox.warning(self, "Input Required", "Please select a baseline file to verify against.")
            return
        
        # Create and start the file operation thread
        self.file_operation_thread = FileOperationThread(
            operation='verify_integrity',
            file_path=baseline_path
        )
        self.file_operation_thread.progress_signal.connect(self.update_progress)
        self.file_operation_thread.result_signal.connect(self.handle_file_operation_result)
        self.file_operation_thread.start()
    
    def update_progress(self, percentage, message):
        """Update the progress bar and status message.""" 
        self.progress_bar.setValue(percentage)
        self.results_text.append(message)
        
        # Auto-scroll to bottom
        cursor = self.results_text.textCursor()
        cursor.movePosition(cursor.End)
        self.results_text.setTextCursor(cursor)
    
    def handle_file_operation_result(self, result):
        """Handle the result of a file operation.""" 
        operation = result.get('operation', '')
        
        if 'error' in result:
            error = result['error']
            self.results_text.append(f"Error during {operation}: {error}")
            QMessageBox.warning(self, "Operation Failed", f"The {operation} operation failed: {error}")
            return
        
        if operation == 'create_baseline':
            self.results_text.append(f"Baseline created successfully at {result.get('output_path', '')}")
            QMessageBox.information(self, "Success", "Baseline created successfully!")
        
        elif operation == 'verify_integrity':
            total_files = result.get('total_files', 0)
            changed_files = result.get('changed_files', [])
            missing_files = result.get('missing_files', [])
            new_files = result.get('new_files', [])
            
            self.results_text.append(f"\nVerification completed for {total_files} files:")
            self.results_text.append(f"- Changed files: {len(changed_files)}")
            self.results_text.append(f"- Missing files: {len(missing_files)}")
            self.results_text.append(f"- New files: {len(new_files)}")
            
            if changed_files:
                self.results_text.append("\nChanged files:")
                for file in changed_files:
                    self.results_text.append(f"- {file}")
            
            if missing_files:
                self.results_text.append("\nMissing files:")
                for file in missing_files:
                    self.results_text.append(f"- {file}")
            
            if new_files:
                self.results_text.append("\nNew files:")
                for file in new_files:
                    self.results_text.append(f"- {file}")
            
            if not changed_files and not missing_files and not new_files:
                self.results_text.append("\nAll files are unchanged!")
                QMessageBox.information(self, "Success", "Verification completed. All files match the baseline!")
            else:
                QMessageBox.warning(self, "Changes Detected", f"Verification completed. {len(changed_files)} changed, {len(missing_files)} missing, {len(new_files)} new files detected.")
    
    def apply_filter(self):
        """Apply the filter to the process list.""" 
        # Only update if we're visible to save resources
        if self.isVisible() and self.tabs.currentWidget() == self.process_monitor_tab:
            self.update_process_list()
    
    def apply_sort(self, sort_by):
        """Apply the sort to the process list.""" 
        # Only update if we're visible to save resources
        if self.isVisible() and self.tabs.currentWidget() == self.process_monitor_tab:
            self.update_process_list()
    
    def apply_limit(self, limit_text):
        """Apply the process limit for performance.""" 
        # Only update if we're visible to save resources
        if self.isVisible() and self.tabs.currentWidget() == self.process_monitor_tab:
            self.update_process_list()
    
    def toggle_auto_refresh(self, state):
        """Toggle auto-refresh of the process list.""" 
        if state == Qt.Checked:
            if not self.process_timer.isActive() and self.isVisible():
                self.update_process_list()
                self.process_timer.start(3000)  # 3-second refresh
        else:
            if self.process_timer.isActive():
                self.process_timer.stop()
    
    def update_process_list(self):
        """Update the list of processes.""" 
        # Don't update if hidden
        if not self.isVisible() or self.tabs.currentWidget() != self.process_monitor_tab:
            return
        
        # Don't start a new thread if one is already running
        if self.process_thread and self.process_thread.isRunning():
            return
        
        # Get the filter text
        filter_text = self.filter_input.text().lower()
        
        # Get the sort option
        sort_by = self.sort_combo.currentText()
        
        # Get the limit option
        limit_text = self.limit_combo.currentText()
        limit = 9999 if limit_text == "All" else int(limit_text)
        
        # Create and start the process monitoring thread
        self.process_thread = ProcessMonitorThread(
            filter_text=filter_text,
            sort_by=sort_by,
            limit=limit
        )
        self.process_thread.update_signal.connect(self.update_process_table)
        self.process_thread.error_signal.connect(self.handle_process_error)
        self.process_thread.start()
    
    def update_process_table(self, processes, time_str):
        """Update the process table with the list of processes.""" 
        # Block signals to prevent flickering
        self.process_table.blockSignals(True)
        
        # Temporarily disable sorting
        was_sorting_enabled = self.process_table.isSortingEnabled()
        self.process_table.setSortingEnabled(False)
        
        # Clear the table
        self.process_table.setRowCount(0)
        
        # Batch update for better performance
        self.process_table.setRowCount(len(processes))
        
        # Add processes to table
        for row, process in enumerate(processes):
            pid_item = QTableWidgetItem(str(process.get('pid', 0)))
            pid_item.setData(Qt.UserRole, process.get('pid', 0))  # Store raw value for sorting
            
            name_item = QTableWidgetItem(process.get('name', ''))
            
            username_item = QTableWidgetItem(process.get('username', ''))
            
            cpu_percent = process.get('cpu_percent', 0)
            cpu_item = QTableWidgetItem(f"{cpu_percent:.1f}%")
            cpu_item.setData(Qt.UserRole, cpu_percent)  # Store raw value for sorting
            
            memory_percent = process.get('memory_percent', 0)
            memory_item = QTableWidgetItem(f"{memory_percent:.1f}%")
            memory_item.setData(Qt.UserRole, memory_percent)  # Store raw value for sorting
            
            self.process_table.setItem(row, 0, pid_item)
            self.process_table.setItem(row, 1, name_item)
            self.process_table.setItem(row, 2, username_item)
            self.process_table.setItem(row, 3, cpu_item)
            self.process_table.setItem(row, 4, memory_item)
        
        # Re-enable sorting if it was enabled
        self.process_table.setSortingEnabled(was_sorting_enabled)
        
        # Unblock signals
        self.process_table.blockSignals(False)
        
        # Update status label
        self.status_label.setText(f"Last updated: {time_str} | Showing {len(processes)} processes")
    
    def handle_process_error(self, error_message):
        """Handle errors from the process monitoring thread.""" 
        self.status_label.setText(f"Error: {error_message}")
        QMessageBox.warning(self, "Process Monitor Error", f"An error occurred while monitoring processes: {error_message}")

    def cleanup(self):
        """Clean up resources before closing.""" 
        # Stop process monitoring timer
        if hasattr(self, 'process_timer') and self.process_timer.isActive():
            self.process_timer.stop()
            
        # Stop process thread if running
        if hasattr(self, 'process_thread') and self.process_thread and self.process_thread.isRunning():
            self.process_thread.running = False
            self.process_thread.terminate()
            self.process_thread.wait()
            
        # Stop file operation thread if running
        if hasattr(self, 'file_operation_thread') and self.file_operation_thread and self.file_operation_thread.isRunning():
            self.file_operation_thread.terminate()
            self.file_operation_thread.wait()