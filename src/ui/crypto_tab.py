from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel, QPushButton, 
                          QLineEdit, QTextEdit, QGroupBox, QComboBox, QTabWidget, 
                          QHBoxLayout, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class HashGeneratorThread(QThread):
    """Thread for generating hashes without blocking the UI."""
    result_signal = pyqtSignal(dict)
    
    def __init__(self, text, hash_type):
        super().__init__()
        self.text = text
        self.hash_type = hash_type
        
    def run(self):
        try:
            from src.tools.crypto.hash_generator import HashGenerator
            
            generator = HashGenerator()
            result = generator.generate_hash(self.text, self.hash_type)
            
            self.result_signal.emit(result)
        except Exception as e:
            self.result_signal.emit({"error": str(e)})


class FileEncryptionThread(QThread):
    """Thread for file encryption/decryption without blocking the UI."""
    result_signal = pyqtSignal(dict)
    
    def __init__(self, operation, file_path, password, method='aes'):
        super().__init__()
        self.operation = operation  # 'encrypt' or 'decrypt'
        self.file_path = file_path
        self.password = password
        self.method = method
        
    def run(self):
        try:
            from src.tools.crypto.file_encryption import FileEncryptionTool
            
            encryptor = FileEncryptionTool()
            
            if self.operation == 'encrypt':
                result = encryptor.encrypt_file(self.file_path, self.password, method=self.method)
            else:
                result = encryptor.decrypt_file(self.file_path, self.password, method=self.method)
            
            # Add operation type to result
            result['operation'] = self.operation
            
            self.result_signal.emit(result)
        except Exception as e:
            self.result_signal.emit({
                "error": str(e),
                "operation": self.operation
            })


class PasswordStrengthThread(QThread):
    """Thread for checking password strength without blocking the UI."""
    result_signal = pyqtSignal(dict)
    
    def __init__(self, password):
        super().__init__()
        self.password = password
        
    def run(self):
        try:
            # Don't check empty passwords
            if not self.password:
                self.result_signal.emit({"skip": True})
                return
                
            from src.tools.crypto.password_strength import PasswordStrengthChecker
            
            checker = PasswordStrengthChecker()
            result = checker.check_strength(self.password)
            
            # Add suggestions
            result['suggestions'] = checker.generate_improvement_suggestions(self.password)
            
            self.result_signal.emit(result)
        except Exception as e:
            self.result_signal.emit({"error": str(e)})


class CryptoToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        
        # Create main layout
        self.layout = QVBoxLayout(self)
        
        # Create a tab widget for crypto tools
        self.tabs = QTabWidget()
        
        # Create individual tool tabs
        self.hash_generator_tab = self._create_hash_generator_tab()
        self.file_encryption_tab = self._create_file_encryption_tab()
        self.password_strength_tab = self._create_password_strength_tab()
        
        # Add tool tabs to tab widget
        self.tabs.addTab(self.hash_generator_tab, "Hash Generator")
        self.tabs.addTab(self.file_encryption_tab, "File Encryption")
        self.tabs.addTab(self.password_strength_tab, "Password Strength")
        
        # Add tab widget to main layout
        self.layout.addWidget(self.tabs)
        
        # Initialize threads
        self.hash_thread = None
        self.file_thread = None
        self.password_thread = None
        
        # Flags to prevent multiple thread launches
        self.hash_in_progress = False
        self.file_op_in_progress = False
    
    def _create_hash_generator_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input section
        input_group = QGroupBox("Generate Hash")
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Input Text:"), 0, 0)
        self.hash_input = QTextEdit()
        self.hash_input.setPlaceholderText("Enter text to hash...")
        input_layout.addWidget(self.hash_input, 0, 1, 1, 3)
        
        input_layout.addWidget(QLabel("Hash Type:"), 1, 0)
        self.hash_type = QComboBox()
        self.hash_type.addItems(["MD5", "SHA-1", "SHA-256", "SHA-512"])
        input_layout.addWidget(self.hash_type, 1, 1)
        
        self.generate_hash_button = QPushButton("Generate Hash")
        self.generate_hash_button.clicked.connect(self.generate_hash)
        input_layout.addWidget(self.generate_hash_button, 1, 2, 1, 2)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Hash Result")
        results_layout = QVBoxLayout()
        
        self.hash_result = QTextEdit()
        self.hash_result.setReadOnly(True)
        results_layout.addWidget(self.hash_result)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab
    
    def _create_file_encryption_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Encryption section
        encrypt_group = QGroupBox("Encrypt/Decrypt File")
        encrypt_layout = QGridLayout()
        
        encrypt_layout.addWidget(QLabel("File:"), 0, 0)
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        encrypt_layout.addWidget(self.file_path, 0, 1, 1, 2)
        
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_file)
        encrypt_layout.addWidget(self.browse_button, 0, 3)
        
        encrypt_layout.addWidget(QLabel("Password:"), 1, 0)
        self.encrypt_password = QLineEdit()
        self.encrypt_password.setEchoMode(QLineEdit.Password)
        encrypt_layout.addWidget(self.encrypt_password, 1, 1, 1, 3)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        button_layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        button_layout.addWidget(self.decrypt_button)
        
        encrypt_layout.addLayout(button_layout, 2, 0, 1, 4)
        
        encrypt_group.setLayout(encrypt_layout)
        layout.addWidget(encrypt_group)
        
        # Status section
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        
        self.encrypt_status = QTextEdit()
        self.encrypt_status.setReadOnly(True)
        status_layout.addWidget(self.encrypt_status)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        return tab
    
    def _create_password_strength_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input section
        input_group = QGroupBox("Check Password Strength")
        input_layout = QGridLayout()
        
        input_layout.addWidget(QLabel("Password:"), 0, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.check_password_strength)
        input_layout.addWidget(self.password_input, 0, 1, 1, 3)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Password Analysis")
        results_layout = QVBoxLayout()
        
        self.password_strength = QTextEdit()
        self.password_strength.setReadOnly(True)
        results_layout.addWidget(self.password_strength)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab
    
    def generate_hash(self):
        """Generate hash for the given input text and selected hash type using HashGenerator."""
        input_text = self.hash_input.toPlainText()
        if not input_text:
            self.hash_result.setText("Please enter text to hash.")
            return
        
        # Show progress message
        self.hash_result.setText("Generating hash...")
        
        # Prevent multiple simultaneous operations
        if self.hash_in_progress:
            return
        self.hash_in_progress = True
        
        # Disable the button while processing
        self.generate_hash_button.setEnabled(False)
        
        # Get hash type and normalize it
        hash_type = self.hash_type.currentText().lower()
        if hash_type == "sha-1":
            hash_type = "sha1"
        elif hash_type == "sha-256":
            hash_type = "sha256"
        elif hash_type == "sha-512":
            hash_type = "sha512"
        
        # Create and start the thread
        self.hash_thread = HashGeneratorThread(input_text, hash_type)
        self.hash_thread.result_signal.connect(self.handle_hash_result)
        self.hash_thread.start()
    
    def handle_hash_result(self, result):
        """Handle the hash generation result from the thread."""
        # Re-enable the button
        self.generate_hash_button.setEnabled(True)
        self.hash_in_progress = False
        
        if "error" in result:
            self.hash_result.setText(f"Error: {result['error']}")
            return
        
        # Display the hash with formatting
        hash_value = result['hash']
        algorithm = result['algorithm'].upper()
        
        # Create a nicely formatted result
        formatted_result = f"Algorithm: {algorithm}\n\n"
        formatted_result += f"{hash_value}\n\n"
        formatted_result += f"Input Length: {len(self.hash_input.toPlainText())} characters\n"
        formatted_result += f"Hash Length: {len(hash_value)} characters"
        
        self.hash_result.setText(formatted_result)
    
    def browse_file(self):
        """Browse for a file to encrypt or decrypt."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_path:
            self.file_path.setText(file_path)
    
    def encrypt_file(self):
        """Encrypt the selected file using our FileEncryptionTool in a thread."""
        file_path = self.file_path.text()
        password = self.encrypt_password.text()
        
        if not file_path:
            self.encrypt_status.setText("Please select a file to encrypt.")
            return
        
        if not password:
            self.encrypt_status.setText("Please enter a password for encryption.")
            return
        
        # Prevent multiple simultaneous operations
        if self.file_op_in_progress:
            return
        self.file_op_in_progress = True
        
        # Disable buttons while processing
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        
        # Show progress message
        self.encrypt_status.setText("Encrypting file... Please wait.")
        
        # Create and start the thread
        self.file_thread = FileEncryptionThread('encrypt', file_path, password)
        self.file_thread.result_signal.connect(self.handle_file_operation_result)
        self.file_thread.start()
    
    def decrypt_file(self):
        """Decrypt the selected file using our FileEncryptionTool in a thread."""
        file_path = self.file_path.text()
        password = self.encrypt_password.text()
        
        if not file_path:
            self.encrypt_status.setText("Please select a file to decrypt.")
            return
        
        if not password:
            self.encrypt_status.setText("Please enter the password used for encryption.")
            return
        
        if not file_path.endswith('.encrypted'):
            response = QMessageBox.question(self, "Confirm Decryption", 
                                          "The selected file doesn't have the .encrypted extension. Are you sure this is an encrypted file?",
                                          QMessageBox.Yes | QMessageBox.No)
            if response == QMessageBox.No:
                return
        
        # Prevent multiple simultaneous operations
        if self.file_op_in_progress:
            return
        self.file_op_in_progress = True
        
        # Disable buttons while processing
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        
        # Show progress message
        self.encrypt_status.setText("Decrypting file... Please wait.")
        
        # Create and start the thread
        self.file_thread = FileEncryptionThread('decrypt', file_path, password)
        self.file_thread.result_signal.connect(self.handle_file_operation_result)
        self.file_thread.start()
    
    def handle_file_operation_result(self, result):
        """Handle the file encryption/decryption result from the thread."""
        # Re-enable buttons
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(True)
        self.file_op_in_progress = False
        
        if "error" in result:
            self.encrypt_status.setText(f"Error: {result['error']}")
            return
        
        operation = result.get('operation', '')
        operation_name = "Encryption" if operation == 'encrypt' else "Decryption"
        
        if result.get("success"):
            self.encrypt_status.setText(
                f"File {operation_name.lower()} completed successfully!\n"
                f"{operation_name} method: {result['method'].upper()}\n"
                f"{'Original' if operation == 'encrypt' else 'Encrypted'} file size: {result.get('file_size', result.get('encrypted_size', 0))} bytes\n"
                f"{'Encrypted' if operation == 'encrypt' else 'Decrypted'} file size: {result.get('encrypted_size', result.get('decrypted_size', 0))} bytes\n"
                f"Output file: {result['output_file']}"
            )
        else:
            self.encrypt_status.setText(f"{operation_name} failed with unknown error.")
    
    def check_password_strength(self):
        """Check password strength using the PasswordStrengthChecker in a thread."""
        password = self.password_input.text()
        
        if not password:
            self.password_strength.setText("Enter a password to check its strength.")
            return
        
        # Create and start the thread
        self.password_thread = PasswordStrengthThread(password)
        self.password_thread.result_signal.connect(self.handle_password_strength_result)
        self.password_thread.start()
    
    def handle_password_strength_result(self, result):
        """Handle the password strength result from the thread."""
        # Skip empty password or if "skip" flag is set (avoids unnecessary calculations)
        if not self.password_input.text() or result.get("skip"):
            return
            
        if "error" in result:
            self.password_strength.setText(f"Error checking password strength: {result['error']}")
            return
        
        # Map strength to color
        strength = result['strength']
        if strength == "Very Weak":
            color = "darkred"
        elif strength == "Weak":
            color = "red"
        elif strength == "Moderate":
            color = "orange"
        elif strength == "Strong":
            color = "green"
        else:  # Very Strong
            color = "darkgreen"
        
        # Get improvement suggestions
        suggestions = result.get('suggestions', [])
        
        # Create the HTML result
        score_percentage = (result['score'] / 100) * 100  # Convert to percentage
        
        html_result = f"<h3>Password Strength: <span style='color:{color}'>{strength}</span></h3>"
        html_result += f"<p>Score: {result['score']}/100 ({score_percentage:.0f}%)</p>"
        
        # Add feedback
        if result['feedback']:
            html_result += "<h4>Analysis:</h4><ul>"
            for item in result['feedback']:
                # Add emoji based on whether it's positive or negative feedback
                emoji = "✅" if "good" in item.lower() or "strong" in item.lower() else "❌"
                html_result += f"<li>{emoji} {item}</li>"
            html_result += "</ul>"
        
        # Add suggestions if they exist and password isn't very strong
        if suggestions and strength != "Very Strong":
            html_result += "<h4>Suggestions to improve your password:</h4><ul>"
            for suggestion in suggestions:
                html_result += f"<li>💡 {suggestion}</li>"
            html_result += "</ul>"
        
        # Add tips for creating strong passwords
        if strength not in ["Strong", "Very Strong"]:
            html_result += "<h4>Tips for strong passwords:</h4><ul>"
            html_result += "<li>Use at least 12 characters</li>"
            html_result += "<li>Include uppercase and lowercase letters</li>"
            html_result += "<li>Include numbers and special characters</li>"
            html_result += "<li>Avoid common words and patterns</li>"
            html_result += "<li>Don't use personal information</li>"
            html_result += "</ul>"
        
        self.password_strength.setHtml(html_result)
    
    def initialize(self):
        """Initialize or re-initialize the tab when it becomes active."""
        print("Crypto tab initializing...")
        
        # Reset hash generator tab
        self.hash_input.clear()
        self.hash_result.clear()
        
        # Reset file encryption tab
        self.file_path.clear()
        self.encrypt_password.clear()
        self.encrypt_status.clear()
        
        # Reset password strength tab
        self.password_input.clear()
        self.password_strength.clear()
        
        # Ensure buttons are enabled
        self.generate_hash_button.setEnabled(True)
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(True)
        
        # Reset operation flags
        self.hash_in_progress = False
        self.file_op_in_progress = False