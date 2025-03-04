import sys
import os
import json
import random
import string
import base64
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTreeView, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QDialog,
                             QMessageBox, QCheckBox, QSpinBox, QFormLayout, QTabWidget,
                             QListWidget, QListWidgetItem, QMenu, QAction, QInputDialog,
                             QFileDialog, QFrame, QSplitter, QScrollArea, QGroupBox)
from PyQt5.QtCore import Qt, QModelIndex, QVariant
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPalette, QColor
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import secrets




def apply_dark_theme(app):
    # Create a dark palette with purple/pink accents
    dark_palette = QPalette()

    # Define colors
    background_color = QColor(30, 30, 30)
    text_color = QColor(240, 240, 240)
    accent_color = QColor(170, 85, 255)  # Purple/pink accent
    secondary_accent = QColor(130, 60, 200)  # Darker purple for contrast
    highlight_color = QColor(200, 100, 255)  # Lighter purple for highlights

    # Set colors for different roles
    dark_palette.setColor(QPalette.Window, background_color)
    dark_palette.setColor(QPalette.WindowText, text_color)
    dark_palette.setColor(QPalette.Base, QColor(45, 45, 45))
    dark_palette.setColor(QPalette.AlternateBase, QColor(55, 55, 55))
    dark_palette.setColor(QPalette.ToolTipBase, accent_color)
    dark_palette.setColor(QPalette.ToolTipText, text_color)
    dark_palette.setColor(QPalette.Text, text_color)
    dark_palette.setColor(QPalette.Button, QColor(50, 50, 50))
    dark_palette.setColor(QPalette.ButtonText, text_color)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Link, accent_color)
    dark_palette.setColor(QPalette.Highlight, highlight_color)
    dark_palette.setColor(QPalette.HighlightedText, Qt.black)

    # Apply the palette
    app.setPalette(dark_palette)

    # Set stylesheet for rounded corners and additional styling
    app.setStyleSheet("""
        QWidget {
            font-family: 'Segoe UI', Arial, sans-serif;
        }

        QMainWindow, QDialog {
            background-color: #1e1e1e;
        }

        QMenuBar {
            background-color: #252525;
            color: #f0f0f0;
            border-bottom: 1px solid #333333;
        }

        QMenuBar::item {
            background-color: transparent;
            padding: 6px 10px;
            border-radius: 4px;
        }

        QMenuBar::item:selected {
            background-color: #aa55ff;
            color: white;
        }

        QMenuBar::item:pressed {
            background-color: #8240c8;
            color: white;
        }

        QPushButton {
            background-color: #aa55ff;
            color: white;
            border: none;
            border-radius: 8px;
            padding: 6px 12px;
            font-weight: bold;
        }

        QPushButton:hover {
            background-color: #c880ff;
        }

        QPushButton:pressed {
            background-color: #8240c8;
        }

        QPushButton:disabled {
            background-color: #555555;
            color: #888888;
        }

        QLineEdit, QSpinBox {
            background-color: #333333;
            color: #f0f0f0;
            border: 1px solid #555555;
            border-radius: 6px;
            padding: 4px;
        }

        QLineEdit:focus, QSpinBox:focus {
            border: 1px solid #aa55ff;
        }

        QTreeView, QListWidget {
            background-color: #2d2d2d;
            border-radius: 8px;
            border: 1px solid #444444;
            padding: 4px;
        }

        QTreeView::item:selected, QListWidget::item:selected {
            background-color: #aa55ff;
            color: white;
            border-radius: 4px;
        }

        QTreeView::item:hover, QListWidget::item:hover {
            background-color: #444444;
            border-radius: 4px;
        }

        QCheckBox {
            color: #f0f0f0;
        }

        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border-radius: 4px;
        }

        QCheckBox::indicator:unchecked {
            background-color: #333333;
            border: 1px solid #555555;
        }

        QCheckBox::indicator:checked {
            background-color: #aa55ff;
            border: 1px solid #aa55ff;
        }

        QGroupBox {
            border: 1px solid #444444;
            border-radius: 8px;
            margin-top: 1ex;
            padding-top: 10px;
            color: #f0f0f0;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 5px;
        }

        QMenu {
            background-color: #2d2d2d;
            border: 1px solid #444444;
            border-radius: 6px;
        }

        QMenu::item {
            padding: 5px 20px 5px 20px;
            border-radius: 4px;
        }

        QMenu::item:selected {
            background-color: #aa55ff;
            color: white;
        }

        QLabel {
            color: #f0f0f0;
        }

        QLabel#FolderTitle, QLabel#EntriesTitle {
            font-weight: bold;
            font-size: 14px;
            color: #aa55ff;
            padding: 8px;
            background-color: #252525;
            border-radius: 8px;
            margin-bottom: 5px;
        }

        QSplitter::handle {
            background-color: #444444;
        }

        QScrollBar:vertical {
            border: none;
            background-color: #2d2d2d;
            width: 10px;
            border-radius: 5px;
        }

        QScrollBar::handle:vertical {
            background-color: #555555;
            min-height: 20px;
            border-radius: 5px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #aa55ff;
        }

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }

        QWidget#LeftPanel, QWidget#RightPanel {
            background-color: #1e1e1e;
            border-radius: 8px;
            padding: 10px;
        }

        QTreeView {
            background-color: #2d2d2d;
            border-radius: 0 0 8px 8px;
            border: 1px solid #444444;
            border-top: none;
            padding: 4px;
        }

        QListWidget {
            background-color: #2d2d2d;
            border-radius: 0 0 8px 8px;
            border: 1px solid #444444;
            border-top: none;
            padding: 4px;
        }
    """)


class PasswordGenerator(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Generator")
        self.setMinimumWidth(400)

        layout = QVBoxLayout()

        # Password length
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Length:"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 64)
        self.length_spin.setValue(16)
        length_layout.addWidget(self.length_spin)
        layout.addLayout(length_layout)

        # Character options
        self.uppercase_check = QCheckBox("Uppercase letters (A-Z)")
        self.uppercase_check.setChecked(True)
        layout.addWidget(self.uppercase_check)

        self.lowercase_check = QCheckBox("Lowercase letters (a-z)")
        self.lowercase_check.setChecked(True)
        layout.addWidget(self.lowercase_check)

        self.numbers_check = QCheckBox("Numbers (0-9)")
        self.numbers_check.setChecked(True)
        layout.addWidget(self.numbers_check)

        self.symbols_check = QCheckBox("Symbols (!@#$%^&*)")
        self.symbols_check.setChecked(True)
        layout.addWidget(self.symbols_check)

        # Generated password
        layout.addWidget(QLabel("Generated Password:"))
        self.password_field = QLineEdit()
        self.password_field.setReadOnly(True)
        layout.addWidget(self.password_field)

        # Buttons
        button_layout = QHBoxLayout()
        generate_button = QPushButton("Generate")
        generate_button.clicked.connect(self.generate_password)
        button_layout.addWidget(generate_button)

        accept_button = QPushButton("Use Password")
        accept_button.clicked.connect(self.accept)
        button_layout.addWidget(accept_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.generate_password()

    def generate_password(self):
        length = self.length_spin.value()
        chars = ""

        if self.uppercase_check.isChecked():
            chars += string.ascii_uppercase
        if self.lowercase_check.isChecked():
            chars += string.ascii_lowercase
        if self.numbers_check.isChecked():
            chars += string.digits
        if self.symbols_check.isChecked():
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"

        if not chars:
            QMessageBox.warning(self, "Warning", "Please select at least one character type")
            return

        password = ''.join(random.choice(chars) for _ in range(length))
        self.password_field.setText(password)

    def get_password(self):
        return self.password_field.text()


class CustomFieldWidget(QWidget):
    def __init__(self, field_name="", field_value="", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        self.name_edit = QLineEdit(field_name)
        self.name_edit.setPlaceholderText("Field Name")
        layout.addWidget(self.name_edit)

        self.value_edit = QLineEdit(field_value)
        self.value_edit.setPlaceholderText("Value")
        layout.addWidget(self.value_edit)

        self.delete_button = QPushButton("X")
        self.delete_button.setMaximumWidth(30)
        self.delete_button.clicked.connect(self.delete_field)
        layout.addWidget(self.delete_button)

        self.setLayout(layout)

    def delete_field(self):
        self.parent().remove_custom_field(self)

    def get_data(self):
        return {
            "name": self.name_edit.text(),
            "value": self.value_edit.text()
        }


class PasswordEntryDialog(QDialog):
    def __init__(self, entry_data=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Entry")
        self.setMinimumWidth(500)

        self.entry_data = entry_data or {}

        layout = QVBoxLayout()

        form_layout = QFormLayout()

        # Title (required)
        self.title_edit = QLineEdit(self.entry_data.get("title", ""))
        self.title_edit.setPlaceholderText("Required")
        form_layout.addRow("Title*:", self.title_edit)

        # Username (optional)
        self.username_edit = QLineEdit(self.entry_data.get("username", ""))
        form_layout.addRow("Username:", self.username_edit)

        # Email (optional)
        self.email_edit = QLineEdit(self.entry_data.get("email", ""))
        form_layout.addRow("Email:", self.email_edit)

        # Password (required)
        password_layout = QHBoxLayout()
        self.password_edit = QLineEdit(self.entry_data.get("password", ""))
        self.password_edit.setPlaceholderText("Required")
        self.password_edit.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.password_edit)

        self.show_password_btn = QPushButton("Show")
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.toggled.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_btn)

        self.generate_password_btn = QPushButton("Generate")
        self.generate_password_btn.clicked.connect(self.generate_password)
        password_layout.addWidget(self.generate_password_btn)

        form_layout.addRow("Password*:", password_layout)

        # URL (optional)
        self.url_edit = QLineEdit(self.entry_data.get("url", ""))
        form_layout.addRow("URL:", self.url_edit)

        layout.addLayout(form_layout)

        # Custom fields
        custom_fields_group = QGroupBox("Custom Fields")
        self.custom_fields_layout = QVBoxLayout()

        # Add custom fields
        for field in self.entry_data.get("custom_fields", []):
            self.add_custom_field(field.get("name", ""), field.get("value", ""))

        add_field_button = QPushButton("Add Custom Field")
        add_field_button.clicked.connect(lambda: self.add_custom_field())
        self.custom_fields_layout.addWidget(add_field_button)

        custom_fields_group.setLayout(self.custom_fields_layout)
        layout.addWidget(custom_fields_group)

        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.accept)
        button_layout.addWidget(save_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.custom_field_widgets = []

    def toggle_password_visibility(self, checked):
        self.password_edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        self.show_password_btn.setText("Hide" if checked else "Show")

    def generate_password(self):
        dialog = PasswordGenerator(self)
        if dialog.exec_() == QDialog.Accepted:
            self.password_edit.setText(dialog.get_password())

    def add_custom_field(self, name="", value=""):
        field_widget = CustomFieldWidget(name, value, self)
        # Insert before the "Add Custom Field" button
        self.custom_fields_layout.insertWidget(self.custom_fields_layout.count() - 1, field_widget)
        self.custom_field_widgets.append(field_widget)

    def remove_custom_field(self, widget):
        self.custom_fields_layout.removeWidget(widget)
        self.custom_field_widgets.remove(widget)
        widget.deleteLater()

    def get_data(self):
        # Validate required fields
        if not self.title_edit.text():
            QMessageBox.warning(self, "Warning", "Title is required")
            return None

        if not self.password_edit.text():
            QMessageBox.warning(self, "Warning", "Password is required")
            return None

        custom_fields = []
        for widget in self.custom_field_widgets:
            field_data = widget.get_data()
            if field_data["name"] and field_data["value"]:
                custom_fields.append(field_data)

        return {
            "title": self.title_edit.text(),
            "username": self.username_edit.text(),
            "email": self.email_edit.text(),
            "password": self.password_edit.text(),
            "url": self.url_edit.text(),
            "custom_fields": custom_fields
        }


class MasterPasswordDialog(QDialog):
    def __init__(self, is_new=False, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Master Password")
        self.is_new = is_new

        layout = QVBoxLayout()

        if is_new:
            layout.addWidget(QLabel("Create a strong master password:"))
            self.password_edit = QLineEdit()
            self.password_edit.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.password_edit)

            layout.addWidget(QLabel("Confirm master password:"))
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_edit)

            self.complexity_label = QLabel("")
            layout.addWidget(self.complexity_label)

            self.password_edit.textChanged.connect(self.check_password_strength)
        else:
            layout.addWidget(QLabel("Enter your master password:"))
            self.password_edit = QLineEdit()
            self.password_edit.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.password_edit)

        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.validate)
        button_layout.addWidget(ok_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def check_password_strength(self):
        password = self.password_edit.text()

        if len(password) < 8:
            self.complexity_label.setText("Password is too short (minimum 8 characters)")
            self.complexity_label.setStyleSheet("color: #ff5555")
            return False

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        strength = sum([has_upper, has_lower, has_digit, has_special])

        if strength == 4:
            self.complexity_label.setText("Password strength: Strong")
            self.complexity_label.setStyleSheet("color: #55ff7f")
            return True
        elif strength == 3:
            self.complexity_label.setText("Password strength: Good")
            self.complexity_label.setStyleSheet("color: #ffaa55")
            return True
        else:
            self.complexity_label.setText("Password is too weak (use uppercase, lowercase, numbers, and symbols)")
            self.complexity_label.setStyleSheet("color: #ff5555")
            return False

    def validate(self):
        if self.is_new:
            if not self.check_password_strength():
                return

            if self.password_edit.text() != self.confirm_edit.text():
                QMessageBox.warning(self, "Error", "Passwords do not match")
                return

        self.accept()

    def get_password(self):
        return self.password_edit.text()


class PasswordManager:
    def __init__(self):
        self.key = None
        self.fernet = None

    def setup_encryption(self, password, salt=None):
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.key = key
        self.fernet = Fernet(key)
        return salt

    def encrypt_data(self, data):
        if not self.fernet:
            raise ValueError("Encryption not initialized")

        json_data = json.dumps(data)
        return self.fernet.encrypt(json_data.encode())

    def decrypt_data(self, encrypted_data):
        if not self.fernet:
            raise ValueError("Encryption not initialized")

        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    def save_data(self, filename, data):
        encrypted_data = self.encrypt_data(data)
        with open(filename, 'wb') as f:
            f.write(encrypted_data)

    def load_data(self, filename):
        with open(filename, 'rb') as f:
            encrypted_data = f.read()
        return self.decrypt_data(encrypted_data)

    def save_salt(self, filename, salt):
        with open(filename, 'wb') as f:
            f.write(salt)

    def load_salt(self, filename):
        with open(filename, 'rb') as f:
            return f.read()


class FolderTreeModel(QStandardItemModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels(["Folders"])

    def flags(self, index):
        default_flags = super().flags(index)
        return default_flags | Qt.ItemIsDropEnabled | Qt.ItemIsDragEnabled


class PasswordKeeperApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Keeper")
        self.resize(900, 600)

        self.password_manager = PasswordManager()
        self.data_file = "passwords.dat"
        self.salt_file = "salt.dat"
        self.data = {"folders": {}, "entries": {}}

        # Check if first run
        self.first_run = not (os.path.exists(self.data_file) and os.path.exists(self.salt_file))

        if not self.authenticate():
            sys.exit(0)

        self.init_ui()

    def authenticate(self):
        if self.first_run:
            dialog = MasterPasswordDialog(is_new=True, parent=self)
            if dialog.exec_() != QDialog.Accepted:
                return False

            master_password = dialog.get_password()
            salt = self.password_manager.setup_encryption(master_password)
            self.password_manager.save_salt(self.salt_file, salt)
            return True
        else:
            salt = self.password_manager.load_salt(self.salt_file)

            max_attempts = 3
            for attempt in range(max_attempts):
                dialog = MasterPasswordDialog(is_new=False, parent=self)
                if dialog.exec_() != QDialog.Accepted:
                    return False

                master_password = dialog.get_password()
                try:
                    self.password_manager.setup_encryption(master_password, salt)
                    self.data = self.password_manager.load_data(self.data_file)
                    return True
                except ValueError:
                    attempts_left = max_attempts - attempt - 1
                    if attempts_left > 0:
                        QMessageBox.warning(self, "Error", f"Incorrect password. {attempts_left} attempts remaining.")
                    else:
                        QMessageBox.critical(self, "Error", "Too many failed attempts.")
                        return False

    def init_ui(self):
        central_widget = QWidget()
        main_layout = QHBoxLayout()

        # Left side - folder tree
        left_panel = QWidget()
        left_panel.setObjectName("LeftPanel")
        left_layout = QVBoxLayout()

        folders_label = QLabel("Folders")
        folders_label.setObjectName("FolderTitle")  # Set object name for styling
        left_layout.addWidget(folders_label)

        self.folder_tree = QTreeView()
        self.folder_model = FolderTreeModel()
        self.folder_tree.setModel(self.folder_model)
        self.folder_tree.setDragEnabled(True)
        self.folder_tree.setAcceptDrops(True)
        self.folder_tree.setDropIndicatorShown(True)
        self.folder_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.folder_tree.customContextMenuRequested.connect(self.show_folder_context_menu)
        self.folder_tree.selectionModel().selectionChanged.connect(self.folder_selected)

        left_layout.addWidget(self.folder_tree)

        folder_buttons_layout = QHBoxLayout()
        add_folder_btn = QPushButton("Add Folder")
        add_folder_btn.clicked.connect(self.add_folder)
        folder_buttons_layout.addWidget(add_folder_btn)

        left_layout.addLayout(folder_buttons_layout)
        left_panel.setLayout(left_layout)

        # Right side - password entries
        right_panel = QWidget()
        right_panel.setObjectName("RightPanel")
        right_layout = QVBoxLayout()

        entries_label = QLabel("Password Entries")
        entries_label.setObjectName("EntriesTitle")  # Set object name for styling
        right_layout.addWidget(entries_label)

        self.entry_list = QListWidget()
        self.entry_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.entry_list.customContextMenuRequested.connect(self.show_entry_context_menu)
        self.entry_list.itemDoubleClicked.connect(self.view_entry)

        right_layout.addWidget(self.entry_list)

        entry_buttons_layout = QHBoxLayout()
        add_entry_btn = QPushButton("Add Entry")
        add_entry_btn.clicked.connect(self.add_entry)
        entry_buttons_layout.addWidget(add_entry_btn)

        right_layout.addLayout(entry_buttons_layout)
        right_panel.setLayout(right_layout)

        # Add panels to splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 600])

        main_layout.addWidget(splitter)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Menu bar
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")

        change_master_action = QAction("Change Master Password", self)
        change_master_action.triggered.connect(self.change_master_password)
        file_menu.addAction(change_master_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Load data
        self.load_folders()

    def load_folders(self):
        self.folder_model.clear()
        self.folder_model.setHorizontalHeaderLabels(["Folders"])

        root_item = self.folder_model.invisibleRootItem()

        # Add "All Passwords" virtual folder
        all_passwords_item = QStandardItem("All Passwords")
        all_passwords_item.setData("all", Qt.UserRole)
        root_item.appendRow(all_passwords_item)

        # Add actual folders
        self.add_folders_recursive(root_item, self.data["folders"], "")

    def add_folders_recursive(self, parent_item, folders_dict, parent_path):
        for folder_name, folder_data in folders_dict.items():
            current_path = f"{parent_path}/{folder_name}" if parent_path else folder_name

            folder_item = QStandardItem(folder_name)
            folder_item.setData(current_path, Qt.UserRole)
            parent_item.appendRow(folder_item)

            if "subfolders" in folder_data:
                self.add_folders_recursive(folder_item, folder_data["subfolders"], current_path)

    def get_folder_dict(self, path):
        if not path:
            return self.data["folders"]

        parts = path.split("/")
        current = self.data["folders"]

        for part in parts:
            if part not in current:
                current[part] = {"subfolders": {}}
            if "subfolders" not in current[part]:
                current[part]["subfolders"] = {}
            current = current[part]["subfolders"]

        return current

    def add_folder(self):
        selected_indexes = self.folder_tree.selectedIndexes()
        parent_path = ""

        if selected_indexes:
            selected_item = self.folder_model.itemFromIndex(selected_indexes[0])
            parent_path = selected_item.data(Qt.UserRole)

            # Don't allow adding folders to "All Passwords"
            if parent_path == "all":
                parent_path = ""

        folder_name, ok = QInputDialog.getText(self, "New Folder", "Folder name:")

        if ok and folder_name:
            parent_dict = self.get_folder_dict(parent_path)

            if folder_name in parent_dict:
                QMessageBox.warning(self, "Error", f"Folder '{folder_name}' already exists")
                return

            parent_dict[folder_name] = {"subfolders": {}}

            self.save_data()
            self.load_folders()

    def show_folder_context_menu(self, position):
        indexes = self.folder_tree.selectedIndexes()
        if not indexes:
            return

        selected_item = self.folder_model.itemFromIndex(indexes[0])
        folder_path = selected_item.data(Qt.UserRole)


        if folder_path == "all":
            return

        menu = QMenu()
        rename_action = menu.addAction("Rename")
        delete_action = menu.addAction("Delete")

        action = menu.exec_(self.folder_tree.viewport().mapToGlobal(position))

        if action == rename_action:
            self.rename_folder(folder_path)
        elif action == delete_action:
            self.delete_folder(folder_path)

    def rename_folder(self, folder_path):
        parts = folder_path.split("/")
        folder_name = parts[-1]
        parent_path = "/".join(parts[:-1])

        new_name, ok = QInputDialog.getText(self, "Rename Folder", "New folder name:", text=folder_name)

        if ok and new_name and new_name != folder_name:
            parent_dict = self.get_folder_dict(parent_path)

            if new_name in parent_dict:
                QMessageBox.warning(self, "Error", f"Folder '{new_name}' already exists")
                return

            # Rename folder
            parent_dict[new_name] = parent_dict[folder_name]
            del parent_dict[folder_name]

            # Update entries
            for entry_id, entry in self.data["entries"].items():
                if entry["folder"] == folder_path:
                    new_folder_path = f"{parent_path}/{new_name}" if parent_path else new_name
                    entry["folder"] = new_folder_path

            self.save_data()
            self.load_folders()

    def delete_folder(self, folder_path):
        confirm = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete the folder '{folder_path}' and all its contents?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            parts = folder_path.split("/")
            folder_name = parts[-1]
            parent_path = "/".join(parts[:-1])

            parent_dict = self.get_folder_dict(parent_path)
            del parent_dict[folder_name]

            # Delete entries in this folder and subfolders
            entries_to_delete = []
            for entry_id, entry in self.data["entries"].items():
                if entry["folder"] == folder_path or entry["folder"].startswith(f"{folder_path}/"):
                    entries_to_delete.append(entry_id)

            for entry_id in entries_to_delete:
                del self.data["entries"][entry_id]

            self.save_data()
            self.load_folders()

    def folder_selected(self):
        indexes = self.folder_tree.selectedIndexes()
        if not indexes:
            return

        selected_item = self.folder_model.itemFromIndex(indexes[0])
        folder_path = selected_item.data(Qt.UserRole)

        self.load_entries(folder_path)

    def load_entries(self, folder_path):
        self.entry_list.clear()

        for entry_id, entry in self.data["entries"].items():
            if folder_path == "all" or entry["folder"] == folder_path:
                item = QListWidgetItem(entry["title"])
                item.setData(Qt.UserRole, entry_id)
                self.entry_list.addItem(item)

    def add_entry(self):
        indexes = self.folder_tree.selectedIndexes()
        if not indexes:
            QMessageBox.warning(self, "Warning", "Please select a folder first")
            return

        selected_item = self.folder_model.itemFromIndex(indexes[0])
        folder_path = selected_item.data(Qt.UserRole)

        # Don't allow adding entries to "All Passwords"
        if folder_path == "all":
            QMessageBox.warning(self, "Warning",
                                "Cannot add entries to 'All Passwords'. Please select a specific folder.")
            return

        dialog = PasswordEntryDialog(parent=self)
        if dialog.exec_() == QDialog.Accepted:
            entry_data = dialog.get_data()
            if entry_data:
                entry_id = secrets.token_hex(8)
                entry_data["folder"] = folder_path
                self.data["entries"][entry_id] = entry_data

                self.save_data()
                self.load_entries(folder_path)

    def view_entry(self, item):
        entry_id = item.data(Qt.UserRole)
        entry_data = self.data["entries"][entry_id]

        dialog = PasswordEntryDialog(entry_data, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            updated_data = dialog.get_data()
            if updated_data:
                updated_data["folder"] = entry_data["folder"]  # Preserve folder
                self.data["entries"][entry_id] = updated_data

                self.save_data()

                # Refresh the entry list
                indexes = self.folder_tree.selectedIndexes()
                if indexes:
                    selected_item = self.folder_model.itemFromIndex(indexes[0])
                    folder_path = selected_item.data(Qt.UserRole)
                    self.load_entries(folder_path)

    def show_entry_context_menu(self, position):
        item = self.entry_list.itemAt(position)
        if not item:
            return

        entry_id = item.data(Qt.UserRole)

        menu = QMenu()
        edit_action = menu.addAction("Edit")
        delete_action = menu.addAction("Delete")

        action = menu.exec_(self.entry_list.viewport().mapToGlobal(position))

        if action == edit_action:
            self.view_entry(item)
        elif action == delete_action:
            self.delete_entry(entry_id)

    def delete_entry(self, entry_id):
        confirm = QMessageBox.question(
            self, "Confirm Deletion",
            "Are you sure you want to delete this password entry?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            del self.data["entries"][entry_id]
            self.save_data()

            # Refresh the entry list
            indexes = self.folder_tree.selectedIndexes()
            if indexes:
                selected_item = self.folder_model.itemFromIndex(indexes[0])
                folder_path = selected_item.data(Qt.UserRole)
                self.load_entries(folder_path)

    def change_master_password(self):
        # Verify current password first
        dialog = MasterPasswordDialog(is_new=False, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return

        current_password = dialog.get_password()
        salt = self.password_manager.load_salt(self.salt_file)

        try:
            # Verify current password
            temp_manager = PasswordManager()
            temp_manager.setup_encryption(current_password, salt)
            temp_manager.load_data(self.data_file)

            # Get new password
            new_dialog = MasterPasswordDialog(is_new=True, parent=self)
            if new_dialog.exec_() != QDialog.Accepted:
                return

            new_password = new_dialog.get_password()

            # Re-encrypt data with new password
            new_salt = self.password_manager.setup_encryption(new_password)
            self.password_manager.save_salt(self.salt_file, new_salt)
            self.save_data()

            QMessageBox.information(self, "Success", "Master password changed successfully")
        except ValueError:
            QMessageBox.critical(self, "Error", "Current password is incorrect")

    def save_data(self):
        self.password_manager.save_data(self.data_file, self.data)

    def closeEvent(self, event):
        self.save_data()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    apply_dark_theme(app)
    window = PasswordKeeperApp()
    window.show()
    sys.exit(app.exec_())

