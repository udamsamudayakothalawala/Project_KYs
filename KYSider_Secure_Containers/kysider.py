import os
import sys
import json
import logging

from PyQt5.QtCore import QObject, QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPlainTextEdit,
    QPushButton,
    QInputDialog,
    QRadioButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QStyle,
)

from kysider_extractor import KYSiderExtractor
from kysider_keys import (
    RECIPIENT_KEY_METHODS,
    generate_recipient_keypair,
    recipient_key_id,
    save_recipient_private_key,
    save_recipient_public_key,
)
from kysider_packager import KYSiderPackager
from kysider_security import format_container_security_report, inspect_source_path

def get_secure_path(filename):
    """ Guarantees files can communicate and locate assets inside the Inno Setup folder """
    # sys.argv[0] points directly to the location of your running kysider.exe
    base_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(base_path, filename)

logger = logging.getLogger("kysider")


class LogEmitter(QObject):
    message = pyqtSignal(str)


class QtLogHandler(logging.Handler):
    def __init__(self, emitter):
        super().__init__()
        self.emitter = emitter

    def emit(self, record):
        self.emitter.message.emit(self.format(record))


class BoundIDDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Restore chunked container")
        self.setMinimumWidth(500)
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        layout.addWidget(QLabel("Browse the creator's BoundID.json or enter the Bound ID manually."))
        form = QFormLayout()
        self.bound_id_input = QLineEdit()
        self.bound_id_input.setPlaceholderText("Bound ID")
        token_row = QHBoxLayout()
        token_row.addWidget(self.bound_id_input, 1)
        browse_button = QPushButton("Browse JSON")
        browse_button.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        browse_button.clicked.connect(self._browse_bound_id)
        token_row.addWidget(browse_button)
        form.addRow("Bound ID", token_row)
        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Restore")
        buttons.accepted.connect(self._accept_if_valid)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_bound_id(self):
        logger.info("Selecting BoundID JSON for recovery.")
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select BoundID.json",
            "",
            "Bound ID JSON (*.json)",
        )
        if not path:
            logger.info("BoundID JSON selection cancelled.")
            return
        try:
            if os.path.getsize(path) > 64 * 1024:
                raise ValueError("Bound ID file is too large.")
            with open(path, "r", encoding="utf-8") as bound_file:
                payload = json.load(bound_file)
            bound_id = payload.get("bound_id") if isinstance(payload, dict) else None
            if not isinstance(bound_id, str) or len(bound_id) < 32:
                raise ValueError("This JSON file does not contain a valid Bound ID.")
            self.bound_id_input.setText(bound_id)
            logger.info("BoundID loaded from %s.", path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            logger.exception("Could not load BoundID from selected JSON.")
            QMessageBox.warning(self, "Invalid Bound ID file", str(error))

    def _accept_if_valid(self):
        if len(self.bound_id_input.text().strip()) < 32:
            logger.warning("Recovery restore validation failed: BoundID is missing or invalid.")
            QMessageBox.warning(self, "Bound ID required", "Enter a valid Bound ID or browse its JSON file.")
            return
        logger.info("Recovery BoundID accepted for verification.")
        self.accept()

    @property
    def bound_id(self):
        return self.bound_id_input.text().strip()


class ContainerCreatedDialog(QDialog):
    def __init__(self, container_path, bound_id, enc_id, parent=None):
        super().__init__(parent)
        self.container_path = container_path
        self.bound_id = bound_id
        self.enc_id = enc_id
        self.setWindowTitle("Container created")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("The .kysd container was created successfully."))
        layout.addWidget(QLabel("Save or copy any IDs you need. This window stays open until you close it."))

        actions = QHBoxLayout()
        actions.addWidget(self._action_button("Copy EncID", self._copy_enc_id))
        actions.addWidget(self._action_button("Save EncID", self._save_enc_id))
        actions.addWidget(self._action_button("Save BoundID", self._save_bound_id))
        actions.addWidget(self._action_button("Save both IDs", self._save_both_ids))
        actions.addWidget(self._action_button("Copy Bound ID", self._copy_bound_id))
        layout.addLayout(actions)

        close_button = QPushButton("Close")
        close_button.clicked.connect(self._close_dialog)
        layout.addWidget(close_button, 0, Qt.AlignRight)

    def _action_button(self, label, callback):
        button = QPushButton(label)
        button.clicked.connect(callback)
        return button

    def _close_dialog(self):
        logger.info("Container ID dialog closed.")
        self.accept()

    def _copy_enc_id(self):
        QApplication.clipboard().setText(self.enc_id)
        logger.info("EncID copied to clipboard.")
        QMessageBox.information(self, "EncID copied", "EncID copied to the clipboard.")

    def _copy_bound_id(self):
        QApplication.clipboard().setText(self.bound_id)
        logger.info("BoundID copied to clipboard.")
        QMessageBox.information(self, "Bound ID copied", "Bound ID copied to the clipboard.")

    def _save_enc_id(self):
        logger.info("Saving EncID credentials.")
        self._save_id_json(
            {"format_version": 1, "container": os.path.basename(self.container_path), "enc_id": self.enc_id},
            "encID.json",
        )

    def _save_bound_id(self):
        logger.info("Saving BoundID credentials.")
        self._save_id_json(
            {"format_version": 1, "container": os.path.basename(self.container_path), "bound_id": self.bound_id},
            "BoundID.json",
        )

    def _save_both_ids(self):
        logger.info("Saving EncID and BoundID credentials.")
        self._save_id_json(
            {
                "format_version": 1,
                "container": os.path.basename(self.container_path),
                "enc_id": self.enc_id,
                "bound_id": self.bound_id,
            },
            "encID-BoundID.json",
        )

    def _save_id_json(self, payload, default_name):
        logger.info("Opening save dialog for %s.", default_name)
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save container IDs",
            os.path.join(os.path.dirname(self.container_path), default_name),
            "JSON files (*.json)",
        )
        if not path:
            logger.info("Credential save cancelled.")
            return
        if not path.lower().endswith(".json"):
            path += ".json"
        try:
            with open(path, "w", encoding="utf-8") as output_file:
                json.dump(payload, output_file, sort_keys=True, indent=2)
            logger.info("Credential JSON saved to %s.", path)
            QMessageBox.information(self, "IDs saved", f"Credential JSON saved to:\n{path}")
        except OSError as error:
            logger.exception("Could not save credential JSON.")
            QMessageBox.critical(self, "Could not save IDs", str(error))


class TaskWorker(QThread):
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, operation):
        super().__init__()
        self.operation = operation

    def run(self):
        try:
            self.succeeded.emit(self.operation())
        except Exception as error:
            logger.exception("Background operation failed.")
            self.failed.emit(str(error))


class KYSiderWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KYSider Secure Containers")
        self.setMinimumSize(560, 420)
        self.resize(1100, 700)
        self.workers = set()
        self.active_extractor = None
        self.active_container_path = None
        self._pending_log_messages = []
        self.log_emitter = LogEmitter(self)
        self.log_emitter.message.connect(self._append_log_message)
        self.log_handler = QtLogHandler(self.log_emitter)
        self.log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s  %(message)s", "%H:%M:%S"))
        logger.setLevel(logging.INFO)
        logger.addHandler(self.log_handler)

        central = QWidget()
        central.setObjectName("workspace")
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(12)

        eyebrow = QLabel("KYSIDER SECURE CONTAINERS")
        eyebrow.setObjectName("eyebrow")
        heading = QLabel("Container workspace")
        heading.setObjectName("heading")
        layout.addWidget(eyebrow)
        layout.addWidget(heading)

        workspace_splitter = QSplitter(Qt.Horizontal)
        workspace_splitter.setChildrenCollapsible(False)

        left_panel = QWidget()
        left_panel.setObjectName("toolPanel")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._make_scrollable_page(self._build_package_page()), "Package")
        self.tabs.addTab(self._make_scrollable_page(self._build_unlock_page()), "Unlock")
        self.tabs.addTab(self._make_scrollable_page(self._build_chunked_files_page()), "Chunked Files")
        left_layout.addWidget(self.tabs, 1)

        self.show_passwords = QCheckBox("Show package passwords")
        self.show_passwords.toggled.connect(self._toggle_password_visibility)
        left_layout.addWidget(self.show_passwords)
        workspace_splitter.addWidget(left_panel)
        workspace_splitter.addWidget(self._build_log_page())
        for message in self._pending_log_messages:
            self.activity_log.appendPlainText(message)
        self._pending_log_messages.clear()
        workspace_splitter.setStretchFactor(0, 3)
        workspace_splitter.setStretchFactor(1, 2)
        self.workspace_splitter = workspace_splitter
        layout.addWidget(workspace_splitter, 1)
        self._update_workspace_orientation()

        self.setStyleSheet(
            """
            QWidget#workspace, QWidget#toolPanel { background: #252526; }
            QWidget#logPanel { background: #2d2d2d; }
            QWidget#page { background-color: #2d2d2d; }
            QWidget { color: #d4d4d4; font-family: 'Segoe UI'; font-size: 13px; }
            QLabel#eyebrow { color: #8e8e8e; font-size: 10px; font-weight: 700; }
            QLabel#heading { color: #f0f0f0; font-size: 21px; font-weight: 600; }
            QTabWidget::pane { background: #2d2d2d; border: 1px solid #3f3f3f; }
            QTabBar { background: #252526; }
            QTabBar::tab {
                background: #303030; color: #a9a9a9; border: 1px solid #3c3c3c;
                border-bottom: none; padding: 9px 16px; margin-right: 2px;
            }
            QTabBar::tab:selected { background: #3a3a3a; color: #f2f2f2; border-top: 2px solid #4a90e2; }
            QTabBar::tab:hover:!selected { background: #353535; color: #e4e4e4; }
            QLabel#pageTitle { color: #f0f0f0; font-size: 17px; font-weight: 600; }
            QLabel#status { background: #353535; color: #c4c4c4; padding: 9px 11px; border-left: 3px solid #4a90e2; }
            QLabel#warning { background: #3b3328; color: #e8c98d; padding: 11px; border-left: 3px solid #d6a64d; }
            QLineEdit, QComboBox, QListWidget, QPlainTextEdit {
                background: #1e1e1e; color: #dedede; border: 1px solid #454545;
                padding: 7px 9px; selection-background-color: #264f78;
            }
            QLineEdit:focus, QComboBox:focus, QListWidget:focus, QPlainTextEdit:focus { border: 1px solid #4a90e2; }
            QComboBox::drop-down { border: none; width: 24px; }
            QComboBox QAbstractItemView { background: #2d2d2d; color: #dedede; selection-background-color: #264f78; }
            QPushButton {
                background: #3a3a3a; color: #e0e0e0; border: 1px solid #505050;
                padding: 8px 11px; min-height: 18px;
            }
            QPushButton:hover { background: #454545; border-color: #626262; }
            QPushButton:pressed { background: #303030; }
            QPushButton#primary { background: #0e639c; color: #ffffff; border: 1px solid #1177bb; font-weight: 600; padding: 9px 14px; }
            QPushButton#primary:hover { background: #1177bb; }
            QPushButton:disabled { color: #777777; background: #303030; border-color: #3a3a3a; }
            QCheckBox, QRadioButton { spacing: 8px; color: #c6c6c6; }
            QCheckBox::indicator, QRadioButton::indicator { width: 14px; height: 14px; }
            QCheckBox::indicator:checked, QRadioButton::indicator:checked { background: #0e639c; border: 1px solid #4a90e2; }
            QProgressBar { background: #1e1e1e; border: 1px solid #414141; }
            QProgressBar::chunk { background: #0e639c; }
            QSplitter::handle { background: #1e1e1e; }
            QSplitter::handle:hover { background: #4a90e2; }
            QScrollArea { background: #2d2d2d; border: none; }
            QScrollArea QWidget#page { background-color: #2d2d2d; }
            QScrollBar:vertical { background: #252526; width: 12px; margin: 0; }
            QScrollBar::handle:vertical { background: #555555; min-height: 24px; }
            QScrollBar::handle:vertical:hover { background: #6a6a6a; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            """
        )

    def _make_scrollable_page(self, page):
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QScrollArea.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setWidget(page)
        return scroll_area

    def _update_workspace_orientation(self):
        orientation = Qt.Horizontal if self.width() >= 1000 else Qt.Vertical
        if self.workspace_splitter.orientation() == orientation:
            return
        self.workspace_splitter.setOrientation(orientation)
        if orientation == Qt.Horizontal:
            self.workspace_splitter.setSizes([self.width() * 3 // 5, self.width() * 2 // 5])
        else:
            self.workspace_splitter.setSizes([self.height() * 3 // 5, self.height() * 2 // 5])

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_workspace_orientation()

    def _build_package_page(self):
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(16)

        title = QLabel("Create a container")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        form = QFormLayout()
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)

        self.source_path = QLineEdit()
        self.source_path.setPlaceholderText("Choose a file or folder")
        source_row = QHBoxLayout()
        source_row.addWidget(self.source_path, 1)
        source_file_button = QPushButton("File")
        source_file_button.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        source_file_button.clicked.connect(self._browse_source_file)
        source_folder_button = QPushButton("Folder")
        source_folder_button.setIcon(self.style().standardIcon(QStyle.SP_DirIcon))
        source_folder_button.clicked.connect(self._browse_source_folder)
        source_row.addWidget(source_file_button)
        source_row.addWidget(source_folder_button)
        form.addRow("Source", source_row)

        self.output_path = QLineEdit()
        self.output_path.setPlaceholderText("Save as .kysd")
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_path, 1)
        output_button = QPushButton("Save as")
        output_button.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        output_button.clicked.connect(self._browse_output_path)
        output_row.addWidget(output_button)
        form.addRow("Container", output_row)

        self.package_password = QLineEdit()
        self.package_password.setEchoMode(QLineEdit.Password)
        self.package_password.setPlaceholderText("Master password")
        form.addRow("Password", self.package_password)

        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.setPlaceholderText("Enter it again")
        form.addRow("Confirm", self.confirm_password)

        self.encryption_group = QButtonGroup(page)
        encryption_row = QHBoxLayout()
        self.aes_radio = QRadioButton("AES-256-GCM")
        self.chacha_radio = QRadioButton("ChaCha20-Poly1305")
        self.aes_radio.setChecked(True)
        self.encryption_group.addButton(self.aes_radio)
        self.encryption_group.addButton(self.chacha_radio)
        encryption_row.addWidget(self.aes_radio)
        encryption_row.addWidget(self.chacha_radio)
        encryption_row.addStretch(1)
        form.addRow("Encryption", encryption_row)

        self.key_wrapping_method = QComboBox()
        self.key_wrapping_method.addItems(("Password + EncID only",) + RECIPIENT_KEY_METHODS)
        self.key_wrapping_method.currentIndexChanged.connect(self._update_recipient_key_controls)
        form.addRow("Recipient key layer", self.key_wrapping_method)

        self.recipient_public_key_path = QLineEdit()
        self.recipient_public_key_path.setPlaceholderText("Select recipient public key JSON")
        public_key_row = QHBoxLayout()
        public_key_row.addWidget(self.recipient_public_key_path, 1)
        self.recipient_public_key_button = QPushButton("Browse")
        self.recipient_public_key_button.clicked.connect(self._browse_recipient_public_key)
        public_key_row.addWidget(self.recipient_public_key_button)
        form.addRow("Recipient public key", public_key_row)

        self.generate_recipient_key_button = QPushButton("Generate recipient key pair")
        self.generate_recipient_key_button.clicked.connect(self._generate_recipient_keypair)
        form.addRow("", self.generate_recipient_key_button)
        self._update_recipient_key_controls()
        layout.addLayout(form)

        self.package_button = QPushButton("Create .kysd container")
        self.package_button.setObjectName("primary")
        self.package_button.clicked.connect(self._create_container)
        layout.addWidget(self.package_button, 0, Qt.AlignLeft)

        self.package_progress = QProgressBar()
        self.package_progress.setRange(0, 0)
        self.package_progress.setTextVisible(False)
        self.package_progress.setFixedHeight(6)
        self.package_progress.hide()
        layout.addWidget(self.package_progress)

        self.package_status = QLabel("Ready")
        self.package_status.setObjectName("status")
        layout.addWidget(self.package_status)
        layout.addStretch(1)
        return page

    def _build_unlock_page(self):
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(16)

        title = QLabel("Unlock a container")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        warning = QLabel(
            "Version 3 through 5 containers require both password and EncID. Recipient-key containers also require the recipient's protected private key. Three failed authentication attempts move supported containers into a private recovery set."
        )
        warning.setObjectName("warning")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        form = QFormLayout()
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)

        self.container_path = QLineEdit()
        self.container_path.setPlaceholderText("Choose a .kysd file")
        container_row = QHBoxLayout()
        container_row.addWidget(self.container_path, 1)
        container_button = QPushButton("Browse")
        container_button.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        container_button.clicked.connect(self._browse_container)
        container_row.addWidget(container_button)
        form.addRow("Container", container_row)

        self.extract_path = QLineEdit(os.path.abspath("./extracted_payload"))
        extract_row = QHBoxLayout()
        extract_row.addWidget(self.extract_path, 1)
        extract_button = QPushButton("Folder")
        extract_button.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        extract_button.clicked.connect(self._browse_extract_folder)
        extract_row.addWidget(extract_button)
        form.addRow("Extract to", extract_row)

        self.unlock_password = QLineEdit()
        self.unlock_password.setEchoMode(QLineEdit.Password)
        self.unlock_password.setPlaceholderText("Container password")
        form.addRow("Password", self.unlock_password)

        self.unlock_enc_id = QLineEdit()
        self.unlock_enc_id.setEchoMode(QLineEdit.Password)
        self.unlock_enc_id.setPlaceholderText("EncID from encID.json")
        enc_id_row = QHBoxLayout()
        enc_id_row.addWidget(self.unlock_enc_id, 1)
        enc_id_browse = QPushButton("Browse JSON")
        enc_id_browse.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        enc_id_browse.clicked.connect(self._browse_enc_id)
        enc_id_row.addWidget(enc_id_browse)
        form.addRow("EncID", enc_id_row)

        self.recipient_private_key_path = QLineEdit()
        self.recipient_private_key_path.setPlaceholderText("Required for recipient-key containers")
        private_key_row = QHBoxLayout()
        private_key_row.addWidget(self.recipient_private_key_path, 1)
        private_key_button = QPushButton("Browse")
        private_key_button.clicked.connect(self._browse_recipient_private_key)
        private_key_row.addWidget(private_key_button)
        form.addRow("Recipient private key", private_key_row)

        self.recipient_key_passphrase = QLineEdit()
        self.recipient_key_passphrase.setEchoMode(QLineEdit.Password)
        self.recipient_key_passphrase.setPlaceholderText("Private-key file passphrase")
        form.addRow("Key passphrase", self.recipient_key_passphrase)

        layout.addLayout(form)

        action_row = QHBoxLayout()
        self.unlock_button = QPushButton("Unlock and extract")
        self.unlock_button.setObjectName("primary")
        self.unlock_button.clicked.connect(self._unlock_container)
        action_row.addWidget(self.unlock_button)
        report_button = QPushButton("Container security report")
        report_button.clicked.connect(self._show_container_security_report)
        action_row.addWidget(report_button)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        self.unlock_progress = QProgressBar()
        self.unlock_progress.setRange(0, 0)
        self.unlock_progress.setTextVisible(False)
        self.unlock_progress.setFixedHeight(6)
        self.unlock_progress.hide()
        layout.addWidget(self.unlock_progress)

        self.unlock_status = QLabel("Ready")
        self.unlock_status.setObjectName("status")
        layout.addWidget(self.unlock_status)
        layout.addStretch(1)
        return page

    def _build_chunked_files_page(self):
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(14)

        title = QLabel("Chunked files")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        layout.addWidget(QLabel("Select a recovery set to restore it with a Bound ID."))

        self.chunked_files_list = QListWidget()
        self.chunked_files_list.itemClicked.connect(self._restore_selected_chunked_file)
        layout.addWidget(self.chunked_files_list, 1)

        actions = QHBoxLayout()
        refresh_button = QPushButton("Refresh list")
        refresh_button.clicked.connect(self._refresh_chunked_files)
        actions.addWidget(refresh_button)
        self.chunked_restore_button = QPushButton("Restore selected")
        self.chunked_restore_button.setObjectName("primary")
        self.chunked_restore_button.clicked.connect(self._restore_selected_chunked_file)
        actions.addWidget(self.chunked_restore_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.chunked_progress = QProgressBar()
        self.chunked_progress.setRange(0, 0)
        self.chunked_progress.setTextVisible(False)
        self.chunked_progress.setFixedHeight(6)
        self.chunked_progress.hide()
        layout.addWidget(self.chunked_progress)

        self.chunked_status = QLabel("Ready")
        self.chunked_status.setObjectName("status")
        layout.addWidget(self.chunked_status)
        self._refresh_chunked_files()
        return page

    def _build_log_page(self):
        page = QWidget()
        page.setObjectName("logPanel")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(14)

        title = QLabel("Activity log")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        self.activity_log = QPlainTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMaximumBlockCount(1000)
        layout.addWidget(self.activity_log, 1)

        clear_button = QPushButton("Clear log")
        clear_button.clicked.connect(self._clear_activity_log)
        layout.addWidget(clear_button, 0, Qt.AlignRight)
        return page

    def _append_log_message(self, message):
        if hasattr(self, "activity_log"):
            self.activity_log.appendPlainText(message)
        else:
            self._pending_log_messages.append(message)

    def _clear_activity_log(self):
        self.activity_log.clear()
        logger.info("Activity log cleared.")

    def _toggle_password_visibility(self, visible):
        echo_mode = QLineEdit.Normal if visible else QLineEdit.Password
        self.package_password.setEchoMode(echo_mode)
        self.confirm_password.setEchoMode(echo_mode)

    def _update_recipient_key_controls(self):
        requires_recipient_key = self.key_wrapping_method.currentText() in RECIPIENT_KEY_METHODS
        self.recipient_public_key_path.setEnabled(requires_recipient_key)
        self.recipient_public_key_button.setEnabled(requires_recipient_key)
        self.generate_recipient_key_button.setEnabled(requires_recipient_key)

    def _browse_recipient_public_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select recipient public key",
            "",
            "KYSider public key (*.json)",
        )
        if path:
            self.recipient_public_key_path.setText(path)
            logger.info("Recipient public key selected: %s.", path)
        else:
            logger.info("Recipient public key selection cancelled.")

    def _browse_recipient_private_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select recipient private key",
            "",
            "KYSider private key (*.json)",
        )
        if path:
            self.recipient_private_key_path.setText(path)
            logger.info("Recipient private key selected: %s.", path)
        else:
            logger.info("Recipient private key selection cancelled.")

    def _generate_recipient_keypair(self):
        algorithm = self.key_wrapping_method.currentText()
        if algorithm not in RECIPIENT_KEY_METHODS:
            QMessageBox.warning(self, "Select a key method", "Choose RSA, ECC, or ML-KEM first.")
            return
        passphrase, accepted = QInputDialog.getText(
            self,
            "Protect private key",
            "Set a private-key passphrase (at least 12 characters):",
            QLineEdit.Password,
        )
        if not accepted:
            logger.info("Recipient key generation cancelled at passphrase prompt.")
            return
        confirmation, accepted = QInputDialog.getText(
            self,
            "Confirm private-key passphrase",
            "Enter the private-key passphrase again:",
            QLineEdit.Password,
        )
        if not accepted:
            logger.info("Recipient key generation cancelled at confirmation prompt.")
            return
        if passphrase != confirmation or len(passphrase) < 12:
            logger.warning("Recipient key generation stopped because passphrase validation failed.")
            QMessageBox.warning(
                self,
                "Invalid passphrase",
                "Passphrases must match and contain at least 12 characters.",
            )
            return

        public_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save recipient public key",
            f"recipient-{algorithm.lower().replace(' ', '-').replace('-', '_')}.public.json",
            "KYSider public key (*.json)",
        )
        if not public_path:
            logger.info("Recipient key generation cancelled at public-key save dialog.")
            return
        private_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save protected recipient private key",
            f"recipient-{algorithm.lower().replace(' ', '-').replace('-', '_')}.private.json",
            "KYSider private key (*.json)",
        )
        if not private_path:
            logger.info("Recipient key generation cancelled at private-key save dialog.")
            return
        if os.path.normcase(os.path.abspath(public_path)) == os.path.normcase(os.path.abspath(private_path)):
            QMessageBox.warning(self, "Choose separate files", "Public and private keys must use different files.")
            return

        try:
            public_key, private_key = generate_recipient_keypair(algorithm)
            key_id = recipient_key_id(algorithm, public_key)
            save_recipient_private_key(private_path, algorithm, private_key, key_id, passphrase)
            save_recipient_public_key(public_path, algorithm, public_key)
            self.recipient_public_key_path.setText(public_path)
            logger.info("Generated %s recipient key pair.", algorithm)
            QMessageBox.information(
                self,
                "Recipient key pair generated",
                "Share the public key with the container maker. Keep the encrypted private key and its passphrase safe.",
            )
        except (OSError, ValueError, RuntimeError) as error:
            logger.exception("Could not generate or save recipient key pair.")
            QMessageBox.critical(self, "Key generation failed", str(error))

    def _browse_source_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select source file")
        if path:
            self.source_path.setText(path)
            logger.info("Source file selected: %s.", path)
        else:
            logger.info("Source file selection cancelled.")

    def _browse_source_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select source folder")
        if path:
            self.source_path.setText(path)
            logger.info("Source folder selected: %s.", path)
        else:
            logger.info("Source folder selection cancelled.")

    def _browse_output_path(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save KYSider container",
            "secure_vault.kysd",
            "KYSider container (*.kysd)",
        )
        if path:
            if not path.lower().endswith(".kysd"):
                path += ".kysd"
            self.output_path.setText(path)
            logger.info("Container output path selected: %s.", path)
        else:
            logger.info("Container output path selection cancelled.")

    def _browse_container(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select KYSider container",
            "",
            "KYSider container (*.kysd);;All files (*)",
        )
        if path:
            self.container_path.setText(path)
            logger.info("Container selected: %s.", path)
            self._generate_container_security_report(path, show_dialog=False)
        else:
            logger.info("Container selection cancelled.")

    def _browse_extract_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select extraction folder")
        if path:
            self.extract_path.setText(path)
            logger.info("Extraction folder selected: %s.", path)
        else:
            logger.info("Extraction folder selection cancelled.")

    def _browse_enc_id(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select EncID JSON",
            "",
            "EncID JSON (*.json)",
        )
        if not path:
            return
        try:
            if os.path.getsize(path) > 64 * 1024:
                raise ValueError("EncID file is too large.")
            with open(path, "r", encoding="utf-8") as enc_id_file:
                payload = json.load(enc_id_file)
            enc_id = payload.get("enc_id") if isinstance(payload, dict) else None
            if not isinstance(enc_id, str) or len(enc_id) < 32:
                raise ValueError("This JSON file does not contain a valid EncID.")
            self.unlock_enc_id.setText(enc_id)
            logger.info("EncID loaded from %s.", path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            logger.exception("Could not load EncID from selected JSON.")
            QMessageBox.warning(self, "Invalid EncID file", str(error))

    def _create_container(self):
        source = self.source_path.text().strip()
        destination = self.output_path.text().strip()
        password = self.package_password.text()
        confirmation = self.confirm_password.text()
        if not source or not destination or not password:
            logger.warning("Container creation validation failed: required fields are missing.")
            QMessageBox.warning(self, "Missing information", "Select a source, container path, and password.")
            return
        if password != confirmation:
            logger.warning("Container creation validation failed: password confirmation did not match.")
            QMessageBox.warning(self, "Password mismatch", "The passwords do not match.")
            return

        overwrite = False
        if os.path.lexists(destination):
            answer = QMessageBox.question(
                self,
                "Replace container?",
                "A file already exists at this path. Replace it?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                logger.info("Container replacement declined.")
                return
            overwrite = True

        encryption_method = self.encryption_group.checkedButton().text()
        key_wrapping_method = self.key_wrapping_method.currentText()
        recipient_public_key_path = self.recipient_public_key_path.text().strip()
        if key_wrapping_method in RECIPIENT_KEY_METHODS and not recipient_public_key_path:
            logger.warning("Recipient-key packaging blocked because no public key was selected.")
            QMessageBox.warning(
                self,
                "Recipient public key required",
                "Choose the recipient's public key or generate a recipient key pair.",
            )
            return
        logger.info("Checking source files for potentially risky file types.")
        self.package_status.setText("Checking source files...")
        self._start_task(
            lambda: inspect_source_path(source),
            lambda findings: self._source_inspection_finished(
                findings,
                source,
                destination,
                password,
                encryption_method,
                overwrite,
                key_wrapping_method,
                recipient_public_key_path,
            ),
            self.package_status,
            self.package_progress,
        )

    def _source_inspection_finished(
        self,
        findings,
        source,
        destination,
        password,
        encryption_method,
        overwrite,
        key_wrapping_method,
        recipient_public_key_path,
    ):
        self._set_busy(False)
        suspicious_paths, suspicious_count = findings
        if suspicious_count:
            displayed_paths = "\n".join(f"- {path}" for path in suspicious_paths)
            if suspicious_count > len(suspicious_paths):
                displayed_paths += f"\n- ... and {suspicious_count - len(suspicious_paths)} more"
            answer = QMessageBox.warning(
                self,
                "Potentially risky source files",
                "The source contains executable, script, installer, or shortcut files. "
                "KYSider does not run or malware-scan them.\n\n"
                f"{displayed_paths}\n\nContinue packaging these files?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                logger.warning("Container creation cancelled after potentially risky source files were found.")
                self.package_status.setText("Packaging cancelled after source warning")
                return

        self._start_package_creation(
            source,
            destination,
            password,
            encryption_method,
            overwrite,
            key_wrapping_method,
            recipient_public_key_path,
        )

    def _start_package_creation(
        self,
        source,
        destination,
        password,
        encryption_method,
        overwrite,
        key_wrapping_method="Password + EncID only",
        recipient_public_key_path="",
    ):
        def operation():
            logger.info("Creating a container from %s.", source)
            packager = KYSiderPackager(destination, encryption_method)
            packager.create_container(
                source,
                password,
                overwrite=overwrite,
                key_wrapping_method=key_wrapping_method,
                recipient_public_key_path=recipient_public_key_path,
            )
            return packager.container_name, packager.bound_id, packager.enc_id

        logger.info("Container creation started.")
        self.package_status.setText("Packaging and encrypting...")
        self._start_task(operation, self._package_finished, self.package_status, self.package_progress)

    def _package_finished(self, result):
        self._set_busy(False)
        container_path, bound_id, enc_id = result
        self.package_status.setText(f"Created {container_path}")
        logger.info("Container creation completed: %s.", container_path)
        ContainerCreatedDialog(container_path, bound_id, enc_id, self).exec_()

    def _unlock_container(self):
        container_path = self.container_path.text().strip()
        extract_path = self.extract_path.text().strip()
        password = self.unlock_password.text()
        enc_id = self.unlock_enc_id.text().strip()
        recipient_private_key_path = self.recipient_private_key_path.text().strip()
        recipient_key_passphrase = self.recipient_key_passphrase.text()
        if not container_path or not extract_path:
            logger.warning("Unlock validation failed: container or extraction folder is missing.")
            QMessageBox.warning(self, "Missing information", "Select a container and extraction folder.")
            return

        normalized_path = os.path.realpath(os.path.abspath(container_path))
        if self.active_container_path != normalized_path:
            try:
                self.active_extractor = KYSiderExtractor(normalized_path)
                self.active_container_path = normalized_path
            except Exception as error:
                logger.exception("Could not open selected container.")
                QMessageBox.critical(self, "Container error", str(error))
                return
        extractor = self.active_extractor
        if extractor.format_version == 5 and (not recipient_private_key_path or not recipient_key_passphrase):
            logger.warning("Recipient-key unlock blocked because private key credentials are missing.")
            QMessageBox.warning(
                self,
                "Recipient private key required",
                "This container requires the recipient's private-key file and its passphrase, in addition to the password and EncID.",
            )
            return

        def operation():
            logger.info("Unlock and extraction started for %s.", normalized_path)
            return extractor, extractor.unlock(
                password,
                enc_id,
                extract_path,
                recipient_private_key_path,
                recipient_key_passphrase,
            )

        self.unlock_status.setText("Verifying and extracting...")
        self._start_task(operation, self._unlock_finished, self.unlock_status, self.unlock_progress)

    def _show_container_security_report(self):
        container_path = self.container_path.text().strip()
        if not container_path:
            logger.warning("Container security report requested without a selected container.")
            QMessageBox.warning(self, "No container selected", "Select a container to generate its security report.")
            return
        self._generate_container_security_report(container_path, show_dialog=True)

    def _generate_container_security_report(self, container_path, show_dialog):
        normalized_path = os.path.realpath(os.path.abspath(container_path))
        def operation():
            extractor = KYSiderExtractor(normalized_path)
            return format_container_security_report(extractor.metadata, os.path.getsize(normalized_path))

        logger.info("Generating container security report for %s.", normalized_path)
        self._start_task(
            operation,
            lambda report: self._security_report_finished(report, show_dialog),
            self.unlock_status,
            self.unlock_progress,
        )

    def _security_report_finished(self, report, show_dialog=True):
        self._set_busy(False)
        logger.info("Container security report:\n%s", report)
        self.unlock_status.setText("Security report added to Activity Log")
        if show_dialog:
            QMessageBox.information(self, "Container security report", report)

    def _unlock_finished(self, result):
        self._set_busy(False)
        extractor, success = result
        if success:
            logger.info("Unlock and extraction completed.")
            self.active_extractor = None
            self.active_container_path = None
            self.unlock_status.setText("Unlocked successfully")
            QMessageBox.information(self, "Unlocked", "The payload was extracted successfully.")
            if extractor.suspicious_files:
                sample = "\n".join(f"- {path}" for path in extractor.suspicious_files[:50])
                remaining = len(extractor.suspicious_files) - 50
                if remaining > 0:
                    sample += f"\n- ... and {remaining} more"
                logger.warning(
                    "Extracted potentially risky files (%d): %s",
                    len(extractor.suspicious_files),
                    ", ".join(extractor.suspicious_files[:50]),
                )
                QMessageBox.warning(
                    self,
                    "Potentially risky files extracted",
                    "The extracted payload contains executable, script, installer, or shortcut file types. "
                    "KYSider did not run or malware-scan them. Do not open files you do not trust.\n\n"
                    f"{sample}",
                )
            if extractor.format_version in (1, 2):
                QMessageBox.warning(
                    self,
                    "Legacy container",
                    "This older container format does not use EncID. Repackage the extracted files to use password plus EncID.",
                )
            return

        if extractor.recovery_record_path:
            record_path = extractor.recovery_record_path
            self.container_path.clear()
            self.active_extractor = None
            self.active_container_path = None
            self.unlock_status.setText("Three failures reached; container moved to Chunked Files")
            self.tabs.setCurrentIndex(2)
            self._refresh_chunked_files()
            QMessageBox.warning(
                self,
                "File chunk-hidden",
                f"After three failed authentication attempts, the original container was moved to a recovery set.\nUse BoundID.json or enter the Bound ID in the restore dialog.",
            )
            self._prompt_recovery(record_path)
            return

        if extractor.last_failure in ("password", "authentication", "blank_enc_id", "blank_password"):
            attempts = extractor.failed_unlock_attempts
            if extractor.format_version == 1 and attempts >= 3:
                message = "Three password attempts failed. This legacy container was left unchanged because it lacks authenticated recovery metadata."
                self.unlock_status.setText("Legacy container unchanged; repackage it for recovery support")
            else:
                message = f"Password or EncID failed ({attempts}/3). The container is unchanged."
                self.unlock_status.setText(message)
        elif extractor.last_failure == "chunkhide_failed":
            message = "Three attempts failed, but the recovery set could not be created. The original container was left in place."
            self.unlock_status.setText("Chunkhide could not start; original container remains")
        else:
            message = "The password, hardware binding, or container data was not accepted. The container was left unchanged."
            self.unlock_status.setText("Unlock failed; container unchanged")
        QMessageBox.warning(
            self,
            "Unlock failed",
            message,
        )

    def _refresh_chunked_files(self):
        logger.info("Refreshing recovery-set list.")
        self.chunked_files_list.clear()
        try:
            recovery_root = KYSiderExtractor._recovery_root()
            recovery_sets = []
            for entry in os.scandir(recovery_root):
                if not entry.name.startswith("set-") or not entry.is_dir(follow_symlinks=False):
                    continue
                record_path = os.path.join(entry.path, "recovery.json")
                if os.path.islink(record_path) or not os.path.isfile(record_path):
                    continue
                try:
                    if os.path.getsize(record_path) > 64 * 1024:
                        continue
                    with open(record_path, "r", encoding="utf-8") as record_file:
                        manifest = json.load(record_file)
                    container_path = manifest.get("container_path") if isinstance(manifest, dict) else None
                    if not isinstance(container_path, str) or os.path.lexists(container_path):
                        continue
                    recovery_sets.append((os.path.getmtime(record_path), container_path, record_path))
                except (OSError, ValueError, json.JSONDecodeError):
                    continue

            for modified_time, container_path, record_path in sorted(recovery_sets, reverse=True):
                item = QListWidgetItem(f"{os.path.basename(container_path)}  |  {container_path}")
                item.setData(Qt.UserRole, record_path)
                item.setToolTip(f"Recovery record: {record_path}")
                self.chunked_files_list.addItem(item)

            if not recovery_sets:
                empty_item = QListWidgetItem("No chunked files found")
                empty_item.setFlags(Qt.NoItemFlags)
                self.chunked_files_list.addItem(empty_item)
            self.chunked_status.setText(f"{len(recovery_sets)} recovery set(s)")
            logger.info("Recovery-set list refreshed: %d set(s).", len(recovery_sets))
        except (OSError, ValueError) as error:
            self.chunked_status.setText(f"Could not list recovery sets: {error}")
            logger.exception("Could not refresh recovery-set list.")

    def _restore_selected_chunked_file(self, item=None):
        selected_item = item or self.chunked_files_list.currentItem()
        record_path = selected_item.data(Qt.UserRole) if selected_item else None
        if not record_path:
            logger.warning("Recovery restore requested without a selected recovery set.")
            return
        self._prompt_recovery(record_path)

    def _prompt_recovery(self, record_path):
        dialog = BoundIDDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            self.chunked_status.setText("Recovery set retained")
            logger.info("Recovery restore cancelled.")
            return

        logger.info("Recovery restore started.")
        self.chunked_status.setText("Verifying recovery set...")
        self._start_task(
            lambda: KYSiderExtractor.recover_from_record(record_path, dialog.bound_id),
            self._recovery_restored,
            self.chunked_status,
            self.chunked_progress,
        )

    def _recovery_restored(self, container_path):
        self._set_busy(False)
        self.active_extractor = None
        self.active_container_path = None
        self.container_path.setText(container_path)
        self.unlock_status.setText("Container restored and verified")
        self.chunked_status.setText("Container restored and verified")
        self.tabs.setCurrentIndex(1)
        self._refresh_chunked_files()
        QMessageBox.information(
            self,
            "Container restored",
            "The container was reassembled and its size and SHA-256 integrity were verified. Enter its password to unlock it.",
        )

    def _start_task(self, operation, on_success, status_label, progress_bar):
        self._set_busy(True, progress_bar)
        process_name = status_label.text()
        logger.info("Background process started: %s.", process_name)

        def process_succeeded(result):
            logger.info("Background process completed: %s.", process_name)
            on_success(result)

        worker = TaskWorker(operation)
        self.workers.add(worker)
        worker.succeeded.connect(process_succeeded)
        worker.failed.connect(lambda message: self._task_failed(message, status_label))
        worker.finished.connect(lambda worker=worker: self._worker_finished(worker))
        worker.start()

    def _worker_finished(self, worker):
        self.workers.discard(worker)
        worker.deleteLater()

    def _task_failed(self, message, status_label):
        self._set_busy(False)
        process_name = status_label.text()
        status_label.setText("Operation failed")
        logger.error("Background process failed (%s): %s.", process_name, message)
        QMessageBox.critical(self, "Operation failed", message)

    def _set_busy(self, busy, progress_bar=None):
        self.tabs.setEnabled(not busy)
        if busy:
            self.active_progress = progress_bar
            if progress_bar is not None:
                progress_bar.show()
        elif getattr(self, "active_progress", None) is not None:
            self.active_progress.hide()
            self.active_progress = None

    def closeEvent(self, event):
        if any(worker.isRunning() for worker in self.workers):
            QMessageBox.warning(self, "Operation in progress", "Wait for the current operation to finish.")
            event.ignore()
            return
        logger.removeHandler(self.log_handler)
        event.accept()


def main():
    application = QApplication.instance()
    if application is None:
        application = QApplication(sys.argv)
    application.setStyle("Fusion")
    application.setFont(QFont("Segoe UI", 10))
    window = KYSiderWindow()
    window.show()
    return application.exec_()


if __name__ == "__main__":
    sys.exit(main())
