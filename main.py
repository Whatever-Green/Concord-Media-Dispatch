import sys
import os
import shutil
import exifread
import hashlib
import json
import re           
import ctypes       
import subprocess   
from datetime import datetime
from pathlib import Path
from PIL import Image 

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout, 
                             QVBoxLayout, QLabel, QPushButton, QTreeView, 
                             QComboBox, QLineEdit, QFileDialog, 
                             QFrame, QMessageBox, QProgressBar, QDialog, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QDialogButtonBox,
                             QTableView, QListView, QSplitter, QStackedWidget, QSlider, QStyle, QGroupBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSortFilterProxyModel, QUrl, QSize
from PyQt6.QtGui import QFileSystemModel, QStandardItemModel, QStandardItem, QPixmap

from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtMultimediaWidgets import QVideoWidget

# --- SECURITY & UTILITY ENGINES ---
def sanitize_filename(name):
    return re.sub(r'[\\/*?:"<>|]', "", name)

def is_safe_to_wipe(source_dir):
    path = Path(source_dir).resolve()
    drive = path.anchor 
    sys_drive = Path(os.path.abspath(sys.prefix)).anchor
    if drive == sys_drive:
        return False, f"CRITICAL LOCKOUT: The source is on your System Boot Drive ({sys_drive}). Wiping is disabled."
    try:
        total_gb = shutil.disk_usage(path).total / (1024**3)
        if total_gb > 600: 
            return False, f"WARNING: The source drive is unusually large ({total_gb:.0f} GB)."
    except Exception: pass
    if os.name == 'nt': 
        if ctypes.windll.kernel32.GetDriveTypeW(drive.replace('\\', '')) != 2: 
            return False, "WARNING: Drive is not registering as Removable."
    else: 
        if not str(path).startswith('/Volumes/') and not str(path).startswith('/media/'):
            return False, "WARNING: Source is not mounted as a removable volume."
    return True, "Safe"

def get_media_date(file_path):
    path = Path(file_path)
    if path.suffix.lower() in {'.jpg', '.jpeg', '.png', '.cr2', '.arw', '.tiff'}:
        try:
            with open(file_path, 'rb') as f:
                tags = exifread.process_file(f, stop_tag="EXIF DateTimeOriginal", details=False)
                if "EXIF DateTimeOriginal" in tags:
                    date_str = str(tags["EXIF DateTimeOriginal"])
                    dt = datetime.strptime(date_str, "%Y:%m:%d %H:%M:%S")
                    return dt.strftime("%Y"), dt.strftime("%m"), dt.strftime("%d"), date_str
        except Exception: pass 
    try:
        dt = datetime.fromtimestamp(os.path.getmtime(file_path))
        return dt.strftime("%Y"), dt.strftime("%m"), dt.strftime("%d"), dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception: return "Unknown", "Unknown", "Unknown", "Unknown Time"

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception: return None

# --- BACKGROUND WORKERS ---
class ScanWorker(QThread):
    file_found = pyqtSignal(str, str, str, str)
    status_update = pyqtSignal(str)
    finished = pyqtSignal(int)
    def __init__(self, source_dir):
        super().__init__()
        self.source_dir = Path(source_dir)
    def run(self):
        # Added .mpg and .mpeg support here
        media_extensions = {'.jpg', '.jpeg', '.png', '.mp4', '.mov', '.cr2', '.arw', '.mpg', '.mpeg'}
        found_count = 0
        self.status_update.emit("Scanning directories...")
        for file_path in self.source_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in media_extensions:
                _, _, _, full_date = get_media_date(file_path)
                self.file_found.emit(file_path.name, file_path.suffix.lower(), str(file_path), full_date)
                found_count += 1
                if found_count % 10 == 0: self.status_update.emit(f"Scanning... Found {found_count} files")
        self.finished.emit(found_count)

class DispatchWorker(QThread):
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    finished = pyqtSignal(int, int, list) 
    
    def __init__(self, dispatch_plan, backup_dir=None, wipe_source=False):
        super().__init__()
        self.dispatch_plan = dispatch_plan 
        self.backup_dir = Path(backup_dir) if backup_dir else None
        self.wipe_source = wipe_source
        self.audit_log = []

    def run(self):
        success_count = 0
        total_count = len(self.dispatch_plan)
        
        for row, item in enumerate(self.dispatch_plan):
            src_file_path = item['src']
            primary_dest = item['dest']
            convert_ext = item.get('convert_ext', '') 
            
            self.status_update.emit(f"Processing: {Path(src_file_path).name}")

            conversion_failed = False
            if convert_ext:
                self.status_update.emit(f"Converting to {convert_ext.upper()}: {Path(src_file_path).name}...")
                primary_success = self._convert_media(src_file_path, primary_dest, convert_ext)
                if not primary_success: conversion_failed = True
            else:
                src_hash = calculate_sha256(src_file_path)
                if not src_hash: continue
                primary_success = self._safe_copy(src_file_path, primary_dest, src_hash)

            backup_success = True
            if self.backup_dir and not conversion_failed:
                try:
                    relative_route = Path(primary_dest).relative_to(item['base_dest'])
                    backup_dest = self.backup_dir / relative_route
                except ValueError:
                    backup_dest = self.backup_dir / Path(primary_dest).name

                if convert_ext and primary_success:
                    backup_success = self._safe_copy(primary_dest, backup_dest, calculate_sha256(primary_dest))
                else:
                    backup_success = self._safe_copy(src_file_path, backup_dest, src_hash)

            if primary_success and backup_success:
                success_count += 1
                final_hash = calculate_sha256(primary_dest)
                self.audit_log.append({"filename": Path(primary_dest).name, "status": "SUCCESS", "hash": final_hash})
                if self.wipe_source:
                    try: os.remove(src_file_path)
                    except Exception as e: print(f"Wipe failed: {e}")
            else:
                self.audit_log.append({"filename": Path(src_file_path).name, "status": "FAILED"})
                
            self.progress_update.emit(row + 1)
        self.finished.emit(success_count, total_count, self.audit_log)

    def _safe_copy(self, src, dest, src_hash):
        target_dir = Path(dest).parent
        target_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = target_dir / (Path(src).name + ".concord_tmp")
        try:
            shutil.copy2(src, tmp_path)
            os.replace(tmp_path, dest)
            if src_hash == calculate_sha256(dest): return True
            if Path(dest).exists(): os.remove(dest) 
            return False
        except Exception:
            if tmp_path.exists():
                try: os.remove(tmp_path)
                except: pass
            return False

    def _convert_media(self, src, dest, ext):
        target_dir = Path(dest).parent
        target_dir.mkdir(parents=True, exist_ok=True)
        
        if ext in {'.jpg', '.jpeg', '.png', '.webp'}:
            try:
                with Image.open(src) as img:
                    if ext in {'.jpg', '.jpeg'} and img.mode in ('RGBA', 'P'):
                        img = img.convert('RGB')
                    img.save(dest, quality=95)
                return True
            except Exception as e:
                print(f"Image Conversion Error: {e}")
                return False
                
        # Added .mpg and .mpeg support to the FFmpeg transcoder
        elif ext in {'.mp4', '.mov', '.mkv', '.mpg', '.mpeg'}:
            try:
                command = ['ffmpeg', '-y', '-i', src, '-c:v', 'libx264', '-preset', 'fast', '-crf', '22', dest]
                subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                return True
            except FileNotFoundError:
                print("FFmpeg not found! Please install FFmpeg to enable video conversion.")
                return False
            except subprocess.CalledProcessError as e:
                print(f"Video Conversion Error: {e}")
                return False
        return False


# --- DIALOGS ---
class PreviewDialog(QDialog):
    def __init__(self, dispatch_plan, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pre-Flight Review")
        self.resize(1000, 500)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<b>Review Routing & Conversion Plan.</b>"))
        self.table = QTableWidget()
        self.table.setColumnCount(4) 
        self.table.setHorizontalHeaderLabels(["Original File", "New Name", "Convert To", "Primary Destination"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setRowCount(len(dispatch_plan))
        for row, item in enumerate(dispatch_plan):
            self.table.setItem(row, 0, QTableWidgetItem(Path(item['src']).name))
            self.table.setItem(row, 1, QTableWidgetItem(Path(item['dest']).name))
            self.table.setItem(row, 2, QTableWidgetItem(item.get('convert_ext', 'None')))
            self.table.setItem(row, 3, QTableWidgetItem(str(Path(item['dest']).parent)))
        layout.addWidget(self.table)
        self.btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.btn_box.accepted.connect(self.accept)
        self.btn_box.rejected.connect(self.reject)
        layout.addWidget(self.btn_box)

class SchemaEditorDialog(QDialog):
    def __init__(self, current_schema, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Smart Schema Builder")
        self.resize(850, 600) 
        self.schema_data = current_schema 

        layout = QVBoxLayout(self)
        
        def_group = QGroupBox("1. Default Behavior (If no special rules match)")
        def_group.setToolTip("These settings apply if a file does not match any of the rules below.")
        def_layout = QHBoxLayout()
        def_layout.addWidget(QLabel("Route To:"))
        self.txt_def_route = QLineEdit(self.schema_data.get("default_route", "[YYYY]/[MM]/[DD]"))
        self.txt_def_route.setToolTip("Dynamic folder creation. Use [YYYY], [MM], [EXT], etc.")
        def_layout.addWidget(self.txt_def_route)
        def_layout.addWidget(QLabel("Rename To:"))
        self.txt_def_name = QLineEdit(self.schema_data.get("default_name", "[YYYY][MM][DD]_[CUSTOM]_[SEQ]"))
        def_group.setLayout(def_layout)
        layout.addWidget(def_group)

        list_group = QGroupBox("2. Active Smart Rules (Read from top to bottom)")
        list_layout = QVBoxLayout()
        self.rule_list = QListView()
        self.rule_model = QStandardItemModel()
        self.rule_list.setModel(self.rule_model)
        list_layout.addWidget(self.rule_list)
        btn_remove = QPushButton("- Remove Selected Rule")
        btn_remove.clicked.connect(self.remove_rule)
        list_layout.addWidget(btn_remove)
        list_group.setLayout(list_layout)
        layout.addWidget(list_group)

        build_group = QGroupBox("3. Build a New Rule")
        build_layout = QVBoxLayout()
        
        if_layout = QHBoxLayout()
        if_layout.addWidget(QLabel("<b>IF</b>"))
        self.combo_type = QComboBox()
        self.combo_type.addItems(["Extension", "Date Taken"])
        if_layout.addWidget(self.combo_type)
        
        self.combo_operator = QComboBox()
        self.combo_operator.addItems(["is exactly", "is before", "is after"])
        if_layout.addWidget(self.combo_operator)
        
        self.txt_value = QLineEdit()
        self.txt_value.setPlaceholderText("e.g. .mp4 or 2008-01-01")
        if_layout.addWidget(self.txt_value)
        build_layout.addLayout(if_layout)
        
        then_layout = QHBoxLayout()
        then_layout.addWidget(QLabel("<b>THEN</b> Route To:"))
        self.txt_rule_route = QLineEdit()
        self.txt_rule_route.setPlaceholderText("e.g. Needs_Review/")
        then_layout.addWidget(self.txt_rule_route)
        
        then_layout.addWidget(QLabel("Rename To:"))
        self.txt_rule_name = QLineEdit()
        self.txt_rule_name.setPlaceholderText("Leave blank to keep original")
        then_layout.addWidget(self.txt_rule_name)
        
        then_layout.addWidget(QLabel("Convert To:"))
        self.txt_rule_convert = QLineEdit()
        self.txt_rule_convert.setPlaceholderText("e.g. .jpg or .mp4")
        self.txt_rule_convert.setToolTip("Converts the media file. Requires FFmpeg for video. Leave blank to keep original format.")
        then_layout.addWidget(self.txt_rule_convert)

        build_layout.addLayout(then_layout)

        btn_add = QPushButton("+ Add Smart Rule")
        btn_add.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        btn_add.clicked.connect(self.add_rule)
        build_layout.addWidget(btn_add)
        build_group.setLayout(build_layout)
        layout.addWidget(build_group)

        for rule in self.schema_data.get("rules", []): self._add_rule_to_ui(rule)

        io_layout = QHBoxLayout()
        btn_import = QPushButton("Import Schema (.json)")
        btn_import.clicked.connect(self.import_schema)
        btn_export = QPushButton("Export Schema (.json)")
        btn_export.clicked.connect(self.export_schema)
        io_layout.addWidget(btn_import)
        io_layout.addWidget(btn_export)
        layout.addLayout(io_layout)

        self.btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.btn_box.accepted.connect(self.save_and_accept)
        self.btn_box.rejected.connect(self.reject)
        layout.addWidget(self.btn_box)

    def _add_rule_to_ui(self, rule_dict):
        sentence = f"IF {rule_dict['type']} {rule_dict['operator']} '{rule_dict['value']}' ➔ ROUTE: {rule_dict['route']}"
        if rule_dict.get('name'): sentence += f" | RENAME: {rule_dict['name']}"
        if rule_dict.get('convert'): sentence += f" | CONVERT TO: {rule_dict['convert']}"
        item = QStandardItem(sentence)
        item.setData(rule_dict, Qt.ItemDataRole.UserRole) 
        self.rule_model.appendRow(item)

    def add_rule(self):
        r_type = self.combo_type.currentText()
        r_op = self.combo_operator.currentText()
        r_val = self.txt_value.text().strip()
        r_route = self.txt_rule_route.text().strip()
        r_name = self.txt_rule_name.text().strip()
        r_convert = self.txt_rule_convert.text().strip().lower() 
        
        if not r_val or not r_route:
            QMessageBox.warning(self, "Missing Info", "You must provide a Value and a Route pattern.")
            return
            
        new_rule = {"type": r_type, "operator": r_op, "value": r_val, "route": r_route, "name": r_name, "convert": r_convert}
        self._add_rule_to_ui(new_rule)
        self.txt_value.clear()
        self.txt_rule_route.clear()
        self.txt_rule_name.clear()
        self.txt_rule_convert.clear()

    def remove_rule(self):
        for index in self.rule_list.selectedIndexes(): self.rule_model.removeRow(index.row())

    def save_and_accept(self):
        self.schema_data["default_route"] = self.txt_def_route.text()
        self.schema_data["default_name"] = self.txt_def_name.text()
        rules = []
        for row in range(self.rule_model.rowCount()):
            rules.append(self.rule_model.item(row).data(Qt.ItemDataRole.UserRole))
        self.schema_data["rules"] = rules
        self.accept()

    def export_schema(self):
        self.save_and_accept() 
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Schema", "", "JSON Files (*.json)")
        if file_path:
            with open(file_path, 'w') as f: json.dump(self.schema_data, f, indent=4)
            QMessageBox.information(self, "Exported", "Schema saved successfully.")

    def import_schema(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Schema", "", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'r') as f: self.schema_data = json.load(f)
                self.txt_def_route.setText(self.schema_data.get("default_route", ""))
                self.txt_def_name.setText(self.schema_data.get("default_name", ""))
                self.rule_model.clear()
                for rule in self.schema_data.get("rules", []): self._add_rule_to_ui(rule)
            except Exception as e: QMessageBox.warning(self, "Error", f"Failed to load schema: {e}")

# --- MAIN APPLICATION ---
class ConcordDispatchApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Concord Media Dispatch (Studio Edition)")
        self.resize(1350, 750) 
        self.current_source_dir = None
        
        self.advanced_schema = {
            "default_route": "[YYYY]/[MM]/[DD]",
            "default_name": "[YYYY][MM][DD]_[CUSTOM]_[SEQ]",
            "rules": [
                {"type": "Date Taken", "operator": "is before", "value": "2008-01-01", "route": "Flagged_Dates/", "name": "BAD_DATE_[SEQ]", "convert": ""},
                {"type": "Extension", "operator": "is exactly", "value": ".mov, .mpg, .mpeg", "route": "Converted_Proxies/", "name": "[CUSTOM]_PROXY_[SEQ]", "convert": ".mp4"}
            ]
        }

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # --- Pane 1 ---
        from_pane_widget = QWidget()
        from_pane = QVBoxLayout(from_pane_widget)
        from_pane.addWidget(QLabel("<b>FROM: Source Drive</b>"))
        self.btn_select_source = QPushButton("Select Source...")
        self.btn_select_source.setToolTip("Select the SD Card or external drive you want to ingest media from.")
        self.source_tree = QTreeView()
        self.file_model = QFileSystemModel()
        self.file_model.setRootPath("") 
        self.source_tree.setModel(self.file_model)
        self.source_tree.setRootIndex(self.file_model.index(""))
        from_pane.addWidget(self.btn_select_source)
        from_pane.addWidget(self.source_tree)
        splitter.addWidget(from_pane_widget)

        # --- Pane 2 ---
        garner_pane_widget = QWidget()
        garner_pane = QVBoxLayout(garner_pane_widget)
        garner_pane.addWidget(QLabel("<b>GARNER: Staging & Review</b>"))
        tools_layout = QHBoxLayout()
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search files...")
        self.btn_toggle_all = QPushButton("Select All")
        self.btn_toggle_view = QPushButton("Switch to Grid View")
        self.btn_toggle_view.setCheckable(True)
        tools_layout.addWidget(self.txt_search)
        tools_layout.addWidget(self.btn_toggle_all)
        tools_layout.addWidget(self.btn_toggle_view)
        garner_pane.addLayout(tools_layout)

        self.garner_model = QStandardItemModel(0, 4) 
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.garner_model)
        self.proxy_model.setFilterKeyColumn(-1) 
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self.view_stack = QStackedWidget()
        self.garner_table = QTableView()
        self.garner_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.garner_table.verticalHeader().setVisible(False)
        self.garner_table.setModel(self.proxy_model)
        self.garner_table.setSortingEnabled(True)
        self.view_stack.addWidget(self.garner_table)

        self.garner_grid = QListView()
        self.garner_grid.setViewMode(QListView.ViewMode.IconMode)
        self.garner_grid.setIconSize(QSize(100, 100))
        self.garner_grid.setResizeMode(QListView.ResizeMode.Adjust)
        self.garner_grid.setModel(self.proxy_model)
        self.view_stack.addWidget(self.garner_grid)

        self.preview_stack = QStackedWidget()
        self.preview_stack.setMinimumHeight(280)
        self.lbl_preview_image = QLabel("No Preview")
        self.lbl_preview_image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_stack.addWidget(self.lbl_preview_image)

        video_card = QWidget()
        video_layout = QVBoxLayout(video_card)
        video_layout.setContentsMargins(0,0,0,0)
        self.video_widget = QVideoWidget()
        self.media_player = QMediaPlayer()
        self.audio_output = QAudioOutput()
        self.media_player.setAudioOutput(self.audio_output)
        self.media_player.setVideoOutput(self.video_widget)
        
        control_layout = QHBoxLayout()
        self.btn_play = QPushButton()
        self.btn_play.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        self.btn_pause = QPushButton()
        self.btn_pause.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))
        self.slider_video = QSlider(Qt.Orientation.Horizontal)
        control_layout.addWidget(self.btn_play)
        control_layout.addWidget(self.btn_pause)
        control_layout.addWidget(self.slider_video)
        video_layout.addWidget(self.video_widget)
        video_layout.addLayout(control_layout)
        self.preview_stack.addWidget(video_card)

        self.lbl_preview_meta = QLabel("Metadata will appear here.")
        self.btn_scan_media = QPushButton("Scan Source")
        self.btn_scan_media.setToolTip("Scans the selected source drive for images and video formats.")
        self.lbl_garner_status = QLabel("0 files queued")

        garner_pane.addWidget(self.btn_scan_media)
        garner_pane.addWidget(self.view_stack) 
        garner_pane.addWidget(self.preview_stack) 
        garner_pane.addWidget(self.lbl_preview_meta)
        garner_pane.addWidget(self.lbl_garner_status)
        splitter.addWidget(garner_pane_widget)

        # --- Pane 3 ---
        dispatch_pane_widget = QWidget()
        dispatch_pane = QVBoxLayout(dispatch_pane_widget)
        dispatch_pane.addWidget(QLabel("<b>DISPATCH: Routing & Actions</b>"))
        
        dest_group = QGroupBox("Destinations")
        dest_layout = QVBoxLayout()
        self.btn_select_dest = QPushButton("Primary Destination...")
        self.txt_dest_path = QLineEdit()
        self.txt_dest_path.setReadOnly(True)
        self.btn_select_backup = QPushButton("Secondary (Backup) Dest...")
        self.txt_backup_path = QLineEdit()
        self.txt_backup_path.setReadOnly(True)
        dest_layout.addWidget(self.btn_select_dest)
        dest_layout.addWidget(self.txt_dest_path)
        dest_layout.addWidget(self.btn_select_backup)
        dest_layout.addWidget(self.txt_backup_path)
        dest_group.setLayout(dest_layout)
        dispatch_pane.addWidget(dest_group)

        schema_group = QGroupBox("Schemas")
        schema_layout = QVBoxLayout()
        self.combo_schema = QComboBox()
        self.combo_schema.addItems(["Year / Month / Day", "Year / Month", "Flat Directory", "Smart Schema Builder..."])
        self.combo_schema.setToolTip("Defines how folders are automatically created based on metadata.")
        self.btn_edit_schema = QPushButton("Configure Smart Schema...")
        self.btn_edit_schema.setVisible(False)
        self.btn_edit_schema.clicked.connect(self.open_schema_editor)

        schema_layout.addWidget(QLabel("Routing Schema:"))
        schema_layout.addWidget(self.combo_schema)
        schema_layout.addWidget(self.btn_edit_schema)
        schema_layout.addWidget(QLabel("Job Name / Custom Tag [CUSTOM]:"))
        self.txt_custom_tag = QLineEdit()
        self.txt_custom_tag.setToolTip("Text entered here will replace the [CUSTOM] tag in your Smart Schema rules.")
        schema_layout.addWidget(self.txt_custom_tag)
        schema_group.setLayout(schema_layout)
        dispatch_pane.addWidget(schema_group)

        action_group = QGroupBox("Post-Dispatch Actions")
        action_layout = QVBoxLayout()
        self.combo_post_action = QComboBox()
        self.combo_post_action.addItems(["Do Nothing (Default)", "Close Application", "⚠️ WIPE SOURCE MEDIA"])
        self.combo_post_action.setStyleSheet("QComboBox QAbstractItemView::item:selected { background-color: darkred; }")
        self.combo_post_action.setToolTip("Choose what the app does automatically after all files are verified.")
        action_layout.addWidget(self.combo_post_action)
        action_group.setLayout(action_layout)
        dispatch_pane.addWidget(action_group)

        dispatch_pane.addStretch() 
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.btn_dispatch = QPushButton("DISPATCH SELECTED")
        self.btn_dispatch.setToolTip("Executes your rules, conversions, copies, and verification.")
        self.btn_dispatch.setMinimumHeight(50)
        self.btn_dispatch.setStyleSheet("background-color: #2E8B57; color: white; font-weight: bold;")
        
        dispatch_pane.addWidget(self.progress_bar)
        dispatch_pane.addWidget(self.btn_dispatch)
        splitter.addWidget(dispatch_pane_widget)
        splitter.setSizes([250, 600, 350])

        # Events
        self.btn_select_source.clicked.connect(self.select_source)
        self.source_tree.clicked.connect(self.on_tree_clicked)
        self.btn_scan_media.clicked.connect(self.start_scan_thread)
        self.btn_select_dest.clicked.connect(lambda: self.select_folder(self.txt_dest_path))
        self.btn_select_backup.clicked.connect(lambda: self.select_folder(self.txt_backup_path))
        self.btn_dispatch.clicked.connect(self.prepare_dispatch)
        self.txt_search.textChanged.connect(self.proxy_model.setFilterFixedString)
        self.garner_table.clicked.connect(self.on_table_clicked)
        self.garner_grid.clicked.connect(self.on_table_clicked)
        self.btn_toggle_all.clicked.connect(self.toggle_all_checkmarks)
        self.btn_toggle_view.toggled.connect(self.switch_view)
        self.combo_schema.currentIndexChanged.connect(self.on_schema_changed)
        self.btn_play.clicked.connect(self.media_player.play)
        self.btn_pause.clicked.connect(self.media_player.pause)
        self.media_player.positionChanged.connect(self.slider_video.setValue)
        self.media_player.durationChanged.connect(self.slider_video.setMaximum)
        self.slider_video.sliderMoved.connect(self.media_player.setPosition)

    def select_source(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Source")
        if folder:
            self.current_source_dir = folder
            self.source_tree.setRootIndex(self.file_model.index(folder))

    def on_tree_clicked(self, index):
        path = self.file_model.filePath(index)
        if os.path.isfile(path): path = os.path.dirname(path)
        self.current_source_dir = path

    def select_folder(self, line_edit):
        folder = QFileDialog.getExistingDirectory(self, "Select Directory")
        if folder: line_edit.setText(folder)

    def switch_view(self, checked):
        if checked:
            self.view_stack.setCurrentIndex(1)
            self.btn_toggle_view.setText("Switch to List View")
        else:
            self.view_stack.setCurrentIndex(0)
            self.btn_toggle_view.setText("Switch to Grid View")

    def start_scan_thread(self):
        if not self.current_source_dir: return
        self.media_player.stop()
        self.garner_model.removeRows(0, self.garner_model.rowCount())
        self.btn_scan_media.setEnabled(False)
        self.scan_worker = ScanWorker(self.current_source_dir)
        self.scan_worker.file_found.connect(self.on_file_found)
        self.scan_worker.status_update.connect(self.lbl_garner_status.setText)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def on_file_found(self, name, ext, full_path, full_date):
        item_name = QStandardItem(name)
        item_name.setData(full_path, Qt.ItemDataRole.UserRole)
        item_name.setCheckable(True)
        item_name.setCheckState(Qt.CheckState.Checked) 
        if ext in {'.jpg', '.jpeg', '.png'}:
            item_name.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
        # Added .mpg and .mpeg to UI video icons
        elif ext in {'.mp4', '.mov', '.mpg', '.mpeg'}:
            item_name.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolume))
        item_ext = QStandardItem(ext)
        item_date = QStandardItem(full_date)
        item_path = QStandardItem(full_path)
        self.garner_model.appendRow([item_name, item_ext, item_date, item_path])

    def on_scan_finished(self, count):
        self.btn_scan_media.setEnabled(True)
        self.garner_table.resizeColumnsToContents()
        self.lbl_garner_status.setText(f"✅ {count} media files queued.")

    def toggle_all_checkmarks(self):
        if self.garner_model.rowCount() == 0: return
        first_item = self.garner_model.item(0, 0)
        new_state = Qt.CheckState.Unchecked if first_item.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked
        for row in range(self.garner_model.rowCount()):
            self.garner_model.item(row, 0).setCheckState(new_state)

    def on_schema_changed(self, index):
        self.btn_edit_schema.setVisible(index == 3)
        if index == 3: self.open_schema_editor() 

    def open_schema_editor(self):
        dialog = SchemaEditorDialog(self.advanced_schema, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.advanced_schema = dialog.schema_data

    def on_table_clicked(self, index):
        source_index = self.proxy_model.mapToSource(index)
        row = source_index.row()
        item = self.garner_model.item(row, 0)
        file_path = item.data(Qt.ItemDataRole.UserRole)
        full_date = self.garner_model.item(row, 2).text()
        path_obj = Path(file_path)

        self.media_player.stop()

        if path_obj.suffix.lower() in {'.jpg', '.jpeg', '.png'}:
            self.preview_stack.setCurrentIndex(0)
            pixmap = QPixmap(file_path)
            pixmap = pixmap.scaled(self.lbl_preview_image.size(), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.lbl_preview_image.setPixmap(pixmap)
        # Added .mpg and .mpeg to the media player routing
        elif path_obj.suffix.lower() in {'.mp4', '.mov', '.mpg', '.mpeg'}:
            self.preview_stack.setCurrentIndex(1)
            self.media_player.setSource(QUrl.fromLocalFile(file_path))
            self.media_player.play()

        size_mb = path_obj.stat().st_size / (1024 * 1024)
        self.lbl_preview_meta.setText(f"<b>File:</b> {path_obj.name}<br><b>Date:</b> {full_date}<br><b>Size:</b> {size_mb:.2f} MB")

    def prepare_dispatch(self):
        dest_dir = self.txt_dest_path.text()
        if not dest_dir or self.garner_model.rowCount() == 0: return
        
        self.media_player.stop()

        schema_index = self.combo_schema.currentIndex()
        base_dest_path = Path(dest_dir)
        
        raw_custom = self.txt_custom_tag.text().strip()
        custom_text = sanitize_filename(raw_custom)
        if raw_custom != custom_text:
            self.txt_custom_tag.setText(custom_text)

        post_action = self.combo_post_action.currentIndex()
        if post_action == 2:
            is_safe, warning_msg = is_safe_to_wipe(self.current_source_dir)
            if not is_safe:
                if "CRITICAL LOCKOUT" in warning_msg:
                    QMessageBox.critical(self, "Wipe Disabled", warning_msg)
                    self.combo_post_action.setCurrentIndex(0)
                    return
                reply = QMessageBox.warning(self, "SECURITY WARNING", 
                                            f"{warning_msg}\n\nAre you absolutely sure you want to proceed with Wiping?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Abort, QMessageBox.StandardButton.Abort)
                if reply != QMessageBox.StandardButton.Yes:
                    self.combo_post_action.setCurrentIndex(0)
                    return
            else:
                reply = QMessageBox.critical(self, "WARNING: DATA DELETION", 
                                            "You have selected to WIPE the source media.\nThe application will ONLY delete verified files.\n\nProceed?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Abort, QMessageBox.StandardButton.Abort)
                if reply != QMessageBox.StandardButton.Yes:
                    self.combo_post_action.setCurrentIndex(0)
                    return

        dispatch_plan = []
        seq_counter = 1
        
        for row in range(self.garner_model.rowCount()):
            item = self.garner_model.item(row, 0)
            if item.checkState() != Qt.CheckState.Checked: continue
                
            src_file_path = item.data(Qt.ItemDataRole.UserRole)
            file_obj = Path(src_file_path)
            ext_clean = file_obj.suffix.lower().replace('.', '')
            
            year, month, day, full_date = get_media_date(src_file_path)

            chosen_route = "[YYYY]/[MM]/[DD]"
            chosen_name = "" 
            convert_ext = ""

            if schema_index == 0: chosen_route = "[YYYY]/[MM]/[DD]"
            elif schema_index == 1: chosen_route = "[YYYY]/[MM]"
            elif schema_index == 2: chosen_route = ""
            elif schema_index == 3: 
                chosen_route = self.advanced_schema.get("default_route", "[YYYY]/[MM]/[DD]")
                chosen_name = self.advanced_schema.get("default_name", "")
                
                try: file_dt = datetime.strptime(full_date, "%Y-%m-%d %H:%M:%S")
                except ValueError: file_dt = datetime.now() 
                
                for rule in self.advanced_schema.get("rules", []):
                    rule_matched = False
                    r_val = rule.get("value", "")
                    r_op = rule.get("operator", "")
                    
                    if rule.get("type") == "Extension":
                        rule_exts = [e.strip().lower() for e in r_val.split(",")]
                        if file_obj.suffix.lower() in rule_exts or ext_clean in rule_exts:
                            rule_matched = True
                            
                    elif rule.get("type") == "Date Taken":
                        try:
                            target_dt = datetime.strptime(r_val, "%Y-%m-%d")
                            if r_op == "is before" and file_dt < target_dt: rule_matched = True
                            elif r_op == "is after" and file_dt > target_dt: rule_matched = True
                            elif r_op == "is exactly" and file_dt.date() == target_dt.date(): rule_matched = True
                        except ValueError: pass
                    
                    if rule_matched:
                        chosen_route = rule.get("route", chosen_route)
                        chosen_name = rule.get("name", chosen_name)
                        convert_ext = rule.get("convert", "")
                        break 
                
            chosen_route = chosen_route.lstrip("\\/")
            chosen_route = chosen_route.replace("[YYYY]", year).replace("[MM]", month).replace("[DD]", day).replace("[EXT]", ext_clean)
            target_dir = base_dest_path / chosen_route

            final_ext = convert_ext.replace('.', '') if convert_ext else ext_clean

            final_name = file_obj.name
            if chosen_name:
                new_name = chosen_name.replace("[YYYY]", year).replace("[MM]", month).replace("[DD]", day).replace("[CUSTOM]", custom_text).replace("[SEQ]", str(seq_counter).zfill(4))
                final_name = f"{new_name}.{final_ext}"
                seq_counter += 1
            elif convert_ext:
                final_name = f"{file_obj.stem}.{final_ext}"

            dispatch_plan.append({
                'src': src_file_path, 
                'dest': target_dir / final_name,
                'base_dest': base_dest_path, 
                'date_full': full_date,
                'convert_ext': convert_ext 
            })

        if not dispatch_plan: return

        dialog = PreviewDialog(dispatch_plan, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.start_dispatch_thread(dispatch_plan, post_action)
        else:
            self.lbl_garner_status.setText("Dispatch cancelled.")

    def start_dispatch_thread(self, dispatch_plan, post_action):
        self.btn_dispatch.setEnabled(False)
        self.progress_bar.setMaximum(len(dispatch_plan))
        backup_path = self.txt_backup_path.text() if self.txt_backup_path.text() else None
        wipe_source = (post_action == 2)
        self.post_dispatch_action = post_action 
        
        self.worker = DispatchWorker(dispatch_plan, backup_path, wipe_source)
        self.worker.progress_update.connect(self.progress_bar.setValue)
        self.worker.status_update.connect(self.lbl_garner_status.setText) 
        self.worker.finished.connect(self.on_dispatch_finished)
        self.worker.start()

    def on_dispatch_finished(self, success_count, total_count, audit_log):
        self.btn_dispatch.setEnabled(True)
        dest_dir = Path(self.txt_dest_path.text())
        log_filename = f"Concord_Dispatch_Log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(dest_dir / log_filename, 'w') as f: json.dump(audit_log, f, indent=4)
        except Exception: pass

        QMessageBox.information(self, "Success", f"Dispatched {success_count} files securely.")
        
        if self.post_dispatch_action == 1: 
            QApplication.quit()
        elif self.post_dispatch_action == 2: 
            self.lbl_garner_status.setText("Dispatch and Wiping complete.")
            self.start_scan_thread()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion") 
    window = ConcordDispatchApp()
    window.show()
    sys.exit(app.exec())