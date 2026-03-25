#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/gui/modern_gui.py

Modern GUI front-end providing:
- AI-assisted analysis
- Graph visualisation
- 3D visualisation
- Threat intelligence queries
- MITRE ATT&CK mapping
- Network analysis
- Forensics tooling
- Dark theme styling
"""

import sys
import os
import json
import logging
import ipaddress
import re
import queue
import time
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

import numpy as np

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QTextEdit, QLineEdit, QFileDialog,
    QProgressBar, QGroupBox, QGridLayout, QComboBox, QCheckBox,
    QDoubleSpinBox, QSpinBox, QTableWidget, QTableWidgetItem, QSplitter, QListWidget, QMessageBox,
    QScrollArea, QFrame, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPainter, QPixmap, QImage

# Write a brief import trace to a log file to help diagnose startup issues.
try:
    with open("gui_startup.log", "a", encoding="utf-8") as _lf:
        _lf.write("[modern_gui] module import started\n")
except Exception:
    pass

# Matplotlib bridge (lazy initialisation). Backend is controlled via THREATINQ_MPL_MODE=qt|agg.
# Default to Agg because some Windows/PyQt5/matplotlib combinations hard-crash
# with an access violation while importing backend_qt5agg during startup.
MATPLOTLIB_AVAILABLE: bool = False
MatplotlibCanvas = None  # type: ignore[assignment]
plt = None  # type: ignore[assignment]
_mpl_mode: Optional[str] = None


def ensure_mpl_ready() -> None:
    """Initialise matplotlib backend lazily to avoid import-time crashes.

    This respects THREATINQ_MPL_MODE. Agg is the default safe mode.
    If the Qt backend import raises a normal Python exception, fall back to Agg.
    """
    global MATPLOTLIB_AVAILABLE, MatplotlibCanvas, plt, _mpl_mode

    if MATPLOTLIB_AVAILABLE and MatplotlibCanvas is not None:
        return

    _mpl_mode = os.environ.get("THREATINQ_MPL_MODE", "agg").strip().lower()
    if _mpl_mode not in {"qt", "agg"}:
        _mpl_mode = "agg"

    log = logging.getLogger("modern_gui")

    if _mpl_mode == "qt":
        try:
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas  # type: ignore
            from matplotlib.figure import Figure  # type: ignore
            import matplotlib.pyplot as _plt  # type: ignore
        except Exception:
            log.exception("Matplotlib Qt backend failed; falling back to Agg.")
            _mpl_mode = "agg"
        else:
            MATPLOTLIB_AVAILABLE = True

            class _QtMatplotlibCanvas(FigureCanvas):  # type: ignore[misc]
                """Qt-native FigureCanvas wrapper."""

                def __init__(self, *, width: float = 12.0, height: float = 8.0, dpi: int = 100) -> None:
                    fig = Figure(figsize=(width, height), dpi=dpi)
                    super().__init__(fig)
                    self.figure = fig

            MatplotlibCanvas = _QtMatplotlibCanvas  # type: ignore[assignment]
            plt = _plt  # type: ignore[assignment]
            return

    # Agg path
    try:
        import matplotlib

        matplotlib.use("Agg", force=True)
        from matplotlib.figure import Figure  # type: ignore
        from matplotlib.backends.backend_agg import FigureCanvasAgg  # type: ignore
        import matplotlib.pyplot as _plt  # type: ignore
    except Exception:
        log.exception("Matplotlib (Agg backend) initialisation failed; charts will be disabled.")
        MATPLOTLIB_AVAILABLE = False
        MatplotlibCanvas = None  # type: ignore[assignment]
        plt = None  # type: ignore[assignment]
    else:
        MATPLOTLIB_AVAILABLE = True

        class _AggMatplotlibCanvas(QWidget):
            """Agg-backed canvas rendered into a pixmap."""

            def __init__(self, *, width: float = 12.0, height: float = 8.0, dpi: int = 100) -> None:
                super().__init__()
                self.figure = Figure(figsize=(width, height), dpi=dpi)
                self._canvas = FigureCanvasAgg(self.figure)
                self._pixmap = QPixmap()
                self._last_buffer: Optional[bytes] = None
                self.setMinimumSize(int(width * dpi * 0.6), int(height * dpi * 0.6))

            def draw(self) -> None:  # type: ignore[override]
                self._canvas.draw()
                buffer, (width, height) = self._canvas.print_to_buffer()
                self._last_buffer = bytes(buffer)
                image = QImage(
                    self._last_buffer,
                    width,
                    height,
                    QImage.Format_RGBA8888,
                )
                if image.isNull():
                    return
                self._pixmap = QPixmap.fromImage(image.rgbSwapped())
                self.update()

            def sizeHint(self):  # type: ignore[override]
                return self._pixmap.size() if not self._pixmap.isNull() else super().sizeHint()

            def paintEvent(self, event):  # type: ignore[override]
                if self._pixmap.isNull():
                    return
                painter = QPainter(self)
                target = self.rect()
                scaled = self._pixmap.scaled(
                    target.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
                )
                x = target.x() + (target.width() - scaled.width()) // 2
                y = target.y() + (target.height() - scaled.height()) // 2
                painter.drawPixmap(x, y, scaled)
                painter.end()

        MatplotlibCanvas = _AggMatplotlibCanvas  # type: ignore[assignment]
        plt = _plt  # type: ignore[assignment]

# Do not warn at import time; warn after ensure_mpl_ready() if still unavailable.

# Ensure ThreatInquisitor modules are importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger("modern_gui")

PRODUCT_NAME = "Pied Piper"
PRODUCT_SUBTITLE = (
    "Интегрированная система многоуровневого анализа вредоносных объектов "
    "с AI-ассистированной классификацией и автоматизацией threat intelligence"
)

from analyzer.clustering import MalwareClustering
from core.config import config_manager

PYQTGRAPH_AVAILABLE = False
pg = None
gl = None


def ensure_pyqtgraph_ready() -> bool:
    """Lazily import pyqtgraph only if explicitly enabled via env.

    Returns True if pyqtgraph is available and imported, False otherwise.
    """
    global PYQTGRAPH_AVAILABLE, pg, gl
    if PYQTGRAPH_AVAILABLE and pg is not None and gl is not None:
        return True

    flag = os.environ.get("THREATINQ_USE_PYQTGRAPH", "").strip().lower() in {"1", "true", "yes", "on"}
    if not flag:
        return False
    try:
        import pyqtgraph as _pg  # type: ignore
        import pyqtgraph.opengl as _gl  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        logging.getLogger("modern_gui").exception("pyqtgraph import failed: %s", exc)
        PYQTGRAPH_AVAILABLE = False
        pg = None
        gl = None
        return False
    else:
        PYQTGRAPH_AVAILABLE = True
        pg = _pg
        gl = _gl
        return True

USE_PYQTGRAPH = (
    os.environ.get("THREATINQ_USE_PYQTGRAPH", "").strip().lower() in {"1", "true", "yes", "on"}
)

try:
    from services.file_monitor import FileMonitorService

    FILE_MONITOR_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    FileMonitorService = None  # type: ignore
    FILE_MONITOR_AVAILABLE = False


def get_threat_intel():
    """Return a ThreatIntelligence instance, raising a readable error on failure."""
    try:
        from core.threat_intel import ThreatIntelligence
    except ImportError as exc:  # pragma: no cover - optional dependency
        logger.error("Failed to import ThreatIntelligence: %s", exc)
        raise RuntimeError("Threat intelligence module is not available.") from exc
    return ThreatIntelligence()


# ==============================================================================
# DARK THEME
# ==============================================================================

DARK_STYLE = """
QMainWindow {
    background-color: #1E1E1E;
    color: #E0E0E0;
}

QWidget {
    background-color: #1E1E1E;
    color: #E0E0E0;
    font-family: 'Segoe UI', Arial;
    font-size: 10pt;
}

QTabWidget::pane {
    border: 1px solid #3C3C3C;
    background-color: #252525;
}

QTabBar::tab {
    background-color: #2D2D2D;
    color: #E0E0E0;
    padding: 10px 20px;
    margin: 2px;
    border: 1px solid #3C3C3C;
}

QTabBar::tab:selected {
    background-color: #0D7377;
    color: white;
    font-weight: bold;
}

QTabBar::tab:hover {
    background-color: #14FFEC;
    color: #1E1E1E;
}

QPushButton {
    background-color: #0D7377;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #14FFEC;
    color: #1E1E1E;
}

QPushButton:pressed {
    background-color: #0A5F63;
}

QPushButton:disabled {
    background-color: #3C3C3C;
    color: #666666;
}

QLineEdit, QTextEdit, QComboBox {
    background-color: #2D2D2D;
    color: #E0E0E0;
    border: 1px solid #3C3C3C;
    padding: 8px;
    border-radius: 3px;
}

QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #14FFEC;
}

QGroupBox {
    border: 2px solid #0D7377;
    border-radius: 5px;
    margin-top: 10px;
    font-weight: bold;
    padding-top: 10px;
}

QGroupBox::title {
    color: #14FFEC;
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}

QTableWidget {
    background-color: #2D2D2D;
    alternate-background-color: #252525;
    gridline-color: #3C3C3C;
    border: 1px solid #3C3C3C;
}

QTableWidget::item {
    padding: 5px;
}

QTableWidget::item:selected {
    background-color: #0D7377;
    color: white;
}

QHeaderView::section {
    background-color: #323232;
    color: #14FFEC;
    padding: 8px;
    border: 1px solid #3C3C3C;
    font-weight: bold;
}

QProgressBar {
    border: 1px solid #3C3C3C;
    border-radius: 5px;
    text-align: center;
    background-color: #2D2D2D;
}

QProgressBar::chunk {
    background-color: #0D7377;
    border-radius: 3px;
}

QListWidget {
    background-color: #2D2D2D;
    border: 1px solid #3C3C3C;
}

QListWidget::item:selected {
    background-color: #0D7377;
    color: white;
}

QScrollBar:vertical {
    background: #2D2D2D;
    width: 12px;
}

QScrollBar::handle:vertical {
    background: #0D7377;
    border-radius: 6px;
}

QScrollBar::handle:vertical:hover {
    background: #14FFEC;
}

QLabel {
    color: #E0E0E0;
}

QCheckBox {
    color: #E0E0E0;
}

QCheckBox::indicator:checked {
    background-color: #0D7377;
    border: 1px solid #14FFEC;
}
"""


# ==============================================================================
# WORKER THREADS
# ==============================================================================

class AnalysisWorker(QThread):
    """Worker thread executing file analysis jobs."""
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            from analyzer.heuristic_analysis import HeuristicAnalyzer
            from services.analysis_pipeline import run_canonical_pipeline

            def _progress(value: int, _stage: str) -> None:
                self.progress.emit(value)

            result = run_canonical_pipeline(
                self.file_path,
                run_dynamic=True,
                timeout=30,
                progress_callback=_progress,
            )
            try:
                heur_analyzer = HeuristicAnalyzer(self.file_path)
                result["heuristic"] = heur_analyzer.analyze()
            except Exception as heur_err:  # pragma: no cover - defensive
                logger.warning(f"Heuristic analysis failed: {heur_err}")
            self.progress.emit(100)
            self.finished.emit(result)

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            self.error.emit(str(e))


class ThreatIntelWorker(QThread):
    """Worker thread performing threat-intelligence lookups."""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, query: str, query_type: str):
        super().__init__()
        self.query = query
        self.query_type = query_type

    def run(self):
        try:
            ti = get_threat_intel()

            if self.query_type == "ip":
                result = ti.check_ip(self.query)
            elif self.query_type == "url":
                result = ti.check_url(self.query)
            elif self.query_type == "domain":
                normalized = self.query
                if not normalized.startswith(("http://", "https://")):
                    normalized = f"https://{normalized}"
                result = ti.check_url(normalized)
                result["queried_domain"] = self.query
            elif self.query_type == "hash":
                result = ti.check_hash(self.query)
            else:
                result = {"error": "Unknown query type"}

            if isinstance(result, dict):
                result.setdefault("_query_type", self.query_type)
                result.setdefault("_query_value", self.query)

            self.finished.emit(result)

        except Exception as e:
            self.error.emit(str(e))


# ==============================================================================
# MAIN GUI
# ==============================================================================

class ModernThreatInquisitorGUI(QMainWindow):
    """Modern ThreatInquisitor graphical interface."""

    def __init__(self):
        super().__init__()
        self.current_file = None
        self.analysis_results = {}
        self._auto_ai_after_analysis = False
        self.clustering_dataset: list = []
        self.family_dataset: list = []
        self.clustering_results: Dict[str, Any] = {}
        self.clustering_clusterer: Optional[MalwareClustering] = None
        self.family_profiles: Dict[str, Any] = {}
        self.family_clusterer: Optional[MalwareClustering] = None
        self.selected_cluster_label: Optional[int] = None
        self.threat_worker: Optional[ThreatIntelWorker] = None
        self._ti_context: Optional[Dict[str, Any]] = None
        self.graph_canvas = None
        self.canvas_3d = None
        self.gl_view = None
        self._gl_items: List[Any] = []
        self.monitor_service: Optional[FileMonitorService] = None
        self.monitor_event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.monitor_timer = QTimer(self)
        self.monitor_timer.setInterval(1000)
        self.monitor_timer.timeout.connect(self._poll_monitor_events)
        self.monitor_events: List[Dict[str, Any]] = []
        self.monitor_status_label: Optional[QLabel] = None
        self.monitor_stats_label: Optional[QLabel] = None
        self.monitor_include_input: Optional[QLineEdit] = None
        self.monitor_exclude_input: Optional[QLineEdit] = None
        self.monitor_paths_list: Optional[QListWidget] = None
        self.table_monitor_events: Optional[QTableWidget] = None
        self.monitor_start_button: Optional[QPushButton] = None
        self.monitor_stop_button: Optional[QPushButton] = None
        self.monitor_baseline_checkbox: Optional[QCheckBox] = None
        self.monitor_baseline_count: int = 0
        self.lbl_ai_provider_status: Optional[QLabel] = None
        self.text_d3fend_summary: Optional[QTextEdit] = None
        self.text_fusion_summary: Optional[QTextEdit] = None
        self.text_retrohunt_summary: Optional[QTextEdit] = None
        self.text_subsystem_status: Optional[QTextEdit] = None
        self.btn_run_retrohunt: Optional[QPushButton] = None
        self.init_ui()

    def init_ui(self):
        """Initialise the user interface."""
        self.setWindowTitle(f"{PRODUCT_NAME} - Система анализа вредоносных объектов")
        self.setGeometry(100, 100, 1600, 900)

        # Apply dark theme
        self.setStyleSheet(DARK_STYLE)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Header
        self.create_header(main_layout)

        # Create analysis tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.create_overview_tab()
        self.create_static_analysis_tab()
        self.create_dynamic_analysis_tab()
        self.create_ai_analysis_tab()
        self.create_graph_visualization_tab()
        self.create_3d_visualization_tab()
        self.create_threat_intel_tab()
        self.create_mitre_attack_tab()
        self.create_network_analysis_tab()
        self.create_monitoring_tab()
        self.create_clustering_tab()
        self.create_forensics_tab()
        self.create_fusion_retro_tab()
        self.create_reports_tab()

        # Status bar
        self.statusBar().showMessage("Готово")
        self.statusBar().setStyleSheet("background-color: #252525; color: #14FFEC;")

    def create_header(self, layout):
        """Create header panel with primary controls."""
        header = QFrame()
        header.setFrameShape(QFrame.StyledPanel)
        header.setStyleSheet("background-color: #252525; border-radius: 5px;")
        header_layout = QHBoxLayout(header)

        title_block = QVBoxLayout()
        title_block.setSpacing(2)

        title = QLabel(PRODUCT_NAME)
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setStyleSheet("color: #14FFEC;")
        title_block.addWidget(title)

        subtitle = QLabel(PRODUCT_SUBTITLE)
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9EE7E3; font-size: 11px;")
        title_block.addWidget(subtitle)

        header_layout.addLayout(title_block, stretch=1)

        header_layout.addStretch()

        self.input_file = QLineEdit()
        self.input_file.setPlaceholderText("Выберите файл для анализа...")
        self.input_file.setReadOnly(True)
        self.input_file.setMinimumWidth(320)
        header_layout.addWidget(self.input_file)

        self.btn_select_file = QPushButton("Выбрать файл")
        self.btn_select_file.clicked.connect(self.select_file)
        header_layout.addWidget(self.btn_select_file)

        self.btn_quick_scan = QPushButton("Быстрый анализ")
        self.btn_quick_scan.clicked.connect(self.quick_analysis)
        self.btn_quick_scan.setEnabled(False)
        header_layout.addWidget(self.btn_quick_scan)

        self.btn_full_scan = QPushButton("Полный анализ")
        self.btn_full_scan.clicked.connect(self.full_analysis)
        self.btn_full_scan.setEnabled(False)
        header_layout.addWidget(self.btn_full_scan)

        self.btn_save_report = QPushButton("Сохранить отчёт")
        self.btn_save_report.clicked.connect(self.save_report)
        self.btn_save_report.setEnabled(False)
        header_layout.addWidget(self.btn_save_report)

        layout.addWidget(header)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)

    def _set_analysis_busy(self, busy: bool, message: Optional[str] = None):
        """Toggle primary controls while background analysis is running."""
        self.progress_bar.setVisible(busy)
        if busy:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
        self.btn_select_file.setEnabled(not busy)
        has_file = bool(self.current_file)
        self.btn_quick_scan.setEnabled(not busy and has_file)
        self.btn_full_scan.setEnabled(not busy and has_file)
        if message:
            self.statusBar().showMessage(message)
        elif not busy:
            self.statusBar().showMessage("Готово")

    # ==============================================================================
    # TAB 1: Overview
    # ==============================================================================

    def create_overview_tab(self):
        """Overview tab setup."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        file_group = QGroupBox("Сведения о файле")
        file_layout = QGridLayout()

        file_layout.addWidget(QLabel("Путь:"), 0, 0)
        self.lbl_file_path = QLabel("Не выбран")
        self.lbl_file_path.setWordWrap(True)
        file_layout.addWidget(self.lbl_file_path, 0, 1)

        file_layout.addWidget(QLabel("Размер файла:"), 1, 0)
        self.lbl_file_size = QLabel("-")
        file_layout.addWidget(self.lbl_file_size, 1, 1)

        file_layout.addWidget(QLabel("MD5:"), 2, 0)
        self.lbl_file_md5 = QLabel("-")
        file_layout.addWidget(self.lbl_file_md5, 2, 1)

        file_layout.addWidget(QLabel("SHA256:"), 3, 0)
        self.lbl_file_sha256 = QLabel("-")
        file_layout.addWidget(self.lbl_file_sha256, 3, 1)

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        results_group = QGroupBox("Краткая сводка")
        results_layout = QVBoxLayout()

        self.lbl_threat_level = QLabel("Оценка угрозы: -")
        self.lbl_threat_level.setFont(QFont("Segoe UI", 14, QFont.Bold))
        results_layout.addWidget(self.lbl_threat_level)

        self.lbl_malware_type = QLabel("Тип: -")
        results_layout.addWidget(self.lbl_malware_type)

        self.lbl_ai_verdict = QLabel("Вердикт AI: -")
        results_layout.addWidget(self.lbl_ai_verdict)

        self.lbl_ml_probability = QLabel("ML-вероятность: -")
        results_layout.addWidget(self.lbl_ml_probability)

        self.lbl_ml_status = QLabel("Статус ML: -")
        self.lbl_ml_status.setWordWrap(True)
        results_layout.addWidget(self.lbl_ml_status)

        self.lbl_behavioral_quadrant = QLabel("Поведенческий квадрант: -")
        self.lbl_behavioral_quadrant.setWordWrap(True)
        results_layout.addWidget(self.lbl_behavioral_quadrant)

        self.lbl_cluster_match = QLabel("Соответствие кластеру: -")
        self.lbl_cluster_match.setWordWrap(True)
        results_layout.addWidget(self.lbl_cluster_match)

        self.lbl_family_match = QLabel("Соответствие семейству: -")
        self.lbl_family_match.setWordWrap(True)
        results_layout.addWidget(self.lbl_family_match)

        self.lbl_sandbox_evasion = QLabel("Обход песочницы: -")
        self.lbl_sandbox_evasion.setWordWrap(True)
        results_layout.addWidget(self.lbl_sandbox_evasion)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        summary_group = QGroupBox("Сводка анализа")
        summary_layout = QVBoxLayout()

        self.txt_summary = QTextEdit()
        self.txt_summary.setReadOnly(True)
        self.txt_summary.setPlaceholderText("Здесь появятся результаты анализа...")
        summary_layout.addWidget(self.txt_summary)

        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)

        layout.addStretch()
        self.tabs.addTab(tab, "Обзор")

    # ==============================================================================
    # TAB 2: Static Analysis
    # ==============================================================================

    def create_static_analysis_tab(self):
        """Static analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        controls = QHBoxLayout()
        btn_run_static = QPushButton("Запустить статический анализ")
        btn_run_static.clicked.connect(self.run_static_analysis)
        controls.addWidget(btn_run_static)
        controls.addStretch()
        layout.addLayout(controls)

        self.txt_static_results = QTextEdit()
        self.txt_static_results.setReadOnly(True)
        self.txt_static_results.setPlaceholderText("Результаты статического анализа...")
        layout.addWidget(self.txt_static_results)

        heur_group = QGroupBox("Эвристический анализ")
        heur_layout = QVBoxLayout()

        self.lbl_entropy = QLabel("Энтропия: -")
        heur_layout.addWidget(self.lbl_entropy)

        self.lbl_packer = QLabel("Упаковщик: -")
        heur_layout.addWidget(self.lbl_packer)

        self.lbl_heur_score = QLabel("Оценка риска: -")
        heur_layout.addWidget(self.lbl_heur_score)

        heur_group.setLayout(heur_layout)
        layout.addWidget(heur_group)

        self.tabs.addTab(tab, "Статический анализ")

    # ==============================================================================
    # TAB 3: Dynamic Analysis
    # ==============================================================================

    def create_dynamic_analysis_tab(self):
        """Dynamic analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        controls = QHBoxLayout()
        btn_run_dynamic = QPushButton("Запустить динамический анализ")
        btn_run_dynamic.clicked.connect(self.run_dynamic_analysis)
        controls.addWidget(btn_run_dynamic)

        self.spin_timeout = QComboBox()
        self.spin_timeout.addItems(["15 s", "30 s", "60 s", "120 s"])
        self.spin_timeout.setCurrentIndex(1)
        controls.addWidget(QLabel("Тайм-аут:"))
        controls.addWidget(self.spin_timeout)
        controls.addStretch()
        layout.addLayout(controls)

        dynamic_tabs = QTabWidget()

        api_widget = QWidget()
        api_layout = QVBoxLayout(api_widget)
        self.table_api_calls = QTableWidget()
        self.table_api_calls.setColumnCount(4)
        self.table_api_calls.setHorizontalHeaderLabels(["Время", "API", "PID", "Аргументы"])
        api_layout.addWidget(self.table_api_calls)
        dynamic_tabs.addTab(api_widget, "Вызовы API")

        net_widget = QWidget()
        net_layout = QVBoxLayout(net_widget)
        self.table_network = QTableWidget()
        self.table_network.setColumnCount(5)
        self.table_network.setHorizontalHeaderLabels(["Время", "Удалённый узел", "Порт", "Протокол", "Статус"])
        net_layout.addWidget(self.table_network)
        dynamic_tabs.addTab(net_widget, "Сеть")

        files_widget = QWidget()
        files_layout = QVBoxLayout(files_widget)
        self.table_files = QTableWidget()
        self.table_files.setColumnCount(3)
        self.table_files.setHorizontalHeaderLabels(["Время", "Операция", "Путь"])
        files_layout.addWidget(self.table_files)
        dynamic_tabs.addTab(files_widget, "Операции с файлами")

        reg_widget = QWidget()
        reg_layout = QVBoxLayout(reg_widget)
        self.table_registry = QTableWidget()
        self.table_registry.setColumnCount(3)
        self.table_registry.setHorizontalHeaderLabels(["Время", "Операция", "Ключ"])
        reg_layout.addWidget(self.table_registry)
        dynamic_tabs.addTab(reg_widget, "Реестр")

        layout.addWidget(dynamic_tabs)
        self.tabs.addTab(tab, "Динамический анализ")

    # ==============================================================================
    # TAB 4: AI Analysis
    # ==============================================================================

    def create_ai_analysis_tab(self):
        """AI analysis tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        controls = QHBoxLayout()
        btn_run_ai = QPushButton("Запустить AI-анализ")
        btn_run_ai.clicked.connect(self.run_ai_analysis)
        controls.addWidget(btn_run_ai)

        self.combo_ai_lang = QComboBox()
        self.combo_ai_lang.addItems(["Русский", "English"])
        controls.addWidget(QLabel("Язык:"))
        controls.addWidget(self.combo_ai_lang)

        btn_generate_yara = QPushButton("Сгенерировать правило YARA")
        btn_generate_yara.clicked.connect(self.generate_yara_rule)
        controls.addWidget(btn_generate_yara)

        controls.addStretch()
        layout.addLayout(controls)

        self.lbl_ai_provider_status = QLabel("AITUNNEL: статус не проверен")
        self.lbl_ai_provider_status.setWordWrap(True)
        layout.addWidget(self.lbl_ai_provider_status)

        splitter = QSplitter(Qt.Vertical)

        desc_group = QGroupBox("Описание угрозы от AI")
        desc_layout = QVBoxLayout()
        self.txt_ai_description = QTextEdit()
        self.txt_ai_description.setReadOnly(True)
        desc_layout.addWidget(self.txt_ai_description)
        desc_group.setLayout(desc_layout)
        splitter.addWidget(desc_group)

        class_group = QGroupBox("Классификация")
        class_layout = QVBoxLayout()
        self.txt_ai_classification = QTextEdit()
        self.txt_ai_classification.setReadOnly(True)
        class_layout.addWidget(self.txt_ai_classification)
        class_group.setLayout(class_layout)
        splitter.addWidget(class_group)

        yara_group = QGroupBox("Правило YARA")
        yara_layout = QVBoxLayout()
        self.txt_yara_rule = QTextEdit()
        self.txt_yara_rule.setReadOnly(True)
        yara_layout.addWidget(self.txt_yara_rule)
        yara_group.setLayout(yara_layout)
        splitter.addWidget(yara_group)

        layout.addWidget(splitter)
        self.tabs.addTab(tab, "AI-анализ")

    # ==============================================================================
    # TAB 5: Graph Visualization
    # ==============================================================================

    def create_graph_visualization_tab(self):
        """Graph visualisation tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        controls = QHBoxLayout()
        btn_generate_graph = QPushButton("Построить граф")
        btn_generate_graph.clicked.connect(self.generate_attack_graph)
        controls.addWidget(btn_generate_graph)

        self.combo_graph_layout = QComboBox()
        self.combo_graph_layout.addItems(["Пружинный", "Круговой", "Камада-Каваи", "Оболочка"])
        controls.addWidget(QLabel("Схема:"))
        controls.addWidget(self.combo_graph_layout)

        btn_save_graph = QPushButton("Сохранить граф")
        btn_save_graph.clicked.connect(self.save_graph)
        controls.addWidget(btn_save_graph)

        controls.addStretch()
        layout.addLayout(controls)

        if MATPLOTLIB_AVAILABLE and MatplotlibCanvas:
            self.graph_canvas = MatplotlibCanvas(width=12, height=8, dpi=100)
            layout.addWidget(self.graph_canvas)
        else:
            layout.addWidget(QLabel("Matplotlib недоступен"))

        stats_group = QGroupBox("Статистика графа")
        stats_layout = QGridLayout()
        self.lbl_graph_nodes = QLabel("Узлы: -")
        self.lbl_graph_edges = QLabel("Рёбра: -")
        stats_layout.addWidget(self.lbl_graph_nodes, 0, 0)
        stats_layout.addWidget(self.lbl_graph_edges, 0, 1)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        self.tabs.addTab(tab, "Граф атаки")

    def create_3d_visualization_tab(self):
        """Tab 6: 3D Visualization"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        controls = QHBoxLayout()
        btn_generate_3d = QPushButton("Построить 3D-визуализацию")
        btn_generate_3d.clicked.connect(self.generate_3d_visualization)
        controls.addWidget(btn_generate_3d)

        btn_save_3d = QPushButton("Сохранить изображение")
        btn_save_3d.clicked.connect(self.save_3d_visualization)
        controls.addWidget(btn_save_3d)
        controls.addStretch()
        layout.addLayout(controls)

        # Lazily enable pyqtgraph if requested via environment
        if USE_PYQTGRAPH and ensure_pyqtgraph_ready() and gl:
            self.gl_view = gl.GLViewWidget()
            self.gl_view.opts["distance"] = 30
            self.gl_view.setBackgroundColor(pg.mkColor("#1E1E1E"))
            layout.addWidget(self.gl_view)
        elif MATPLOTLIB_AVAILABLE and MatplotlibCanvas:
            self.canvas_3d = MatplotlibCanvas(width=12, height=10, dpi=100)
            layout.addWidget(self.canvas_3d)
        else:
            layout.addWidget(QLabel("Для 3D-визуализации требуется pyqtgraph или matplotlib."))

        self.tabs.addTab(tab, "3D-визуализация")

    def create_threat_intel_tab(self):
        """Tab 7: Threat Intelligence"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        controls = QHBoxLayout()
        self.btn_check_intel = QPushButton("Проверить IoC")
        self.btn_check_intel.clicked.connect(self.check_threat_intel)
        controls.addWidget(self.btn_check_intel)

        self.input_ioc = QLineEdit()
        self.input_ioc.setPlaceholderText("Введите IP, домен или хеш...")
        controls.addWidget(self.input_ioc)
        controls.addStretch()
        layout.addLayout(controls)

        intel_tabs = QTabWidget()

        self.text_vt_result = QTextEdit()
        self.text_vt_result.setReadOnly(True)
        intel_tabs.addTab(self.text_vt_result, "VirusTotal")

        self.text_abuseipdb_result = QTextEdit()
        self.text_abuseipdb_result.setReadOnly(True)
        intel_tabs.addTab(self.text_abuseipdb_result, "AbuseIPDB")

        self.text_otx_result = QTextEdit()
        self.text_otx_result.setReadOnly(True)
        intel_tabs.addTab(self.text_otx_result, "AlienVault OTX")

        self.text_urlhaus_result = QTextEdit()
        self.text_urlhaus_result.setReadOnly(True)
        intel_tabs.addTab(self.text_urlhaus_result, "URLhaus")

        layout.addWidget(intel_tabs)

        self.tabs.addTab(tab, "Проверка IoC / TI")

    def create_mitre_attack_tab(self):
        """Tab 8: MITRE ATT&CK"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        controls = QHBoxLayout()
        btn_map_techniques = QPushButton("Сопоставить техники")
        btn_map_techniques.clicked.connect(self.map_mitre_techniques)
        controls.addWidget(btn_map_techniques)

        btn_export_navigator = QPushButton("Экспортировать ATT&CK Navigator")
        btn_export_navigator.clicked.connect(self.export_attack_navigator)
        controls.addWidget(btn_export_navigator)
        controls.addStretch()
        layout.addLayout(controls)

        self.table_mitre = QTableWidget()
        self.table_mitre.setColumnCount(4)
        self.table_mitre.setHorizontalHeaderLabels(["ID техники", "Техника", "Тактика", "Достоверность"])
        self.table_mitre.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table_mitre)

        summary_group = QGroupBox("Сводка")
        summary_layout = QVBoxLayout()
        self.lbl_mitre_summary = QLabel("Обнаружено техник: -")
        summary_layout.addWidget(self.lbl_mitre_summary)
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)

        d3fend_group = QGroupBox("Рекомендации D3FEND")
        d3fend_layout = QVBoxLayout()
        self.text_d3fend_summary = QTextEdit()
        self.text_d3fend_summary.setReadOnly(True)
        d3fend_layout.addWidget(self.text_d3fend_summary)
        d3fend_group.setLayout(d3fend_layout)
        layout.addWidget(d3fend_group)

        self.tabs.addTab(tab, "MITRE ATT&CK")

    def create_fusion_retro_tab(self):
        """Tab: Fusion and external retro-hunt."""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        controls = QHBoxLayout()
        self.btn_run_retrohunt = QPushButton("Запустить ретрохант")
        self.btn_run_retrohunt.clicked.connect(self.run_external_retrohunt)
        controls.addWidget(self.btn_run_retrohunt)

        btn_refresh_status = QPushButton("Обновить статус")
        btn_refresh_status.clicked.connect(self.refresh_subsystem_status)
        controls.addWidget(btn_refresh_status)
        controls.addStretch()
        layout.addLayout(controls)

        self.text_subsystem_status = QTextEdit()
        self.text_subsystem_status.setReadOnly(True)
        layout.addWidget(self.text_subsystem_status)

        splitter = QSplitter(Qt.Horizontal)
        self.text_fusion_summary = QTextEdit()
        self.text_fusion_summary.setReadOnly(True)
        splitter.addWidget(self.text_fusion_summary)

        self.text_retrohunt_summary = QTextEdit()
        self.text_retrohunt_summary.setReadOnly(True)
        splitter.addWidget(self.text_retrohunt_summary)
        layout.addWidget(splitter)

        self.tabs.addTab(tab, "Fusion и ретрохант")
        self.refresh_subsystem_status()

    def create_network_analysis_tab(self):
        """Tab 9: Network Analysis"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        controls = QHBoxLayout()
        btn_analyze_network = QPushButton("Анализировать сеть")
        btn_analyze_network.clicked.connect(self.analyze_network)
        controls.addWidget(btn_analyze_network)
        controls.addStretch()
        layout.addLayout(controls)

        network_tabs = QTabWidget()

        self.table_connections = QTableWidget()
        self.table_connections.setColumnCount(4)
        self.table_connections.setHorizontalHeaderLabels(["Удалённый IP", "Порт", "Протокол", "Статус"])
        network_tabs.addTab(self.table_connections, "Соединения")

        self.table_beaconing = QTableWidget()
        self.table_beaconing.setColumnCount(4)
        self.table_beaconing.setHorizontalHeaderLabels(["IP", "Количество", "Интервал (с)", "Регулярность %"])
        network_tabs.addTab(self.table_beaconing, "Маячковая C2-активность")

        self.table_dns = QTableWidget()
        self.table_dns.setColumnCount(3)
        self.table_dns.setHorizontalHeaderLabels(["Домен", "Тип записи", "Подозрительность"])
        network_tabs.addTab(self.table_dns, "DNS")

        self.text_http_analysis = QTextEdit()
        self.text_http_analysis.setReadOnly(True)
        network_tabs.addTab(self.text_http_analysis, "HTTP/HTTPS")

        layout.addWidget(network_tabs)

        self.tabs.addTab(tab, "Сетевой анализ")

    def create_monitoring_tab(self):
        """Tab: Live filesystem monitoring."""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        if not FILE_MONITOR_AVAILABLE:
            label = QLabel(
                "Для мониторинга файловой системы требуется пакет 'watchdog'. "
                "Установите его, чтобы включить функции живого мониторинга."
            )
            label.setWordWrap(True)
            layout.addWidget(label)
            self.tabs.addTab(tab, "Мониторинг")
            return

        paths_group = QGroupBox("Отслеживаемые каталоги")
        paths_layout = QVBoxLayout()
        self.monitor_paths_list = QListWidget()
        paths_layout.addWidget(self.monitor_paths_list)

        paths_controls = QHBoxLayout()
        btn_load_defaults = QPushButton("Загрузить по умолчанию")
        btn_load_defaults.clicked.connect(self._load_monitor_defaults)
        paths_controls.addWidget(btn_load_defaults)
        btn_add_path = QPushButton("Добавить каталог")
        btn_add_path.clicked.connect(self._add_monitor_path)
        paths_controls.addWidget(btn_add_path)
        btn_remove_path = QPushButton("Удалить выбранное")
        btn_remove_path.clicked.connect(self._remove_selected_monitor_path)
        paths_controls.addWidget(btn_remove_path)
        paths_controls.addStretch()
        paths_layout.addLayout(paths_controls)
        paths_group.setLayout(paths_layout)
        layout.addWidget(paths_group)

        filters_group = QGroupBox("Фильтры")
        filters_layout = QGridLayout()
        filters_layout.addWidget(QLabel("Включать расширения:"), 0, 0)
        self.monitor_include_input = QLineEdit(".exe,.dll,.pdf,.doc,.docx,.elf")
        filters_layout.addWidget(self.monitor_include_input, 0, 1)
        filters_layout.addWidget(QLabel("Исключать пути:"), 1, 0)
        self.monitor_exclude_input = QLineEdit()
        filters_layout.addWidget(self.monitor_exclude_input, 1, 1)
        self.monitor_baseline_checkbox = QCheckBox("Выполнить базовый проход перед запуском")
        self.monitor_baseline_checkbox.setChecked(True)
        filters_layout.addWidget(self.monitor_baseline_checkbox, 2, 0, 1, 2)
        filters_group.setLayout(filters_layout)
        layout.addWidget(filters_group)

        controls = QHBoxLayout()
        self.monitor_status_label = QLabel("Статус: ожидание")
        self.monitor_status_label.setStyleSheet("color: #14FFEC;")
        controls.addWidget(self.monitor_status_label)

        controls.addStretch()

        self.monitor_start_button = QPushButton("Запустить мониторинг")
        self.monitor_start_button.clicked.connect(self.start_monitoring)
        controls.addWidget(self.monitor_start_button)

        self.monitor_stop_button = QPushButton("Остановить")
        self.monitor_stop_button.setEnabled(False)
        self.monitor_stop_button.clicked.connect(self.stop_monitoring)
        controls.addWidget(self.monitor_stop_button)

        btn_baseline = QPushButton("Запустить baseline сейчас")
        btn_baseline.clicked.connect(self.run_monitor_baseline)
        controls.addWidget(btn_baseline)

        btn_smart_scan = QPushButton("Умное сканирование")
        btn_smart_scan.clicked.connect(self.smart_monitor_scan)
        controls.addWidget(btn_smart_scan)

        layout.addLayout(controls)

        self.table_monitor_events = QTableWidget()
        self.table_monitor_events.setColumnCount(5)
        self.table_monitor_events.setHorizontalHeaderLabels(
            ["Время", "Событие", "Путь", "Размер", "Подозрительно"]
        )
        header = self.table_monitor_events.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_monitor_events.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_monitor_events.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table_monitor_events)

        self.monitor_stats_label = QLabel("События: 0 | Baseline: 0")
        layout.addWidget(self.monitor_stats_label)

        self.tabs.addTab(tab, "Мониторинг")
        self._load_monitor_defaults()

    # ----- Monitoring helpers -----

    def _get_monitor_paths(self) -> List[str]:
        if not self.monitor_paths_list:
            return []
        return [self.monitor_paths_list.item(i).text() for i in range(self.monitor_paths_list.count())]

    def _load_monitor_defaults(self):
        defaults = config_manager.get("MONITORING", {}) or {}
        paths = defaults.get("paths") or []
        if self.monitor_paths_list:
            self.monitor_paths_list.clear()
            for path in paths:
                self.monitor_paths_list.addItem(os.path.abspath(path))
        include_ext = defaults.get("include_extensions")
        if include_ext and self.monitor_include_input:
            self.monitor_include_input.setText(",".join(include_ext))
        exclude_paths = defaults.get("exclude_paths")
        if exclude_paths and self.monitor_exclude_input:
            self.monitor_exclude_input.setText(",".join(exclude_paths))
        self._update_monitor_stats()

    def _add_monitor_path(self):
        directory = QFileDialog.getExistingDirectory(self, "Выберите каталог для мониторинга")
        if directory and self.monitor_paths_list:
            if directory not in self._get_monitor_paths():
                self.monitor_paths_list.addItem(directory)
        self._update_monitor_stats()

    def _remove_selected_monitor_path(self):
        if not self.monitor_paths_list:
            return
        for item in self.monitor_paths_list.selectedItems():
            self.monitor_paths_list.takeItem(self.monitor_paths_list.row(item))
        self._update_monitor_stats()

    def _parse_csv_field(self, text: str) -> List[str]:
        return [part.strip() for part in text.split(",") if part.strip()]

    def start_monitoring(self):
        if not FILE_MONITOR_AVAILABLE or FileMonitorService is None:
            QMessageBox.warning(self, "Недоступно", "watchdog не установлен, мониторинг отключён.")
            return
        paths = self._get_monitor_paths()
        if not paths:
            QMessageBox.warning(self, "Нет путей", "Добавьте хотя бы один каталог для мониторинга.")
            return

        defaults = config_manager.get("MONITORING", {}) or {}
        include_text = self.monitor_include_input.text() if self.monitor_include_input else ""
        include_ext = self._parse_csv_field(include_text) or defaults.get("include_extensions")
        exclude_text = self.monitor_exclude_input.text() if self.monitor_exclude_input else ""
        exclude_paths = self._parse_csv_field(exclude_text) or defaults.get("exclude_paths")

        if self.monitor_service:
            try:
                self.monitor_service.stop()
            except Exception:
                logger.exception("Failed to stop existing monitor service.")

        try:
            self.monitor_service = FileMonitorService(
                directories=paths,
                include_extensions=include_ext,
                exclude_paths=exclude_paths,
                recursive=defaults.get("recursive", True),
                baseline_with_hashes=defaults.get("baseline_with_hashes", True),
                event_queue=self.monitor_event_queue,
                max_events=defaults.get("max_events", 500),
                throttle_per_minute=defaults.get("throttle_per_minute"),
            )
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить мониторинг: {exc}")
            logger.exception("Monitor initialisation failed: %s", exc)
            self.monitor_service = None
            return

        baseline_count: Optional[int] = None
        if self.monitor_baseline_checkbox and self.monitor_baseline_checkbox.isChecked():
            baseline_results = self.monitor_service.run_baseline()
            baseline_count = len(baseline_results)

        self.monitor_service.start()
        self.monitor_events.clear()
        self.table_monitor_events.setRowCount(0)
        self.monitor_timer.start()

        if self.monitor_status_label:
            self.monitor_status_label.setText("Статус: работает")
        if self.monitor_start_button:
            self.monitor_start_button.setEnabled(False)
        if self.monitor_stop_button:
            self.monitor_stop_button.setEnabled(True)

        self._update_monitor_stats(baseline_count=baseline_count)
        logger.info("Monitoring started for %d directories.", len(paths))

    def stop_monitoring(self):
        if self.monitor_service:
            try:
                self.monitor_service.stop()
            except Exception:
                logger.exception("Error stopping monitor service.")
        self.monitor_service = None
        self.monitor_timer.stop()
        if self.monitor_status_label:
            self.monitor_status_label.setText("Статус: ожидание")
        if self.monitor_start_button:
            self.monitor_start_button.setEnabled(True)
        if self.monitor_stop_button:
            self.monitor_stop_button.setEnabled(False)
        self._update_monitor_stats()

    def run_monitor_baseline(self):
        paths = self._get_monitor_paths()
        if not paths:
            QMessageBox.warning(self, "Нет путей", "Добавьте каталоги перед запуском baseline.")
            return
        defaults = config_manager.get("MONITORING", {}) or {}
        try:
            service = (
                self.monitor_service
                if self.monitor_service
                else FileMonitorService(
                    directories=paths,
                    include_extensions=defaults.get("include_extensions"),
                    exclude_paths=defaults.get("exclude_paths"),
                    recursive=defaults.get("recursive", True),
                    baseline_with_hashes=defaults.get("baseline_with_hashes", True),
                    max_events=defaults.get("max_events", 500),
                    throttle_per_minute=defaults.get("throttle_per_minute"),
                )
            )
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", f"Не удалось инициализировать baseline: {exc}")
            logger.exception("Baseline initialisation failed: %s", exc)
            return

        results = service.run_baseline()
        suspicious = sum(1 for item in results if item.get("suspicious"))
        QMessageBox.information(
            self,
            "Baseline завершён",
            f"Baseline проверил {len(results)} файлов. Подозрительных файлов: {suspicious}.",
        )
        self._update_monitor_stats(baseline_count=len(results))

    def smart_monitor_scan(self):
        if not self.monitor_service:
            QMessageBox.warning(self, "Мониторинг не запущен", "Сначала запустите мониторинг, затем умное сканирование.")
            return
        target_path = None
        if self.table_monitor_events and self.table_monitor_events.currentRow() >= 0:
            item = self.table_monitor_events.item(self.table_monitor_events.currentRow(), 2)
            if item:
                target_path = item.data(Qt.UserRole) or item.text()
        if not target_path:
            paths = self._get_monitor_paths()
            target_path = paths[0] if paths else None
        results = self.monitor_service.smart_scan(target_path)
        if not results:
            QMessageBox.information(self, "Умное сканирование", "Подозрительные файлы не обнаружены.")
            return
        suspicious = [entry for entry in results if entry.get("suspicious")]
        message = f"Умное сканирование проверило {len(results)} файлов.\nПодозрительных: {len(suspicious)}"
        QMessageBox.information(self, "Умное сканирование завершено", message)

    def _poll_monitor_events(self):
        if not self.monitor_service:
            return
        events = self.monitor_service.drain_public_queue()
        if not events:
            return
        for event in events:
            self._append_monitor_event(event)

    def _append_monitor_event(self, event: Dict[str, Any]):
        if not self.table_monitor_events:
            return
        timestamp = event.get("timestamp", time.time())
        ts_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
        row = 0
        self.table_monitor_events.insertRow(row)
        ts_item = QTableWidgetItem(ts_str)
        event_item = QTableWidgetItem(event.get("action", "-"))
        path_item = QTableWidgetItem(event.get("path", "-"))
        path_item.setData(Qt.UserRole, event.get("path"))
        size = event.get("size")
        size_item = QTableWidgetItem(f"{size}" if size is not None else "-")
        suspicious = event.get("suspicious")
        suspicious_item = QTableWidgetItem("да" if suspicious else "нет")
        if suspicious:
            suspicious_item.setForeground(Qt.red)
        self.table_monitor_events.setItem(row, 0, ts_item)
        self.table_monitor_events.setItem(row, 1, event_item)
        self.table_monitor_events.setItem(row, 2, path_item)
        self.table_monitor_events.setItem(row, 3, size_item)
        self.table_monitor_events.setItem(row, 4, suspicious_item)

        max_rows = 200
        while self.table_monitor_events.rowCount() > max_rows:
            self.table_monitor_events.removeRow(self.table_monitor_events.rowCount() - 1)

        self.monitor_events.append(event)
        if len(self.monitor_events) > 1000:
            self.monitor_events = self.monitor_events[-1000:]
        self._update_monitor_stats()

    def _update_monitor_stats(self, baseline_count: Optional[int] = None):
        if baseline_count is not None:
            self.monitor_baseline_count = baseline_count
        if self.monitor_stats_label:
            text = f"События: {len(getattr(self, 'monitor_events', []))} | Baseline: {self.monitor_baseline_count}"
            self.monitor_stats_label.setText(text)

    def create_clustering_tab(self):
        """Tab: Malware Family Clustering"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        dataset_group = QGroupBox("Набор данных для кластеризации")
        dataset_layout = QGridLayout()

        self.lbl_cluster_dataset = QLabel("Набор данных: не загружен")
        dataset_layout.addWidget(self.lbl_cluster_dataset, 0, 0, 1, 3)

        btn_load_dataset = QPushButton("Загрузить JSON-набор")
        btn_load_dataset.clicked.connect(self.load_clustering_dataset)
        dataset_layout.addWidget(btn_load_dataset, 1, 0)

        dataset_layout.addWidget(QLabel("DBSCAN eps:"), 1, 1)
        self.spin_cluster_eps = QDoubleSpinBox()
        self.spin_cluster_eps.setRange(0.05, 5.0)
        self.spin_cluster_eps.setSingleStep(0.05)
        self.spin_cluster_eps.setValue(0.9)
        dataset_layout.addWidget(self.spin_cluster_eps, 1, 2)

        dataset_layout.addWidget(QLabel("min_samples:"), 2, 1)
        self.spin_cluster_min_samples = QSpinBox()
        self.spin_cluster_min_samples.setRange(1, 100)
        self.spin_cluster_min_samples.setValue(3)
        dataset_layout.addWidget(self.spin_cluster_min_samples, 2, 2)

        btn_run_clustering = QPushButton("Запустить кластеризацию")
        btn_run_clustering.clicked.connect(self.run_clustering)
        dataset_layout.addWidget(btn_run_clustering, 2, 0)

        btn_persist_profiles = QPushButton("Сохранить ML-профили")
        btn_persist_profiles.clicked.connect(self.persist_clustering_profiles)
        dataset_layout.addWidget(btn_persist_profiles, 3, 0)

        dataset_group.setLayout(dataset_layout)
        layout.addWidget(dataset_group)

        splitter = QSplitter(Qt.Vertical)

        clusters_widget = QWidget()
        clusters_layout = QVBoxLayout()
        clusters_widget.setLayout(clusters_layout)

        self.table_clusters = QTableWidget()
        self.table_clusters.setColumnCount(6)
        self.table_clusters.setHorizontalHeaderLabels(
            ["Кластер", "Размер", "Средний риск", "Доминирующий квадрант", "Топ API", "Топ поведения"]
        )
        self.table_clusters.cellClicked.connect(self.on_cluster_selected)
        clusters_layout.addWidget(self.table_clusters)

        splitter.addWidget(clusters_widget)

        details_widget = QWidget()
        details_layout = QVBoxLayout()
        details_widget.setLayout(details_layout)

        self.table_cluster_samples = QTableWidget()
        self.table_cluster_samples.setColumnCount(6)
        self.table_cluster_samples.setHorizontalHeaderLabels(
            ["ID образца", "Риск", "ML", "Квадрант", "Топ API", "Топ IoC"]
        )
        details_layout.addWidget(self.table_cluster_samples)

        self.text_cluster_summary = QTextEdit()
        self.text_cluster_summary.setReadOnly(True)
        self.text_cluster_summary.setPlaceholderText("Сводка по кластеру...")
        details_layout.addWidget(self.text_cluster_summary)

        splitter.addWidget(details_widget)
        layout.addWidget(splitter)

        family_group = QGroupBox("Профили семейств")
        family_layout = QGridLayout()

        self.lbl_family_status = QLabel("Профили ещё не построены")
        family_layout.addWidget(self.lbl_family_status, 0, 0, 1, 3)

        btn_load_family_dataset = QPushButton("Загрузить размеченный набор")
        btn_load_family_dataset.clicked.connect(self.load_family_dataset)
        family_layout.addWidget(btn_load_family_dataset, 1, 0)

        family_layout.addWidget(QLabel("Ключ семейства:"), 1, 1)
        self.input_family_key = QLineEdit("family")
        family_layout.addWidget(self.input_family_key, 1, 2)

        btn_build_profiles = QPushButton("Построить профили")
        btn_build_profiles.clicked.connect(self.build_family_profiles_ui)
        family_layout.addWidget(btn_build_profiles, 2, 0)

        btn_identify_current = QPushButton("Определить текущее семейство")
        btn_identify_current.clicked.connect(self.identify_current_sample_family)
        family_layout.addWidget(btn_identify_current, 2, 1, 1, 2)

        self.text_family_results = QTextEdit()
        self.text_family_results.setReadOnly(True)
        self.text_family_results.setPlaceholderText("Результаты определения семейства...")
        family_layout.addWidget(self.text_family_results, 3, 0, 1, 3)

        family_group.setLayout(family_layout)
        layout.addWidget(family_group)

        self.tabs.addTab(tab, "Кластеризация")

    # ----- Clustering helpers -----

    def _load_dataset_file(self, path: str) -> List[Dict[str, Any]]:
        dataset: List[Dict[str, Any]] = []
        ext = os.path.splitext(path)[1].lower()

        try:
            if ext in {".jsonl", ".ndjson"}:
                with open(path, "r", encoding="utf-8") as handle:
                    for idx, line in enumerate(handle):
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        if isinstance(entry, dict):
                            dataset.append(self._normalise_sample(entry, idx))
            else:
                with open(path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, dict):
                    for key in ("samples", "data", "dataset", "items"):
                        if key in data and isinstance(data[key], list):
                            data = data[key]
                            break
                if not isinstance(data, list):
                    raise ValueError("Неверный формат JSON: ожидался список образцов")
                for idx, entry in enumerate(data):
                    if isinstance(entry, dict):
                        dataset.append(self._normalise_sample(entry, idx))
        except Exception as exc:
            raise RuntimeError(f"Не удалось прочитать набор данных: {exc}") from exc

        return dataset

    def _normalise_sample(self, entry: Dict[str, Any], idx: int) -> Dict[str, Any]:
        sample = dict(entry)
        if "id" not in sample:
            sample["id"] = (
                sample.get("sha256")
                or sample.get("hash")
                or sample.get("file")
                or sample.get("name")
                or f"sample_{idx}"
            )
        return sample

    def load_clustering_dataset(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Загрузка набора данных (JSON/JSONL)",
            "",
            "JSON Files (*.json *.jsonl *.ndjson);;All Files (*.*)",
        )
        if not file_path:
            return
        try:
            dataset = self._load_dataset_file(file_path)
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", str(exc))
            logger.error("Failed to load clustering dataset: %s", exc)
            return

        if not dataset:
            QMessageBox.warning(self, "Пустой набор", "Файл не содержит корректных записей.")
            return

        self.clustering_dataset = dataset
        self.lbl_cluster_dataset.setText(
            f"Набор данных: {os.path.basename(file_path)} ({len(dataset)} образцов)"
        )
        self.clustering_results = {}
        self.table_clusters.setRowCount(0)
        self.table_cluster_samples.setRowCount(0)
        self.text_cluster_summary.clear()
        self.statusBar().showMessage(f"Загружено {len(dataset)} образцов для кластеризации")

    def run_clustering(self):
        if not self.clustering_dataset:
            QMessageBox.warning(self, "Нет данных", "Сначала загрузите набор данных для кластеризации.")
            return
        eps = float(self.spin_cluster_eps.value())
        min_samples = int(self.spin_cluster_min_samples.value())
        try:
            self.clustering_clusterer = MalwareClustering(eps=eps, min_samples=min_samples)
            summary = self.clustering_clusterer.cluster_by_behavior(self.clustering_dataset)
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка кластеризации", str(exc))
            logger.exception("Clustering failed: %s", exc)
            return

        self.clustering_results = summary or {}
        self._populate_clusters_table(summary)
        noise = summary.get("noise", 0)
        message = f"Кластеризация завершена. Найдено кластеров: {len(summary.get('clusters', {}))}."
        if noise:
            message += f" Noise samples: {noise}."
        self.statusBar().showMessage(message)

        if self.table_clusters.rowCount() > 0:
            self.table_clusters.selectRow(0)
            self.on_cluster_selected(0, 0)

    def _populate_clusters_table(self, summary: Dict[str, Any]):
        clusters = summary.get("clusters", {})
        self.table_clusters.setRowCount(0)
        if not clusters:
            return
        for label in sorted(clusters.keys()):
            info = clusters[label]
            summary_info = info.get("summary", {})
            row = self.table_clusters.rowCount()
            self.table_clusters.insertRow(row)

            item_label = QTableWidgetItem(str(label))
            item_label.setData(Qt.UserRole, label)
            self.table_clusters.setItem(row, 0, item_label)

            self.table_clusters.setItem(row, 1, QTableWidgetItem(str(info.get("size", 0))))
            self.table_clusters.setItem(
                row,
                2,
                QTableWidgetItem(f"{summary_info.get('avg_risk', 0):.1f}"),
            )
            self.table_clusters.setItem(
                row,
                3,
                QTableWidgetItem(str(summary_info.get("dominant_quadrant") or "-")),
            )
            self.table_clusters.setItem(
                row,
                4,
                QTableWidgetItem(self._format_feature_list(summary_info.get("top_apis"))),
            )
            self.table_clusters.setItem(
                row,
                5,
                QTableWidgetItem(self._format_feature_list(summary_info.get("top_behaviors"))),
            )

    def _format_feature_list(self, items: Optional[List[str]], limit: int = 3) -> str:
        if not items:
            return "-"
        return ", ".join(items[:limit])

    def on_cluster_selected(self, row: int, column: int):
        item = self.table_clusters.item(row, 0)
        if not item:
            return
        label = item.data(Qt.UserRole)
        if label is None:
            try:
                label = int(item.text())
            except ValueError:
                return
        self.selected_cluster_label = label
        self._populate_cluster_samples(label)

    def _populate_cluster_samples(self, label: int):
        cluster_info = self.clustering_results.get("clusters", {}).get(label)
        self.table_cluster_samples.setRowCount(0)
        if not cluster_info:
            self.text_cluster_summary.clear()
            return

        samples = cluster_info.get("samples", [])
        for sample in samples:
            row = self.table_cluster_samples.rowCount()
            self.table_cluster_samples.insertRow(row)
            self.table_cluster_samples.setItem(row, 0, QTableWidgetItem(str(sample.get("id", "-"))))
            self.table_cluster_samples.setItem(
                row,
                1,
                QTableWidgetItem(f"{sample.get('risk_score', 0):.1f}"),
            )
            self.table_cluster_samples.setItem(
                row,
                2,
                QTableWidgetItem(f"{sample.get('ml_probability', 0):.2f}"),
            )
            self.table_cluster_samples.setItem(
                row,
                3,
                QTableWidgetItem(
                    str((sample.get("behavioral_plane") or {}).get("quadrant") or "-")
                ),
            )
            self.table_cluster_samples.setItem(
                row,
                4,
                QTableWidgetItem(self._format_feature_list(sample.get("api_tokens"))),
            )
            self.table_cluster_samples.setItem(
                row,
                5,
                QTableWidgetItem(self._format_feature_list(sample.get("ioc_tokens"))),
            )

        self.display_cluster_summary(label, cluster_info)

    def display_cluster_summary(self, label: int, cluster_info: Dict[str, Any]):
        summary = cluster_info.get("summary", {})
        lines = [
            f"Кластер #{label}",
            f"Размер: {cluster_info.get('size', 0)} образцов",
            f"Средний риск: {summary.get('avg_risk', 0):.2f}",
            f"Средняя ML-вероятность: {summary.get('avg_ml_probability', 0):.2f}",
            f"Доминирующий квадрант: {summary.get('dominant_quadrant', '-')}",
            f"Распределение по квадрантам: {summary.get('quadrant_distribution', {})}",
            f"Подозрительные API: {self._format_feature_list(summary.get('top_apis'), limit=5)}",
            f"Поведенческие паттерны: {self._format_feature_list(summary.get('top_behaviors'), limit=5)}",
            f"IOC: {self._format_feature_list(summary.get('top_iocs'), limit=5)}",
        ]
        self.text_cluster_summary.setPlainText("\n".join(lines))

    def persist_clustering_profiles(self):
        if not self.clustering_clusterer:
            QMessageBox.warning(self, "Нет модели", "Сначала запустите кластеризацию, затем сохраняйте ML-профили.")
            return
        try:
            stored = self.clustering_clusterer.persist_similarity_profiles()
            persistence_status = self.clustering_clusterer.get_persistence_status()
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка сохранения", str(exc))
            logger.exception("Failed to persist ML profiles: %s", exc)
            return

        sqlite_status = persistence_status.get("sqlite", {})
        qdrant_status = persistence_status.get("qdrant", {})
        message_lines = [
            f"Сохранено {stored} ML-профилей",
            f"SQLite: {sqlite_status.get('stored', 0)} | {sqlite_status.get('path', '-')}",
        ]
        if qdrant_status.get("configured"):
            qdrant_line = (
                f"Qdrant: {qdrant_status.get('stored', 0)} | "
                f"{qdrant_status.get('endpoint', '-')}/{qdrant_status.get('collection', '-')}"
            )
            if qdrant_status.get("error"):
                qdrant_line += f" | ошибка: {qdrant_status.get('error')}"
            message_lines.append(qdrant_line)
        else:
            message_lines.append("Qdrant: отключён или не настроен")

        QMessageBox.information(
            self,
            "Профили сохранены",
            "\n".join(message_lines),
        )
        if qdrant_status.get("configured") and not qdrant_status.get("error"):
            self.statusBar().showMessage(f"Сохранено {stored} ML-профилей в SQLite и Qdrant")
        else:
            self.statusBar().showMessage(f"Сохранено {stored} ML-профилей в SQLite")

    def load_family_dataset(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Загрузить размеченный набор",
            "",
            "JSON Files (*.json *.jsonl *.ndjson);;All Files (*.*)",
        )
        if not file_path:
            return
        try:
            dataset = self._load_dataset_file(file_path)
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка загрузки", str(exc))
            return
        if not dataset:
            QMessageBox.warning(self, "Пустой набор", "Файл не содержит корректных записей.")
            return

        self.family_dataset = dataset
        self.lbl_family_status.setText(
            f"Набор семейств: {os.path.basename(file_path)} ({len(dataset)} образцов)"
        )
        self.family_profiles = {}
        self.text_family_results.clear()

    def build_family_profiles_ui(self):
        dataset = self.family_dataset or self.clustering_dataset
        if not dataset:
            QMessageBox.warning(self, "Нет данных", "Сначала загрузите размеченный набор данных.")
            return

        family_key = self.input_family_key.text().strip() or "family"

        try:
            clusterer = MalwareClustering()
            profiles = clusterer.build_family_profiles(dataset, family_key=family_key)
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка профилирования", str(exc))
            logger.exception("Failed to build family profiles: %s", exc)
            return

        if not profiles:
            QMessageBox.warning(
                self,
                "Нет семейств",
                "Не удалось построить профили. Убедитесь, что в наборе данных есть поле с меткой семейства.",
            )
            return

        self.family_clusterer = clusterer
        self.family_profiles = profiles

        lines = [
            f"Построено профилей: {len(profiles)} (ключ семейства '{family_key}')",
        ]
        for family, profile in sorted(profiles.items()):
            summary = profile.get("summary", {})
            lines.append(
                f"- {family}: {profile.get('size', 0)} образцов, риск {summary.get('avg_risk', 0):.1f}"
            )

        self.lbl_family_status.setText(f"Профилей: {len(profiles)}")
        self.text_family_results.setPlainText("\n".join(lines))
        self.statusBar().showMessage(f"Построено профилей семейств: {len(profiles)}")

    def _build_current_sample_payload(self) -> Optional[Dict[str, Any]]:
        if not self.analysis_results:
            return None
        result = self.analysis_results
        static = result.get("static") or {}
        dynamic = result.get("dynamic") or {}
        risk = result.get("risk") or {}
        if not risk and result.get("threat_score") is not None:
            risk = {"score": result.get("threat_score", 0)}
        if "ml_probability" not in risk and result.get("risk", {}).get("ml_probability") is not None:
            risk["ml_probability"] = result["risk"]["ml_probability"]
        sample = {
            "id": result.get("id") or result.get("file") or "current_sample",
            "static": static,
            "dynamic": dynamic,
            "risk": risk,
            "iocs": result.get("iocs") or [],
            "behavioral_patterns": dynamic.get("behavioral_patterns") or result.get("behavioral_patterns") or [],
            "attributes": result.get("attributes") or {},
        }
        return sample

    def _format_family_identification(self, result: Dict[str, Any]) -> str:
        if not result or result.get("family") is None:
            return result.get("reason", "Не удалось определить семейство.") if result else "Не удалось определить семейство."

        lines = [
            f"Наиболее вероятное семейство: {result['family']}",
            f"Косинусное сходство: {result.get('similarity', 0):.3f}",
            f"Расстояние: {result.get('distance', 0):.3f}",
            f"Манхэттенское расстояние: {result.get('manhattan_distance', 0):.3f}",
            f"Квадрант: {result.get('quadrant', '-')}",
            "",
            "Лучшие кандидаты:",
        ]
        for candidate in result.get("candidates", []):
            lines.append(
                f"- {candidate['family']} | similarity={candidate['similarity']:.3f} "
                f"| distance={candidate['distance']:.3f} "
                f"| manhattan={candidate.get('manhattan_distance', 0):.3f} "
                f"| size={candidate.get('size', 0)}"
            )
        return "\n".join(lines)

    def _select_cluster_row_by_label(self, label: int) -> None:
        for row in range(self.table_clusters.rowCount()):
            item = self.table_clusters.item(row, 0)
            if not item:
                continue
            item_label = item.data(Qt.UserRole)
            if item_label is None:
                try:
                    item_label = int(item.text())
                except ValueError:
                    continue
            if item_label == label:
                self.table_clusters.selectRow(row)
                self.on_cluster_selected(row, 0)
                return

    def _build_ml_context(self) -> Dict[str, Any]:
        sample = self._build_current_sample_payload()
        if not sample:
            return {}

        plane: Dict[str, Any] = {}
        cluster_match: Dict[str, Any] = {}
        nearest_neighbors: List[Dict[str, Any]] = []
        family_match: Dict[str, Any] = {}

        projector = self.family_clusterer or self.clustering_clusterer
        if projector is None:
            try:
                projector = MalwareClustering()
            except Exception:
                projector = None

        if projector is not None:
            try:
                plane = projector.describe_sample_projection(
                    sample,
                    use_family_origin=bool(self.family_clusterer and self.family_profiles),
                )
            except Exception as exc:
                logger.debug("Sample projection unavailable: %s", exc)

        if self.clustering_clusterer:
            try:
                cluster_match = self.clustering_clusterer.identify_family(sample)
            except Exception as exc:
                logger.debug("Cluster match unavailable: %s", exc)
            try:
                nearest_neighbors = self.clustering_clusterer.get_nearest_neighbors(sample, top_k=3)
            except Exception as exc:
                logger.debug("Nearest neighbours unavailable: %s", exc)

        if self.family_clusterer and self.family_profiles:
            try:
                family_match = self.family_clusterer.identify_family_from_profiles(
                    sample,
                    profiles=self.family_profiles,
                    top_k=5,
                )
            except Exception as exc:
                logger.debug("Family identification unavailable: %s", exc)

        context = {
            "behavioral_plane": plane,
            "cluster_match": cluster_match,
            "nearest_neighbors": nearest_neighbors,
            "family_match": family_match,
        }
        self.analysis_results["ml_context"] = context

        label = cluster_match.get("label")
        if label is not None and self.table_clusters.rowCount() > 0:
            try:
                self._select_cluster_row_by_label(int(label))
            except Exception:
                pass

        if family_match and self.text_family_results:
            self.text_family_results.setPlainText(self._format_family_identification(family_match))

        return context

    def identify_current_sample_family(self):
        if not self.family_clusterer or not self.family_profiles:
            QMessageBox.warning(
                self,
                "Нет профилей",
                "Сначала постройте профили семейств, затем запускайте идентификацию.",
            )
            return
        sample = self._build_current_sample_payload()
        if not sample:
            QMessageBox.warning(self, "Нет данных", "Сначала проанализируйте файл, затем запускайте идентификацию семейства.")
            return
        try:
            result = self.family_clusterer.identify_family_from_profiles(
                sample,
                profiles=self.family_profiles,
                top_k=5,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка идентификации", str(exc))
            logger.exception("Family identification failed: %s", exc)
            return

        self.text_family_results.setPlainText(self._format_family_identification(result))

    def create_forensics_tab(self):
        """Tab 10: Forensics"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        controls = QHBoxLayout()
        btn_collect_artifacts = QPushButton("Собрать артефакты")
        btn_collect_artifacts.clicked.connect(self.collect_forensic_artifacts)
        controls.addWidget(btn_collect_artifacts)

        btn_detect_persistence = QPushButton("Найти персистентность")
        btn_detect_persistence.clicked.connect(self.detect_persistence)
        controls.addWidget(btn_detect_persistence)
        controls.addStretch()
        layout.addLayout(controls)

        forensics_tabs = QTabWidget()

        self.table_prefetch = QTableWidget()
        self.table_prefetch.setColumnCount(3)
        self.table_prefetch.setHorizontalHeaderLabels(["Файл", "Путь", "Изменён"])
        forensics_tabs.addTab(self.table_prefetch, "Prefetch")

        self.table_startup = QTableWidget()
        self.table_startup.setColumnCount(4)
        self.table_startup.setHorizontalHeaderLabels(["Hive", "Ключ", "Имя", "Значение"])
        forensics_tabs.addTab(self.table_startup, "Автозапуск")

        self.table_persistence = QTableWidget()
        self.table_persistence.setColumnCount(4)
        self.table_persistence.setHorizontalHeaderLabels(["Тип", "Файл", "Путь", "Изменён"])
        forensics_tabs.addTab(self.table_persistence, "Персистентность")

        self.text_timeline = QTextEdit()
        self.text_timeline.setReadOnly(True)
        forensics_tabs.addTab(self.text_timeline, "Таймлайн")

        layout.addWidget(forensics_tabs)

        self.tabs.addTab(tab, "Форензика")

    def create_reports_tab(self):
        """Tab 11: Reports"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        controls = QHBoxLayout()
        btn_generate_pdf = QPushButton("Создать PDF-отчёт")
        btn_generate_pdf.clicked.connect(self.generate_pdf_report)
        controls.addWidget(btn_generate_pdf)

        btn_generate_json = QPushButton("Экспортировать JSON")
        btn_generate_json.clicked.connect(self.export_json_report)
        controls.addWidget(btn_generate_json)

        btn_generate_html = QPushButton("Создать HTML-отчёт")
        btn_generate_html.clicked.connect(self.generate_html_report)
        controls.addWidget(btn_generate_html)
        controls.addStretch()
        layout.addLayout(controls)

        preview_group = QGroupBox("Предпросмотр отчёта")
        preview_layout = QVBoxLayout()
        self.text_report_preview = QTextEdit()
        self.text_report_preview.setReadOnly(True)
        preview_layout.addWidget(self.text_report_preview)
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        self.tabs.addTab(tab, "Отчёты")

    # ========== Event Handlers ==========

    def select_file(self):
        """Select file for analysis"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл для анализа", "", "All Files (*.*)"
        )
        if file_path:
            self.current_file = file_path
            self.input_file.setText(file_path)
            self.btn_quick_scan.setEnabled(True)
            self.btn_full_scan.setEnabled(True)
            logger.info(f"Selected file: {file_path}")

    def quick_analysis(self):
        """Run quick static analysis"""
        self._auto_ai_after_analysis = False
        self.run_static_analysis()

    def full_analysis(self):
        """Run full analysis (static + dynamic)"""
        self._auto_ai_after_analysis = True
        self.run_analysis()

    def save_report(self):
        """Save report"""
        self.generate_pdf_report()

    def run_analysis(self):
        """Run complete analysis"""
        if not self.current_file:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите файл.")
            return
        if not os.path.isfile(self.current_file):
            QMessageBox.critical(self, "Ошибка", "Выбранный файл недоступен.")
            return

        self._set_analysis_busy(True, f"Выполняется полный анализ файла {os.path.basename(self.current_file)}...")
        self.btn_save_report.setEnabled(False)

        # Start worker thread
        self.worker = AnalysisWorker(self.current_file)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.analysis_complete)
        self.worker.error.connect(self.analysis_error)
        self.worker.start()

        logger.info(f"Starting analysis of {self.current_file}")

    def run_static_analysis(self):
        """Run static analysis only"""
        if not self.current_file:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите файл.")
            return
        if not os.path.isfile(self.current_file):
            QMessageBox.critical(self, "Ошибка", "Выбранный файл недоступен.")
            return

        self.statusBar().showMessage("Выполняется статический анализ...")
        previous_range = (self.progress_bar.minimum(), self.progress_bar.maximum())
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(True)
        try:
            from analyzer.static_analysis import static_analysis
            from analyzer.heuristic_analysis import HeuristicAnalyzer
            results = static_analysis(self.current_file)
            heuristics = HeuristicAnalyzer(self.current_file).analyze()
            self.analysis_results = {'static': results, 'heuristic': heuristics}
            self.display_static_results(results, heuristics)
            self.display_all_results(self.analysis_results)
            self.btn_save_report.setEnabled(True)
            logger.info("Статический анализ завершён")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка статического анализа: {str(e)}")
            logger.error(f"Static analysis error: {e}")
        finally:
            self.progress_bar.setRange(*previous_range)
            self.progress_bar.setVisible(False)
            self.statusBar().showMessage("Статический анализ завершён")

    def run_dynamic_analysis(self):
        """Run dynamic analysis only"""
        if not self.current_file:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите файл.")
            return

        self.statusBar().showMessage("Выполняется динамический анализ...")
        previous_range = (self.progress_bar.minimum(), self.progress_bar.maximum())
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(True)
        try:
            from analyzer.dynamic_analysis import DynamicAnalyzer

            # Get timeout from combobox
            timeout_text = self.spin_timeout.currentText()
            timeout = int(timeout_text.split()[0])  # Extract numeric value from option label

            analyzer = DynamicAnalyzer(self.current_file, timeout=timeout)
            results = analyzer.start_analysis()

            if not self.analysis_results:
                self.analysis_results = {}
            self.analysis_results['dynamic'] = results

            self.display_all_results(self.analysis_results)
            self.btn_save_report.setEnabled(True)
            logger.info("Динамический анализ завершён")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка динамического анализа: {str(e)}")
            logger.error(f"Dynamic analysis error: {e}")
        finally:
            self.progress_bar.setRange(*previous_range)
            self.progress_bar.setVisible(False)
            self.statusBar().showMessage("Динамический анализ завершён")

    def update_progress(self, value):
        """Update progress bar"""
        if not self.progress_bar.isVisible():
            self.progress_bar.setVisible(True)
        if self.progress_bar.maximum() != 100 or self.progress_bar.minimum() != 0:
            self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(value)

    def analysis_complete(self, results):
        """Handle analysis completion"""
        self.analysis_results = results
        self.display_all_results(results)
        self.progress_bar.setValue(100)
        self._set_analysis_busy(False)
        self.btn_save_report.setEnabled(True)
        self.statusBar().showMessage("Анализ успешно завершён")
        QMessageBox.information(self, "Успешно", "Анализ успешно завершён.")
        logger.info("Анализ успешно завершён")
        if self._auto_ai_after_analysis:
            self._auto_ai_after_analysis = False
            self.run_ai_analysis()

    def analysis_error(self, error_msg):
        """Handle analysis error"""
        self._set_analysis_busy(False)
        self.statusBar().showMessage("Анализ завершился ошибкой")
        self.btn_save_report.setEnabled(bool(self.analysis_results))
        QMessageBox.critical(self, "Ошибка", f"Ошибка анализа: {error_msg}")
        logger.error(f"Analysis error: {error_msg}")

    def display_all_results(self, results):
        """Display results in all tabs"""
        risk_payload = results.get("risk") if isinstance(results.get("risk"), dict) else {}
        base_score = risk_payload.get("score")
        adjusted_score = risk_payload.get("adjusted_score", base_score)
        display_score = adjusted_score if isinstance(adjusted_score, (int, float)) else base_score
        level = risk_payload.get("adjusted_level") or risk_payload.get("level") or "-"
        if isinstance(display_score, (int, float)):
            results["threat_score"] = display_score

        # Overview
        self.lbl_file_path.setText(f"{os.path.abspath(self.current_file)}")
        try:
            file_size = os.path.getsize(self.current_file)
        except OSError:
            file_size = 0
        self.lbl_file_size.setText(f"{file_size} bytes")

        # Update hash labels if available
        static_results = results.get('static', {})
        hashes = static_results.get('hashes', {})
        if hashes:
            if 'md5' in hashes:
                self.lbl_file_md5.setText(hashes['md5'])
            if 'sha256' in hashes:
                self.lbl_file_sha256.setText(hashes['sha256'][:32] + "...")

        # Threat score
        threat_score = results.get('threat_score', 0)
        if isinstance(display_score, (int, float)):
            if isinstance(base_score, (int, float)) and display_score != base_score:
                self.lbl_threat_level.setText(
                    f"Оценка угрозы: {display_score:.1f}/100 | базовая={base_score:.1f} | уровень={level}"
                )
            else:
                self.lbl_threat_level.setText(f"Оценка угрозы: {display_score:.1f}/100 | уровень={level}")
        else:
            self.lbl_threat_level.setText(f"Оценка угрозы: {threat_score}/100")

        # Malware type (from static or AI analysis)
        malware_type = "Не определён"
        if 'ai_analysis' in results:
            malware_type = results['ai_analysis'].get('malware_type', 'Не определён')
        elif 'static' in results:
            file_type = results['static'].get('file_type', '')
            if file_type:
                malware_type = file_type
        self.lbl_malware_type.setText(f"Тип: {malware_type}")

        # AI verdict
        ai_verdict = "Не выполнен"
        if 'ai_analysis' in results:
            threat_level = results['ai_analysis'].get('threat_level', 'Неизвестно')
            confidence = results['ai_analysis'].get('confidence', 0)
            ai_verdict = f"{threat_level} (достоверность: {confidence:.0%})"
        self.lbl_ai_verdict.setText(f"Вердикт AI: {ai_verdict}")

        ml_probability = risk_payload.get("ml_probability")
        details = risk_payload.get("details") if isinstance(risk_payload.get("details"), dict) else {}
        ml_meta = details.get("ml_meta") if isinstance(details.get("ml_meta"), dict) else {}
        if isinstance(ml_probability, (int, float)):
            self.lbl_ml_probability.setText(f"ML-вероятность: {ml_probability:.3f}")
            mode = ml_meta.get("mode", "ml")
            model_path = ml_meta.get("model_path")
            suffix = f" | {model_path}" if model_path else ""
            self.lbl_ml_status.setText(f"Статус ML: активен ({mode}){suffix}")
        else:
            self.lbl_ml_probability.setText("ML-вероятность: недоступна")
            fallback_reason = details.get("ml_status") or details.get("ml_error") or "fallback / модель не загружена"
            self.lbl_ml_status.setText(f"Статус ML: {fallback_reason}")

        ml_context = self._build_ml_context()
        plane = ml_context.get("behavioral_plane") if isinstance(ml_context.get("behavioral_plane"), dict) else {}
        cluster_match = ml_context.get("cluster_match") if isinstance(ml_context.get("cluster_match"), dict) else {}
        family_match = ml_context.get("family_match") if isinstance(ml_context.get("family_match"), dict) else {}
        nearest_neighbors = ml_context.get("nearest_neighbors") if isinstance(ml_context.get("nearest_neighbors"), list) else []

        if plane:
            self.lbl_behavioral_quadrant.setText(
                "Поведенческий квадрант: "
                f"{plane.get('quadrant', '-')} | {plane.get('quadrant_label', 'Неизвестно')} "
                f"(x={plane.get('x', 0):.3f}, y={plane.get('y', 0):.3f})"
            )
        else:
            self.lbl_behavioral_quadrant.setText("Поведенческий квадрант: недоступен")

        if cluster_match and cluster_match.get("label") is not None:
            self.lbl_cluster_match.setText(
                "Соответствие кластеру: "
                f"#{cluster_match.get('label')} | сходство={cluster_match.get('similarity', 0):.3f} "
                f"| Манхэттен={cluster_match.get('manhattan_distance', 0):.3f}"
            )
        else:
            self.lbl_cluster_match.setText("Соответствие кластеру: недоступно (сначала запустите кластеризацию)")

        if family_match and family_match.get("family") is not None:
            self.lbl_family_match.setText(
                "Соответствие семейству: "
                f"{family_match.get('family')} | сходство={family_match.get('similarity', 0):.3f}"
            )
        else:
            self.lbl_family_match.setText("Соответствие семейству: недоступно (сначала постройте профили)")

        # Summary
        summary_lines = []
        summary_lines.append("=== Сводка анализа ===\n")
        summary_lines.append(f"Файл: {os.path.basename(self.current_file)}")
        if isinstance(display_score, (int, float)):
            if isinstance(base_score, (int, float)) and display_score != base_score:
                summary_lines.append(f"Оценка угрозы: {display_score:.1f}/100 (базовая {base_score:.1f}, уровень {level})")
            else:
                summary_lines.append(f"Оценка угрозы: {display_score:.1f}/100 (уровень {level})")
        else:
            summary_lines.append(f"Оценка угрозы: {threat_score}/100")
        summary_lines.append(f"Тип: {malware_type}")
        summary_lines.append(f"Вердикт AI: {ai_verdict}\n")
        if isinstance(ml_probability, (int, float)):
            summary_lines.append(f"ML-вероятность: {ml_probability:.3f}")
        else:
            summary_lines.append("ML-вероятность: недоступна")
        summary_lines.append(f"Статус ML: {self.lbl_ml_status.text().replace('Статус ML: ', '')}")
        if plane:
            summary_lines.append(
                f"Поведенческий квадрант: {plane.get('quadrant', '-')} | {plane.get('quadrant_label', 'Неизвестно')}"
            )
        if cluster_match and cluster_match.get("label") is not None:
            summary_lines.append(
                f"Ближайший кластер: #{cluster_match.get('label')} | сходство={cluster_match.get('similarity', 0):.3f}"
            )
        if nearest_neighbors:
            summary_lines.append(
                "Ближайшие соседи: "
                + ", ".join(
                    f"{item.get('id')} ({item.get('manhattan_distance', 0):.3f})"
                    for item in nearest_neighbors[:3]
                    if isinstance(item, dict)
                )
            )
        if family_match and family_match.get("family") is not None:
            summary_lines.append(
                f"Наиболее вероятное семейство: {family_match.get('family')} | сходство={family_match.get('similarity', 0):.3f}"
            )

        dynamic = results.get('dynamic')

        if 'static' in results:
            static = results['static']
            yara_status = static.get("yara_status") or {}
            if yara_status:
                summary_lines.append(f"Статус YARA: {yara_status.get('status', 'unknown')}")
            if 'yara_matches' in static and static['yara_matches']:
                summary_lines.append(f"\nСовпадения YARA: {len(static['yara_matches'])}")
            if 'suspicious_imports' in static:
                summary_lines.append(f"Подозрительные импорты: {len(static.get('suspicious_imports', []))}")

        sandbox_summary_line = "Обход песочницы: не выполнялся"
        if isinstance(dynamic, dict):
            sandbox = dynamic.get("sandbox_evasion")
            if isinstance(sandbox, dict):
                summary = sandbox.get("summary")
                score = sandbox.get("score")
                parts = []
                if summary:
                    parts.append(summary)
                if isinstance(score, (int, float)):
                    parts.append(f"score={score}")
                sandbox_summary_line = "Обход песочницы: " + (" | ".join(parts) if parts else "нет данных")
            else:
                sandbox_summary_line = "Обход песочницы: нет данных"
            if 'api_calls' in dynamic:
                summary_lines.append(f"\nВызовов API: {len(dynamic['api_calls'])}")
            if 'network' in dynamic:
                summary_lines.append(f"Сетевых соединений: {len(dynamic['network'])}")
            if 'file_operations' in dynamic:
                summary_lines.append(f"Операций с файлами: {len(dynamic['file_operations'])}")
        summary_lines.append(sandbox_summary_line)
        ti_summary = results.get("ti_enrichment", {}).get("summary", {}) if isinstance(results.get("ti_enrichment"), dict) else {}
        if ti_summary:
            summary_lines.append(
                "Threat intel: "
                f"malicious={ti_summary.get('malicious', 0)}, "
                f"suspicious={ti_summary.get('suspicious', 0)}, "
                f"unknown={ti_summary.get('unknown', 0)}"
            )
        retro_summary = results.get("retro_hunt", {}) if isinstance(results.get("retro_hunt"), dict) else {}
        if retro_summary:
            summary_lines.append(
                f"Ретрохант: статус={retro_summary.get('status', 'n/a')}, "
                f"совпадения={retro_summary.get('total_hits', 0)}, "
                f"усиление={retro_summary.get('confidence_boost', 0)}"
            )

        if hasattr(self, "lbl_sandbox_evasion"):
            self.lbl_sandbox_evasion.setText(sandbox_summary_line)

        self.txt_summary.setPlainText("\n".join(summary_lines))
        if hasattr(self, "text_report_preview"):
            self.text_report_preview.setPlainText("\n".join(summary_lines))
        if hasattr(self, "btn_save_report"):
            self.btn_save_report.setEnabled(bool(self.analysis_results))

        # Static analysis
        if 'static' in results:
            self.display_static_results(results['static'], results.get('heuristic'))

        # Dynamic analysis
        if isinstance(dynamic, dict):
            self.display_dynamic_results(dynamic)

        self.refresh_subsystem_status()

    def display_static_results(self, results, heuristics: Optional[Dict[str, Any]] = None):
        """Display static analysis results"""
        output = "=== Результаты статического анализа ===\n\n"

        filepath = results.get("filepath")
        if filepath:
            output += f"Файл: {filepath}\n"

        if "file_type" in results:
            output += f"Тип файла: {results['file_type']}\n"

        hashes = results.get("hashes")
        if isinstance(hashes, dict) and hashes:
            output += "\nХеши:\n"
            for algo, digest in hashes.items():
                output += f"  {algo.upper()}: {digest}\n"

        analysis = results.get("analysis")
        if isinstance(analysis, dict) and analysis:
            output += "\nДетали анализа:\n"
            output += json.dumps(analysis, ensure_ascii=False, indent=2)
            output += "\n"

        yara_matches = results.get("yara_matches") or []
        yara_status = results.get("yara_status") or {}
        if yara_status:
            output += "\nСтатус YARA:\n"
            output += json.dumps(yara_status, ensure_ascii=False, indent=2)
            output += "\n"
        if yara_matches:
            output += "\nСовпадения YARA:\n"
            for match in yara_matches:
                output += f"  - {match.get('rule')} (пространство имён: {match.get('namespace')})\n"

        self.txt_static_results.setPlainText(output)

        # Heuristic results
        heur = heuristics or self.analysis_results.get('heuristic') or {}
        if heur:
            entropy = heur.get('entropy')
            packer = heur.get('packer', 'Нет')
            risk = heur.get('risk_score', 0)
            entropy_text = f"{entropy:.2f}" if isinstance(entropy, (int, float)) else "-"
            self.lbl_entropy.setText(f"Энтропия: {entropy_text}")
            self.lbl_packer.setText(f"Упаковщик: {packer or 'Нет'}")
            self.lbl_heur_score.setText(f"Оценка риска: {risk}/100")
        else:
            self.lbl_entropy.setText("Энтропия: -")
            self.lbl_packer.setText("Упаковщик: -")
            self.lbl_heur_score.setText("Оценка риска: -")

    def display_dynamic_results(self, results):
        """Display dynamic analysis results"""
        api_calls = results.get('api_calls') or []
        max_api_rows = 200
        self.table_api_calls.setRowCount(0)
        for call in api_calls[:max_api_rows]:
            row = self.table_api_calls.rowCount()
            self.table_api_calls.insertRow(row)

            timestamp = call.get('timestamp')
            if isinstance(timestamp, (int, float)):
                if timestamp > 10**10:
                    timestamp = timestamp / 1000.0
                time_str = datetime.fromtimestamp(timestamp).isoformat()
            else:
                time_str = str(timestamp or "")

            api_name = call.get('api') or call.get('function') or call.get('name') or ""
            pid = call.get('pid') or call.get('process_id') or ""
            arguments = call.get('args') or call.get('arguments') or ""
            if isinstance(arguments, (dict, list)):
                arguments = json.dumps(arguments, ensure_ascii=False)

            self.table_api_calls.setItem(row, 0, QTableWidgetItem(time_str))
            self.table_api_calls.setItem(row, 1, QTableWidgetItem(str(api_name)))
            self.table_api_calls.setItem(row, 2, QTableWidgetItem(str(pid)))
            self.table_api_calls.setItem(row, 3, QTableWidgetItem(str(arguments)))

        file_entries = results.get('file_operations') or results.get('files') or []
        max_file_rows = 200
        self.table_files.setRowCount(0)
        for op in file_entries[:max_file_rows]:
            if not isinstance(op, dict):
                continue
            row = self.table_files.rowCount()
            self.table_files.insertRow(row)
            timestamp = op.get('timestamp')
            if isinstance(timestamp, (int, float)):
                if timestamp > 10**10:
                    timestamp = timestamp / 1000.0
                time_str = datetime.fromtimestamp(timestamp).isoformat()
            else:
                time_str = str(timestamp or "")
            self.table_files.setItem(row, 0, QTableWidgetItem(time_str))
            self.table_files.setItem(row, 1, QTableWidgetItem(str(op.get('operation') or op.get('action') or "")))
            self.table_files.setItem(row, 2, QTableWidgetItem(str(op.get('path') or op.get('file') or "")))

        registry_entries = results.get('registry') or results.get('registry_operations') or []
        max_registry_rows = 200
        self.table_registry.setRowCount(0)
        for entry in registry_entries[:max_registry_rows]:
            if not isinstance(entry, dict):
                continue
            row = self.table_registry.rowCount()
            self.table_registry.insertRow(row)
            timestamp = entry.get('timestamp')
            if isinstance(timestamp, (int, float)):
                if timestamp > 10**10:
                    timestamp = timestamp / 1000.0
                time_str = datetime.fromtimestamp(timestamp).isoformat()
            else:
                time_str = str(timestamp or "")
            self.table_registry.setItem(row, 0, QTableWidgetItem(time_str))
            self.table_registry.setItem(row, 1, QTableWidgetItem(str(entry.get('operation') or entry.get('action') or "")))
            self.table_registry.setItem(row, 2, QTableWidgetItem(str(entry.get('key') or entry.get('path') or "")))

        network_entries = results.get('network') or []
        max_network_rows = 200
        self.table_network.setRowCount(0)
        for conn in network_entries[:max_network_rows]:
            row = self.table_network.rowCount()
            self.table_network.insertRow(row)

            timestamp = conn.get('timestamp')
            if isinstance(timestamp, (int, float)):
                if timestamp > 10**10:
                    timestamp = timestamp / 1000.0
                time_str = datetime.fromtimestamp(timestamp).isoformat()
            else:
                time_str = str(timestamp or "")

            status = conn.get('status') or conn.get('state') or ""
            protocol = conn.get('protocol') or conn.get('transport') or ""

            self.table_network.setItem(row, 0, QTableWidgetItem(time_str))
            self.table_network.setItem(row, 1, QTableWidgetItem(conn.get('remote_ip') or conn.get('host') or ""))
            self.table_network.setItem(row, 2, QTableWidgetItem(str(conn.get('remote_port', ''))))
            self.table_network.setItem(row, 3, QTableWidgetItem(str(protocol)))
            self.table_network.setItem(row, 4, QTableWidgetItem(str(status)))

        timeline_entries = results.get('timeline')
        if hasattr(self, "text_timeline"):
            if isinstance(timeline_entries, list) and timeline_entries:
                timeline_lines = []
                for item in timeline_entries:
                    if isinstance(item, dict):
                        ts = item.get('timestamp')
                        description = item.get('description') or item.get('event') or ''
                        if isinstance(ts, (int, float)):
                            if ts > 10**10:
                                ts = ts / 1000.0
                            ts_str = datetime.fromtimestamp(ts).isoformat()
                        else:
                            ts_str = str(ts or "")
                        timeline_lines.append(f"{ts_str} - {description}")
                    else:
                        timeline_lines.append(str(item))
                self.text_timeline.setPlainText("\n".join(timeline_lines))
            elif isinstance(timeline_entries, list):
                self.text_timeline.clear()

    def refresh_subsystem_status(self):
        status_payload = self.analysis_results.get("system_status") or {}
        if not isinstance(status_payload, dict):
            status_payload = {}
        if self.text_subsystem_status:
            self.text_subsystem_status.setPlainText(json.dumps(status_payload, ensure_ascii=False, indent=2))

        if self.text_fusion_summary:
            fusion_payload = self.analysis_results.get("fusion") or {}
            self.text_fusion_summary.setPlainText(json.dumps(fusion_payload, ensure_ascii=False, indent=2))

        if self.text_retrohunt_summary:
            retro_payload = self.analysis_results.get("retro_hunt") or {}
            self.text_retrohunt_summary.setPlainText(json.dumps(retro_payload, ensure_ascii=False, indent=2))

        if self.lbl_ai_provider_status:
            ai_status = status_payload.get("aitunnel") or {}
            if isinstance(ai_status, dict) and ai_status:
                mode = ai_status.get("mode", "unknown")
                model = ai_status.get("model", "n/a")
                reason = ai_status.get("reason", "")
                suffix = f" | {reason}" if reason else ""
                self.lbl_ai_provider_status.setText(f"AITUNNEL: режим={mode}, модель={model}{suffix}")

        if self.btn_run_retrohunt:
            retro_connectors = status_payload.get("retrohunt") or []
            enabled = any(
                isinstance(item, dict) and item.get("status") not in {"skipped", None}
                for item in retro_connectors
            )
            if not retro_connectors:
                enabled = False
            self.btn_run_retrohunt.setEnabled(enabled and bool(self.analysis_results))

    def run_external_retrohunt(self):
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните основной анализ.")
            return

        try:
            from services.retro_hunt import RetroHuntOrchestrator

            iocs = self.analysis_results.get("iocs") or []
            if not isinstance(iocs, list) or not iocs:
                QMessageBox.warning(self, "Нет IoC", "Для ретроханта нет доступных IoC.")
                return

            result = RetroHuntOrchestrator().run(
                iocs,
                context={"file_path": self.current_file or "", "source": "gui"},
            )
            self.analysis_results["retro_hunt"] = result
            system_status = self.analysis_results.setdefault("system_status", {})
            if isinstance(system_status, dict):
                system_status["retrohunt"] = [
                    {
                        "connector": item.get("connector"),
                        "status": item.get("status"),
                        "hits": len(item.get("hits", []) or []),
                    }
                    for item in result.get("results", []) or []
                    if isinstance(item, dict)
                ]
            self.refresh_subsystem_status()
            self.display_all_results(self.analysis_results)
            self.statusBar().showMessage("Ретрохант завершён")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", f"Ошибка ретроханта: {exc}")
            logger.error("Retro-hunt error: %s", exc)

    def run_ai_analysis(self):
        """Run AI analysis"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните основной анализ.")
            return

        try:
            from analyzer.ai_analyst import analyze_with_ai

            lang_text = self.combo_ai_lang.currentText()
            language = "ru" if "Рус" in lang_text else "en"
            ai_results = analyze_with_ai(self.analysis_results, language=language)

            ai_info = self.analysis_results.setdefault("ai_analysis", {})
            ai_info.update(ai_results)
            ai_info["language"] = language

            description = ai_results.get("description") or ""
            self.txt_ai_description.setPlainText(description)

            malware_type = ai_results.get("malware_type", "Неизвестно")
            threat_level = ai_results.get("threat_level", "Неизвестно")
            confidence = ai_results.get("confidence", 0.0)
            recommendations = ai_results.get("recommendations") or []
            attack_vectors = ai_results.get("attack_vectors") or []

            lines = [
                f"Тип: {malware_type}",
                f"Уровень угрозы: {threat_level}",
                f"Достоверность: {confidence:.2f}",
            ]
            if recommendations:
                lines.append("\nРекомендации:")
                lines.extend(f"- {item}" for item in recommendations)
            if attack_vectors:
                lines.append("\nВекторы атаки:")
                lines.extend(f"- {item}" for item in attack_vectors)
            self.txt_ai_classification.setPlainText("\n".join(lines))

            yara_rule = ai_results.get("yara_rule")
            if yara_rule:
                self.txt_yara_rule.setPlainText(yara_rule)
                self.analysis_results["ai_analysis"]["yara_rule"] = yara_rule
            else:
                self.txt_yara_rule.clear()
                self.analysis_results["ai_analysis"].pop("yara_rule", None)

            ai_score = ai_results.get("confidence")
            if isinstance(ai_score, (int, float)):
                ai_score_pct = int(round(ai_score * 100))
                ai_info["threat_score"] = ai_results.get("threat_score", ai_score_pct)
                current_score = self.analysis_results.get("threat_score")
                if not isinstance(current_score, (int, float)) or current_score <= 0:
                    self.analysis_results["threat_score"] = ai_info["threat_score"]

            provider_status = ai_results.get("provider_status") or {}
            if self.lbl_ai_provider_status:
                mode = provider_status.get("mode", "unknown")
                model = provider_status.get("model", "n/a")
                reason = provider_status.get("reason", "")
                suffix = f" | {reason}" if reason else ""
                self.lbl_ai_provider_status.setText(f"AITUNNEL: режим={mode}, модель={model}{suffix}")

            self.display_all_results(self.analysis_results)
            logger.info("AI-анализ завершён")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка AI-анализа: {str(e)}")
            logger.error(f"AI analysis error: {e}")

    def generate_yara_rule(self):
        """Generate YARA rule from analysis"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните анализ.")
            return

        try:
            from analyzer.ai_analyst import get_ai_analyst

            rule_name = "TI_RULE"
            if self.current_file:
                rule_name = os.path.splitext(os.path.basename(self.current_file))[0] or rule_name

            analyst = get_ai_analyst()
            rule = analyst.generate_yara_rule(self.analysis_results, rule_name)
            self.txt_yara_rule.setPlainText(rule)
            self.analysis_results.setdefault("ai_analysis", {})["yara_rule"] = rule
            logger.info("Правило YARA сгенерировано")

            self.display_all_results(self.analysis_results)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка генерации YARA: {str(e)}")
            logger.error(f"YARA generation error: {e}")

    def generate_attack_graph(self):
        """Generate attack graph"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните анализ.")
            return

        try:
            from analyzer.attack_graph import AttackGraph
            graph = AttackGraph()
            graph.build_from_analysis(self.analysis_results)

            if graph.graph.number_of_nodes() == 0:
                QMessageBox.information(
                    self,
                    "Граф атаки",
                    "Недостаточно данных для построения графа. Сначала выполните полный или динамический анализ.",
                )
                return

            layout_map = {
                "Пружинный": "spring",
                "Круговой": "circular",
                "Камада-Каваи": "kamada_kawai",
                "Оболочка": "shell",
            }
            layout = layout_map.get(self.combo_graph_layout.currentText(), "spring")
            if MATPLOTLIB_AVAILABLE and MatplotlibCanvas:
                figure = self.graph_canvas.figure
                figure.clf()
                ax = figure.add_subplot(111)
                graph.visualize_on_ax(ax=ax, layout=layout)
                self.graph_canvas.draw()
                self.lbl_graph_nodes.setText(f"Узлы: {graph.graph.number_of_nodes()}")
                self.lbl_graph_edges.setText(f"Рёбра: {graph.graph.number_of_edges()}")
            else:
                QMessageBox.warning(self, "Граф атаки", "Matplotlib недоступен, граф не может быть отрисован.")
                return

            logger.info("Граф атаки построен")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка построения графа: {str(e)}")
            logger.error(f"Graph error: {e}")

    def save_graph(self):
        """Save attack graph"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить изображение графа", "", "PNG Files (*.png)")
        if file_path:
            try:
                if MATPLOTLIB_AVAILABLE and MatplotlibCanvas and hasattr(self, 'graph_canvas'):
                    self.graph_canvas.figure.savefig(file_path, dpi=300, bbox_inches='tight')
                    QMessageBox.information(self, "Успешно", f"Граф сохранён: {file_path}")
                    logger.info(f"Graph saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения: {str(e)}")

    def generate_3d_visualization(self):
        """Generate 3D visualization"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните анализ.")
            return

        try:
            from analyzer.visualization_3d import AttackVisualization3D
            viz = AttackVisualization3D()

            # Add events from dynamic analysis
            if 'dynamic' in self.analysis_results:
                dynamic = self.analysis_results['dynamic']

                timeline = dynamic.get('timeline') or []
                if isinstance(timeline, list):
                    viz.build_from_timeline(timeline)

                api_calls = dynamic.get('api_calls') or []
                for index, call in enumerate(api_calls):
                    if not isinstance(call, dict):
                        continue
                    raw_timestamp = call.get('timestamp', index)
                    if isinstance(raw_timestamp, (int, float)) and raw_timestamp > 10**10:
                        timestamp = raw_timestamp / 1000.0
                    else:
                        timestamp = float(raw_timestamp) if isinstance(raw_timestamp, (int, float)) else index

                    source = f"pid:{call.get('pid', 'unknown')}"
                    target = call.get('api', 'api-call')
                    args = call.get('args', {}) if isinstance(call.get('args'), dict) else {}
                    viz.add_event(timestamp, source, target, 'api-call', **args)

            events = getattr(viz, "events", [])
            if USE_PYQTGRAPH and self.gl_view:
                self._render_gl_visualization(events)
            elif MATPLOTLIB_AVAILABLE and MatplotlibCanvas and hasattr(self, 'canvas_3d'):
                figure = self.canvas_3d.figure
                figure.clf()
                ax = figure.add_subplot(111, projection='3d')
                viz.visualize_3d(ax=ax)
                if hasattr(self.canvas_3d, "draw"):
                    self.canvas_3d.draw()
            else:
                QMessageBox.warning(
                    self,
                    "3D недоступна",
                    "Установите pyqtgraph или matplotlib, чтобы включить 3D-визуализацию.",
                )

            logger.info("3D-визуализация построена")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка 3D-визуализации: {str(e)}")
            logger.error(f"3D viz error: {e}")

    def save_3d_visualization(self):
        """Save 3D visualization"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить 3D-визуализацию", "", "PNG Files (*.png)")
        if file_path:
            try:
                if USE_PYQTGRAPH and self.gl_view:
                    image = self.gl_view.readQImage() if hasattr(self.gl_view, "readQImage") else self.gl_view.grabFramebuffer()
                    if image:
                        image.save(file_path)
                        QMessageBox.information(self, "Успешно", f"3D-визуализация сохранена: {file_path}")
                elif MATPLOTLIB_AVAILABLE and MatplotlibCanvas and hasattr(self, 'canvas_3d'):
                    self.canvas_3d.figure.savefig(file_path, dpi=300, bbox_inches='tight')
                    QMessageBox.information(self, "Успешно", f"3D-визуализация сохранена: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения: {str(e)}")

    def _hex_to_rgba(self, value: str, alpha: float = 1.0) -> Tuple[float, float, float, float]:
        value = value.lstrip("#")
        if len(value) == 3:
            value = "".join(ch * 2 for ch in value)
        r = int(value[0:2], 16) / 255.0
        g = int(value[2:4], 16) / 255.0
        b = int(value[4:6], 16) / 255.0
        return (r, g, b, alpha)

    def _clear_gl_visualization(self):
        if not USE_PYQTGRAPH or not self.gl_view:
            return
        for item in self._gl_items:
            try:
                self.gl_view.removeItem(item)
            except Exception:
                pass
        self._gl_items.clear()

    def _render_gl_visualization(self, events: List[Dict[str, Any]]):
        if not USE_PYQTGRAPH or not self.gl_view:
            return
        self._clear_gl_visualization()
        if not events:
            QMessageBox.information(self, "3D-визуализация", "Нет динамических событий для отображения.")
            return

        nodes = sorted({event.get("source") for event in events} | {event.get("target") for event in events})
        node_positions: Dict[str, Tuple[float, float]] = {}
        count = max(len(nodes), 1)
        for idx, node in enumerate(nodes):
            angle = 2 * np.pi * idx / count
            radius = 8
            node_positions[node] = (float(np.cos(angle) * radius), float(np.sin(angle) * radius))

        timestamps = [event.get("timestamp", idx) for idx, event in enumerate(events)]
        min_time = min(timestamps)
        max_time = max(timestamps)
        time_range = max(max_time - min_time, 1.0)

        operation_colors = {
            "create": "#2ECC71",
            "read": "#3498DB",
            "write": "#E74C3C",
            "delete": "#E67E22",
            "execute": "#9B59B6",
            "connect": "#1ABC9C",
            "inject": "#C0392B",
            "api-call": "#F1C40F",
        }

        for event in events:
            source = event.get("source")
            target = event.get("target")
            if not source or not target:
                continue
            x1, y1 = node_positions.get(source, (0.0, 0.0))
            x2, y2 = node_positions.get(target, (0.0, 0.0))
            timestamp = event.get("timestamp", min_time)
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp).timestamp()
                except Exception:
                    timestamp = min_time
            z = ((float(timestamp) - min_time) / time_range) * 20.0
            color = self._hex_to_rgba(operation_colors.get(event.get("operation", ""), "#CCCCCC"), 0.9)

            line_pos = np.array([[x1, y1, z], [x2, y2, z]], dtype=float)
            line = gl.GLLinePlotItem(pos=line_pos, color=color, width=2, antialias=True)
            self.gl_view.addItem(line)
            self._gl_items.append(line)

        node_positions_arr = []
        for node in nodes:
            x, y = node_positions.get(node, (0.0, 0.0))
            z_events = [
                event.get("timestamp", min_time)
                for event in events
                if event.get("source") == node or event.get("target") == node
            ]
            if z_events:
                z = ((float(z_events[0]) - min_time) / time_range) * 20.0
            else:
                z = 0.0
            node_positions_arr.append([x, y, z])

        node_array = np.array(node_positions_arr, dtype=float)
        node_colors = np.tile(np.array([[1.0, 0.35, 0.4, 1.0]]), (len(node_positions_arr), 1))
        scatter = gl.GLScatterPlotItem(pos=node_array, color=node_colors, size=12, pxMode=True)
        self.gl_view.addItem(scatter)
        self._gl_items.append(scatter)

        self.gl_view.opts["distance"] = 35

    def closeEvent(self, event):
        try:
            if self.monitor_service:
                self.monitor_service.stop()
        except Exception:
            logger.exception("Error stopping monitor during shutdown.")
        super().closeEvent(event)

    def _detect_ioc_type(self, value: str) -> Optional[str]:
        """Return a lightweight IoC type hint based on the supplied value."""
        value = (value or "").strip()
        if not value:
            return None
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        lowered = value.lower()
        if lowered.startswith(("http://", "https://")):
            return "url"
        if re.fullmatch(r"[a-f0-9]{64}", lowered):
            return "sha256"
        if re.fullmatch(r"[a-f0-9]{40}", lowered):
            return "sha1"
        if re.fullmatch(r"[a-f0-9]{32}", lowered):
            return "md5"
        domain_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z0-9.-]{2,}$")
        if domain_pattern.match(value):
            return "domain"
        return None

    def check_threat_intel(self):
        """Check threat intelligence"""
        if self.threat_worker and self.threat_worker.isRunning():
            QMessageBox.information(self, "В процессе", "Запрос threat intelligence уже выполняется.")
            return

        ioc = self.input_ioc.text().strip()
        if not ioc:
            QMessageBox.warning(self, "Ошибка", "Введите индикатор для проверки.")
            return

        ioc_type = self._detect_ioc_type(ioc)
        if not ioc_type:
            QMessageBox.warning(
                self,
                "Некорректный IoC",
                "Укажите корректный IP-адрес, домен, URL или значение хеша.",
            )
            return

        self.text_vt_result.clear()
        self.text_abuseipdb_result.clear()
        self.text_otx_result.clear()
        self.text_urlhaus_result.clear()

        query_type = ioc_type
        query_value = ioc
        if ioc_type in {"sha1", "sha256", "md5"}:
            query_type = "hash"
        elif ioc_type == "domain":
            query_type = "domain"
            query_value = urlparse(ioc).netloc or ioc

        self._ti_context = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "query_type": query_type,
            "query_value": query_value,
        }

        self.btn_check_intel.setEnabled(False)
        self.statusBar().showMessage(f"Выполняется запрос threat intelligence для {ioc}...")

        self.threat_worker = ThreatIntelWorker(query_value, query_type)
        self.threat_worker.finished.connect(self._threat_intel_finished)
        self.threat_worker.error.connect(self._threat_intel_error)
        self.threat_worker.start()
        logger.info("Threat intel query started for %s (%s)", ioc, query_type)

    def _threat_intel_finished(self, results: Dict[str, Any]):
        """Handle successful threat intel responses."""
        try:
            context = self._ti_context or {}
            ioc = context.get("ioc", "")
            ioc_type = context.get("ioc_type", "")
            if not isinstance(results, dict):
                QMessageBox.warning(self, "Ошибка", "Получен неожиданный ответ threat intelligence.")
                return
            if results.get("error"):
                QMessageBox.warning(self, "Ошибка", results.get("error", "Ошибка проверки threat intelligence"))
                return

            indent_kwargs = {"indent": 2, "ensure_ascii": False}

            def _set(widget: QTextEdit, data: Any):
                if widget:
                    widget.setPlainText(json.dumps(data, **indent_kwargs))

            if ioc_type == "ip":
                _set(self.text_abuseipdb_result, results.get("abuseipdb", {}))
                _set(self.text_vt_result, results.get("virustotal", {}))
                _set(self.text_otx_result, results.get("otx", {}))
                _set(self.text_urlhaus_result, results.get("threatfox", {}))
            elif ioc_type in {"url", "domain"}:
                _set(self.text_vt_result, results.get("virustotal", {}))
                _set(self.text_otx_result, results.get("otx", {}))
                _set(self.text_urlhaus_result, results.get("urlhaus", {}))
            else:  # hash and others
                _set(self.text_vt_result, results.get("virustotal", {}))
                _set(self.text_otx_result, results.get("malwarebazaar", {}))
                _set(self.text_urlhaus_result, results.get("threatfox", {}))

            self.statusBar().showMessage(f"Проверка threat intelligence завершена для {ioc}")
            logger.info("Threat intel check complete for %s", ioc)
        finally:
            self.btn_check_intel.setEnabled(True)
            self.threat_worker = None
            self._ti_context = None

    def _threat_intel_error(self, message: str):
        """Handle threat intelligence lookup errors."""
        QMessageBox.critical(self, "Ошибка", f"Ошибка threat intelligence: {message}")
        logger.error("Threat intel error: %s", message)
        self.btn_check_intel.setEnabled(True)
        self.threat_worker = None
        self._ti_context = None
        self.statusBar().showMessage("Запрос threat intelligence завершился ошибкой")

    def map_mitre_techniques(self):
        """Map MITRE ATT&CK techniques"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните анализ.")
            return

        try:
            from analyzer.mitre_attack import map_to_mitre

            mitre_results = self.analysis_results.get("mitre")
            if not isinstance(mitre_results, dict):
                mitre_results = map_to_mitre(self.analysis_results)
                self.analysis_results["mitre"] = mitre_results
            techniques = mitre_results.get('techniques', [])

            self.table_mitre.setRowCount(0)
            for tech in techniques:
                row = self.table_mitre.rowCount()
                self.table_mitre.insertRow(row)
                self.table_mitre.setItem(row, 0, QTableWidgetItem(tech.get('id', '')))
                self.table_mitre.setItem(row, 1, QTableWidgetItem(tech.get('name', '')))
                self.table_mitre.setItem(row, 2, QTableWidgetItem(tech.get('tactic', '')))
                self.table_mitre.setItem(row, 3, QTableWidgetItem(f"{tech.get('confidence', 0):.2f}"))

            self.lbl_mitre_summary.setText(f"Обнаружено техник: {len(techniques)}")
            if self.text_d3fend_summary:
                d3fend_data = self.analysis_results.get("d3fend") or {}
                self.text_d3fend_summary.setPlainText(json.dumps(d3fend_data, ensure_ascii=False, indent=2))
            logger.info(f"MITRE mapping complete: {len(techniques)} techniques")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сопоставления MITRE: {str(e)}")
            logger.error(f"MITRE error: {e}")

    def export_attack_navigator(self):
        """Export ATT&CK Navigator JSON"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Экспортировать Navigator", "", "JSON Files (*.json)")
        if file_path:
            try:
                from analyzer.mitre_attack import export_navigator_json
                export_navigator_json(self.analysis_results, file_path)
                QMessageBox.information(self, "Успешно", f"Navigator JSON сохранён: {file_path}")
                logger.info(f"Navigator JSON exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка экспорта: {str(e)}")

    def analyze_network(self):
        """Analyze network traffic"""
        if not self.analysis_results or 'dynamic' not in self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Сначала выполните динамический анализ.")
            return

        try:
            from analyzer.network_analysis import analyze_network_traffic
            dynamic_data = self.analysis_results['dynamic']
            network_data = dynamic_data.get('network', []) or []
            dns_data = dynamic_data.get('dns') or []
            http_data = dynamic_data.get('http') or []
            results = analyze_network_traffic(network_data, dns_data, http_data)

            connections = results.get('connections', {})
            suspicious_pairs = set()
            for item in connections.get('suspicious_ports', []):
                suspicious_pairs.add((item.get('ip'), item.get('port')))

            # Display connections
            self.table_connections.setRowCount(0)
            if network_data:
                for conn in network_data:
                    row = self.table_connections.rowCount()
                    self.table_connections.insertRow(row)
                    remote_ip = conn.get('remote_ip') or conn.get('host') or ""
                    remote_port = conn.get('remote_port') or conn.get('port') or ""
                    protocol = conn.get('protocol') or conn.get('transport') or ""
                    status = conn.get('status') or conn.get('state') or ""
                    if (remote_ip, remote_port) in suspicious_pairs:
                        status = (status + " | подозрительный порт").strip(" |")
                    self.table_connections.setItem(row, 0, QTableWidgetItem(str(remote_ip)))
                    self.table_connections.setItem(row, 1, QTableWidgetItem(str(remote_port)))
                    self.table_connections.setItem(row, 2, QTableWidgetItem(str(protocol)))
                    self.table_connections.setItem(row, 3, QTableWidgetItem(str(status)))
            else:
                for ip in connections.get('unique_ips', []):
                    row = self.table_connections.rowCount()
                    self.table_connections.insertRow(row)
                    self.table_connections.setItem(row, 0, QTableWidgetItem(ip))
                    self.table_connections.setItem(row, 1, QTableWidgetItem(""))
                    self.table_connections.setItem(row, 2, QTableWidgetItem(""))
                    self.table_connections.setItem(row, 3, QTableWidgetItem(""))

            # Display beaconing
            beacons = connections.get('beaconing_detected', [])
            self.table_beaconing.setRowCount(0)
            for beacon in beacons:
                row = self.table_beaconing.rowCount()
                self.table_beaconing.insertRow(row)
                self.table_beaconing.setItem(row, 0, QTableWidgetItem(beacon.get('ip', '')))
                self.table_beaconing.setItem(row, 1, QTableWidgetItem(str(beacon.get('connection_count', 0))))
                self.table_beaconing.setItem(row, 2, QTableWidgetItem(str(beacon.get('avg_interval_seconds', 0))))
                self.table_beaconing.setItem(row, 3, QTableWidgetItem(str(beacon.get('regularity_score', 0))))

            # DNS overview
            dns_results = results.get('dns') or {}
            flagged_dns = {entry.get('domain'): entry for entry in dns_results.get('dns_tunneling_detected', [])}
            dga_candidates = set(dns_results.get('dga_candidates', []))
            self.table_dns.setRowCount(0)
            for query in dns_data:
                if not isinstance(query, dict):
                    continue
                domain = query.get('domain', '')
                suspicion_parts: List[str] = []
                flagged = flagged_dns.get(domain)
                if flagged:
                    suspicion_parts.append(flagged.get('reason', 'Подозрительно'))
                if domain in dga_candidates:
                    suspicion_parts.append("Кандидат на DGA")
                row = self.table_dns.rowCount()
                self.table_dns.insertRow(row)
                self.table_dns.setItem(row, 0, QTableWidgetItem(domain))
                self.table_dns.setItem(row, 1, QTableWidgetItem(str(query.get('type', ''))))
                self.table_dns.setItem(row, 2, QTableWidgetItem(" | ".join(suspicion_parts)))
            # Add any remaining flagged domains not seen in dns_data
            for domain, info in flagged_dns.items():
                if any(self.table_dns.item(row, 0).text() == domain for row in range(self.table_dns.rowCount())):
                    continue
                row = self.table_dns.rowCount()
                self.table_dns.insertRow(row)
                self.table_dns.setItem(row, 0, QTableWidgetItem(domain))
                self.table_dns.setItem(row, 1, QTableWidgetItem(info.get('query_type', '')))
                self.table_dns.setItem(row, 2, QTableWidgetItem(info.get('reason', 'Подозрительно')))

            # HTTP summary
            http_results = results.get('http') or {}
            http_lines: List[str] = []
            total_requests = http_results.get('total_requests')
            if total_requests is not None:
                http_lines.append(f"Всего запросов: {total_requests}")
            methods = http_results.get('methods') or {}
            if methods:
                method_parts = [f"{method}: {count}" for method, count in methods.items()]
                http_lines.append("Методы: " + ", ".join(method_parts))
            user_agents = http_results.get('user_agents') or {}
            if user_agents:
                ua_parts = [f"{ua or 'N/A'}: {count}" for ua, count in user_agents.items() if count]
                if ua_parts:
                    http_lines.append("User-Agent'ы: " + ", ".join(ua_parts))
            suspicious_headers = http_results.get('suspicious_headers') or []
            for header in suspicious_headers:
                http_lines.append(
                    f"Подозрительный заголовок [{header.get('type', '')}]: {header.get('value', '')} (url={header.get('url', '')})"
                )
            data_exfil = http_results.get('data_exfiltration') or []
            for exfil in data_exfil:
                http_lines.append(
                    f"Возможная эксфильтрация данных: {exfil.get('url', '')} (~{exfil.get('size_kb', 0)} KB, время {exfil.get('timestamp', '')})"
                )
            if hasattr(self, "text_http_analysis"):
                if http_lines:
                    self.text_http_analysis.setPlainText("\n".join(http_lines))
                else:
                    self.text_http_analysis.setPlainText("Аномалии HTTP/HTTPS не обнаружены.")

            self.statusBar().showMessage("Сетевой анализ завершён")
            logger.info("Сетевой анализ завершён")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сетевого анализа: {str(e)}")
            logger.error(f"Network analysis error: {e}")

    def collect_forensic_artifacts(self):
        """Collect forensic artifacts"""
        try:
            from analyzer.forensics import collect_forensic_artifacts
            artifacts = collect_forensic_artifacts()

            # Display prefetch
            self.table_prefetch.setRowCount(0)
            for pf in artifacts.get('prefetch', [])[:20]:
                row = self.table_prefetch.rowCount()
                self.table_prefetch.insertRow(row)
                self.table_prefetch.setItem(row, 0, QTableWidgetItem(pf.get('name', '')))
                self.table_prefetch.setItem(row, 1, QTableWidgetItem(pf.get('path', '')))
                self.table_prefetch.setItem(row, 2, QTableWidgetItem(pf.get('modified', '')))

            # Display startup items
            self.table_startup.setRowCount(0)
            for item in artifacts.get('startup_items', []):
                row = self.table_startup.rowCount()
                self.table_startup.insertRow(row)
                self.table_startup.setItem(row, 0, QTableWidgetItem(item.get('hive', '')))
                self.table_startup.setItem(row, 1, QTableWidgetItem(item.get('key', '')))
                self.table_startup.setItem(row, 2, QTableWidgetItem(item.get('name', '')))
                self.table_startup.setItem(row, 3, QTableWidgetItem(str(item.get('value', ''))))

            if hasattr(self, "text_timeline"):
                timeline_entries = artifacts.get('timeline') or []
                if timeline_entries:
                    lines = []
                    for entry in timeline_entries:
                        if isinstance(entry, dict):
                            ts = entry.get('timestamp') or entry.get('time')
                            description = entry.get('description') or entry.get('event') or ''
                            lines.append(f"{ts}: {description}")
                        else:
                            lines.append(str(entry))
                    self.text_timeline.setPlainText("\n".join(lines))
                else:
                    self.text_timeline.setPlainText("Артефакты таймлайна не собраны.")

            logger.info("Форензические артефакты собраны")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка форензики: {str(e)}")
            logger.error(f"Forensics error: {e}")

    def detect_persistence(self):
        """Detect persistence mechanisms"""
        try:
            from analyzer.forensics import collect_forensic_artifacts
            artifacts = collect_forensic_artifacts()

            self.table_persistence.setRowCount(0)
            for mech in artifacts.get('persistence_mechanisms', []):
                row = self.table_persistence.rowCount()
                self.table_persistence.insertRow(row)
                self.table_persistence.setItem(row, 0, QTableWidgetItem(mech.get('location', '')))
                self.table_persistence.setItem(row, 1, QTableWidgetItem(mech.get('file', '')))
                self.table_persistence.setItem(row, 2, QTableWidgetItem(mech.get('path', '')))
                self.table_persistence.setItem(row, 3, QTableWidgetItem(mech.get('modified', '')))

            logger.info("Поиск персистентности завершён")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка поиска персистентности: {str(e)}")

    def generate_pdf_report(self):
        """Generate PDF report"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Нет данных для формирования отчёта.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить PDF-отчёт", "", "PDF Files (*.pdf)")
        if file_path:
            try:
                from core.reporting import generate_pdf_report
                generate_pdf_report(self.analysis_results, file_path)
                QMessageBox.information(self, "Успешно", f"PDF-отчёт создан: {file_path}")
                logger.info(f"PDF report generated: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка генерации PDF: {str(e)}")

    def export_json_report(self):
        """Export JSON report"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Нет данных для экспорта.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Экспортировать JSON-отчёт", "", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.analysis_results, f, indent=2, ensure_ascii=False)
                QMessageBox.information(self, "Успешно", f"JSON экспортирован: {file_path}")
                logger.info(f"JSON exported: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка экспорта: {str(e)}")

    def generate_html_report(self):
        """Generate HTML report"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Ошибка", "Нет данных для формирования отчёта.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить HTML-отчёт", "", "HTML Files (*.html)")
        if file_path:
            try:
                from core.reporting import generate_html_report
                generate_html_report(self.analysis_results, file_path)
                QMessageBox.information(self, "Успешно", f"HTML-отчёт создан: {file_path}")
                logger.info(f"HTML report generated: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка генерации HTML: {str(e)}")


def run_modern_gui():
    """Run the modern GUI application.

    Returns the Qt application exit code as an int. This allows callers
    to decide how to handle fallback or termination without relying on
    SystemExit side effects.
    """
    try:
        if os.environ.get("THREATINQ_VERBOSE_LAUNCH", "1").lower() not in {"0", "false", "no", "off"}:
            print("[modern_gui] Initialising QApplication...")
    except Exception:
        pass
    app = QApplication(sys.argv)
    try:
        if os.environ.get("THREATINQ_VERBOSE_LAUNCH", "1").lower() not in {"0", "false", "no", "off"}:
            print("[modern_gui] QApplication created.")
    except Exception:
        pass
    app.setStyle("Fusion")

    # Ensure matplotlib backend is ready before constructing UI
    ensure_mpl_ready()
    if not MATPLOTLIB_AVAILABLE:
        logging.getLogger("modern_gui").warning(
            "Matplotlib initialisation failed; graph/3D tabs may be limited."
        )
    if os.environ.get("THREATINQ_VERBOSE_LAUNCH", "1").lower() not in {"0", "false", "no", "off"}:
        print("[modern_gui] Creating main window...")
    window = ModernThreatInquisitorGUI()
    if os.environ.get("THREATINQ_VERBOSE_LAUNCH", "1").lower() not in {"0", "false", "no", "off"}:
        print("[modern_gui] Showing window...")
    window.show()

    code = app.exec_()
    try:
        if os.environ.get("THREATINQ_VERBOSE_LAUNCH", "1").lower() not in {"0", "false", "no", "off"}:
            print(f"[modern_gui] Qt event loop exited with code {code}")
    except Exception:
        pass
    return code


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(run_modern_gui())
