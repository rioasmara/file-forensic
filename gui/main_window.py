"""
Main application window for MFT Reader - forensic $MFT analysis.
"""

import json
import fnmatch
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTableView,
    QTextEdit,
    QTextBrowser,
    QHeaderView,
    QFileDialog,
    QPushButton,
    QLabel,
    QLineEdit,
    QComboBox,
    QProgressBar,
    QProgressDialog,
    QMessageBox,
    QAbstractItemView,
    QMenu,
    QApplication,
    QStatusBar,
    QTabWidget,
    QDialog,
    QFrame,
    QScrollArea,
    QSpinBox,
    QCheckBox,
    QStyle,
    QTreeWidget,
    QTreeWidgetItem,
    QGroupBox,
    QStyledItemDelegate,
    QStyleOptionViewItem,
)
from PySide6.QtCore import Qt, QThread, Signal, QSize, QTimer, QAbstractTableModel, QModelIndex, QObject, QEvent, QMimeData, QByteArray, QRect
from PySide6.QtGui import QAction, QColor, QDrag, QIntValidator, QPainter, QPen

RECORD_INDEX_ROLE = Qt.ItemDataRole.UserRole
EXEC_SWAP_ROLE = Qt.ItemDataRole.UserRole + 1

INITIAL_USN_ROWS = 2000
LOAD_MORE_USN_BATCH = 2000

_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".msi"
}

_SUSPICIOUS_PATH_MARKERS = (
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\$recycle.bin\\",
    "\\recycler\\",
    "\\programdata\\",
    "\\windows\\tasks\\",
    "\\windows\\system32\\tasks\\",
    "\\startup\\",
    "\\perflogs\\",
)

_ROW_RISK_COLORS = {
    "critical": ((0x63, 0x1F, 0x2E), (0xFF, 0xE1, 0xE7)),
    "high": ((0x5A, 0x3D, 0x1F), (0xFF, 0xEA, 0xCB)),
    "medium": ((0x2D, 0x3F, 0x55), (0xD8, 0xE9, 0xFF)),
}

# Extension change: exec ↔ any (executable to/from non-executable) — highlight + thick box
_EXEC_SWAP_HIGHLIGHT = ((0x3D, 0x2B, 0x2B), (0xFF, 0xD4, 0xD4))  # dark red tint, light red text
_EXEC_SWAP_BORDER_COLOR = (0xE6, 0x39, 0x46)
_EXEC_SWAP_BORDER_WIDTH = 3

# FILETIME: 100-nanosecond units
_FILETIME_TICKS_PER_SECOND = 10_000_000

# Lockheed Martin Cyber Kill Chain (7 phases)
KILL_CHAIN_PHASES = (
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
)


from ..mft_parser import (
    iter_mft_records,
    MFTRecord,
    build_path_table,
    build_fs_tree,
    FsTreeData,
    parent_path_for_record,
    parent_path_for_usn_record,
    detect_timestomping_anomaly,
    build_sequence_gap_report,
    build_extension_change_report,
    build_abnormal_sequence_pipeline,
    AttackChain,
    SequenceFinding,
    build_directory_churn_report,
    DirectoryChurnEntry,
    filename_entropy_report,
    extension_entropy_per_directory,
    ExtensionEntropyPerDir,
    is_high_sequence,
    SequenceGapEntry,
    ExtensionChangeEntry,
    DEFAULT_SEQUENCE_GAP_THRESHOLD,
    UsnRecord,
    load_usn_records,
    usn_close_events_by_mft,
    USN_REASON_CLOSE,
    USN_REASON_NAMES,
    USN_REASON_FILE_CREATE,
    USN_REASON_FILE_DELETE,
    USN_REASON_RENAME_OLD_NAME,
    USN_REASON_RENAME_NEW_NAME,
    USN_REASON_DATA_OVERWRITE,
    USN_REASON_DATA_EXTEND,
    USN_REASON_BASIC_INFO_CHANGE,
    iso_to_win_timestamp,
    _win_timestamp_to_iso,
)
def _modified_minus_created_tooltip(rec: MFTRecord) -> str:
    """Format (modified - created) in different units: ms | seconds | minutes | hours | days."""
    created = 0
    modified = 0
    if rec.standard_info:
        created = rec.standard_info.created
        modified = rec.standard_info.modified
    else:
        fn = rec.primary_file_name()
        if fn:
            created = fn.created
            modified = fn.modified
    delta_ticks = modified - created
    if delta_ticks == 0:
        return "0 ms | 0 seconds | 0 minutes  (same as creation)"
    total_seconds = abs(delta_ticks) / _FILETIME_TICKS_PER_SECOND
    sign = "-" if delta_ticks < 0 else ""
    total_ms = int(round(total_seconds * 1000))
    total_sec = total_seconds
    total_min = total_seconds / 60
    total_hr = total_seconds / 3600
    total_d = total_seconds / 86400

    def _fmt(v: float, one: str, many: str) -> str:
        if v == int(v):
            return f"{sign}{int(v)} {one}" if v == 1 else f"{sign}{int(v)} {many}"
        return f"{sign}{v:.3f} {one}" if v == 1 else f"{sign}{v:.3f} {many}"

    parts = [f"{sign}{total_ms:,} ms"]
    parts.append(_fmt(total_sec, "second", "seconds"))
    parts.append(_fmt(total_min, "minute", "minutes"))
    if total_hr >= 0.001:
        parts.append(_fmt(total_hr, "hour", "hours"))
    if total_d >= 0.001:
        parts.append(_fmt(total_d, "day", "days"))
    return " | ".join(parts)


from .compound_filter import (
    MFT_COLUMNS,
    USN_COLUMNS,
    FilterCriterion,
    criterion_matches,
    make_header_draggable,
    CompoundFilterPanel,
    CollapsibleStatsFilter,
    ANOMALY_SEQ_COLUMNS,
    EXT_CHANGE_COLUMNS,
    FILENAME_ENTROPY_COLUMNS,
    EXT_ENTROPY_COLUMNS,
    CHURN_COLUMNS,
    SURVIVAL_COLUMNS,
    TEMPORAL_BURST_POISSON_COLUMNS,
    TEMPORAL_BURST_BURSTINESS_COLUMNS,
    ROW_DROP_MIME,
)
from .session_db import (
    save_session_to_file,
    load_session_from_file,
    SESSION_FILE_FILTER,
    criterion_to_dict,
    dict_to_criterion,
)


def _normalize_nt_path(path: str) -> str:
    return ("\\" + (path or "").replace("/", "\\").strip("\\")).lower() + "\\"


def _is_executable_name(file_name: str) -> bool:
    return Path(file_name or "").suffix.lower() in _EXECUTABLE_EXTENSIONS


def _is_executable_ext(ext: str) -> bool:
    """True if extension (e.g. '.exe' or 'exe') is an executable type."""
    e = (ext or "").strip().lower()
    if not e:
        return False
    return ("." + e if not e.startswith(".") else e) in _EXECUTABLE_EXTENSIONS


def _is_exec_swap(old_ext: str, new_ext: str) -> bool:
    """True if extension changed from executable to non-executable or vice versa."""
    old_exec = _is_executable_ext(old_ext)
    new_exec = _is_executable_ext(new_ext)
    return old_exec != new_exec


def _is_suspicious_parent_path(parent_path: str) -> bool:
    normalized = _normalize_nt_path(parent_path)
    return any(marker in normalized for marker in _SUSPICIOUS_PATH_MARKERS)


def _mft_row_risk_level(rec: MFTRecord, parent_path: str, has_timestomp: bool, seq_high: bool) -> str | None:
    is_exec = _is_executable_name(rec.primary_name())
    suspicious_path = _is_suspicious_parent_path(parent_path)
    if has_timestomp or (is_exec and suspicious_path):
        return "critical"
    if is_exec or suspicious_path:
        return "high"
    if seq_high:
        return "medium"
    return None


def _usn_row_risk_level(rec: UsnRecord, parent_path: str) -> str | None:
    is_exec = _is_executable_name(rec.file_name)
    suspicious_path = _is_suspicious_parent_path(parent_path)
    write_like = bool(
        rec.reason & (
            USN_REASON_FILE_CREATE
            | USN_REASON_FILE_DELETE
            | USN_REASON_RENAME_OLD_NAME
            | USN_REASON_RENAME_NEW_NAME
            | USN_REASON_DATA_OVERWRITE
            | USN_REASON_DATA_EXTEND
        )
    )
    if is_exec and suspicious_path:
        return "critical"
    if (is_exec and write_like) or (suspicious_path and write_like):
        return "high"
    if is_exec or suspicious_path:
        return "medium"
    return None


def _apply_row_risk_colors(items: list[QTableWidgetItem], risk_level: str | None) -> None:
    if not risk_level or risk_level not in _ROW_RISK_COLORS:
        return
    bg, fg = _ROW_RISK_COLORS[risk_level]
    for item in items:
        item.setBackground(QColor(bg[0], bg[1], bg[2]))
        item.setForeground(QColor(fg[0], fg[1], fg[2]))


def _make_risk_legend_chip(text: str, bg: tuple[int, int, int], fg: tuple[int, int, int]) -> QWidget:
    """Small legend chip: color swatch + label."""
    wrap = QWidget()
    layout = QHBoxLayout(wrap)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(5)
    swatch = QFrame()
    swatch.setFixedSize(11, 11)
    swatch.setStyleSheet(
        f"background-color: rgb({bg[0]}, {bg[1]}, {bg[2]});"
        "border: 1px solid #585b70; border-radius: 2px;"
    )
    label = QLabel(text)
    label.setStyleSheet(
        f"color: rgb({fg[0]}, {fg[1]}, {fg[2]});"
        "font-size: 9pt;"
    )
    layout.addWidget(swatch)
    layout.addWidget(label)
    return wrap


class ExecSwapHighlightDelegate(QStyledItemDelegate):
    """Draws a thick box around rows where extension changed exec↔any. Only for highlighted rows."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        super().paint(painter, option, index)
        if index.column() != 0:
            return
        is_exec_swap = index.data(EXEC_SWAP_ROLE)
        if not is_exec_swap:
            return
        view = option.widget
        if not view or not hasattr(view, "model"):
            return
        model = view.model()
        row, col_count = index.row(), model.columnCount()
        row_rect = QRect()
        for c in range(col_count):
            idx = model.index(row, c)
            row_rect = row_rect.united(view.visualRect(idx))
        if row_rect.isEmpty():
            return
        painter.save()
        painter.setClipping(False)  # Allow drawing outside cell so row-wide border is visible
        r, g, b = _EXEC_SWAP_BORDER_COLOR
        painter.setPen(QPen(QColor(r, g, b), _EXEC_SWAP_BORDER_WIDTH))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(row_rect.adjusted(1, 1, -1, -1))
        painter.restore()


class TableRowDragFilter(QObject):
    """Event filter: when user drags a table row, start a drag with that row's cell value for the column under the cursor.
    Must be installed on table.viewport() because mouse events go to the viewport, not the table."""
    def __init__(self, table, table_id: str, get_cell_value):
        super().__init__(table)
        self._table = table
        self._viewport = table.viewport() if hasattr(table, "viewport") else table
        self._table_id = table_id
        self._get_cell_value = get_cell_value
        self._press_row = -1
        self._press_col = -1
        self._press_global = None

    def eventFilter(self, obj, event):
        if obj != self._viewport:
            return False
        t = event.type()
        if t == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
            pt = event.position().toPoint() if hasattr(event, "position") else event.pos()
            idx = self._table.indexAt(pt)
            if idx.isValid():
                self._press_row = idx.row()
                self._press_col = idx.column()
                self._press_global = event.globalPosition().toPoint() if hasattr(event, "globalPosition") else event.globalPos()
            return False
        if t == QEvent.Type.MouseButtonRelease:
            self._press_row = -1
            self._press_col = -1
            self._press_global = None
            return False
        if t == QEvent.Type.MouseMove and self._press_row >= 0 and self._press_col >= 0:
            pos = event.globalPosition().toPoint() if hasattr(event, "globalPosition") else event.globalPos()
            if (pos - self._press_global).manhattanLength() >= QApplication.startDragDistance():
                col = self._press_col
                row = self._press_row
                self._press_row = -1
                self._press_col = -1
                self._press_global = None
                try:
                    value = self._get_cell_value(row, col)
                except Exception:
                    value = ""
                payload = json.dumps({"t": self._table_id, "c": col, "v": value})
                drag = QDrag(self._table)
                mime = QMimeData()
                mime.setText(payload)
                mime.setData(ROW_DROP_MIME, QByteArray(payload.encode("utf-8")))
                drag.setMimeData(mime)
                drag.exec(Qt.DropAction.CopyAction)
                return True
        return False


def _record_display_fields(rec: MFTRecord, path_table: dict) -> tuple:
    """Compute display tuple (c0..c11, seq_high) for one record. Used by MFTTableModel."""
    parent_path = parent_path_for_record(rec, path_table)
    typ = "Dir" if rec.is_directory else "File"
    if not rec.in_use:
        typ += " (del)"
    size = rec.size()
    size_str = f"{size:,}" if size else ""
    mod_mft = rec.standard_info.mft_modified_iso() if rec.standard_info else ""
    acc = rec.standard_info.accessed_iso() if rec.standard_info else ""
    pfn = rec.primary_file_name()
    fn_created_iso = pfn.created_iso() if pfn else ""
    anomaly = detect_timestomping_anomaly(rec)
    anomaly_text = anomaly.flag_message() if anomaly else ""
    seq_high = is_high_sequence(rec, DEFAULT_SEQUENCE_GAP_THRESHOLD)
    seq_text = f"{rec.sequence}" + (" (reused)" if seq_high else "")
    return (
        str(rec.record_number),
        rec.primary_name(),
        parent_path,
        typ,
        size_str,
        rec.created_iso(),
        rec.modified_iso(),
        mod_mft,
        acc,
        fn_created_iso,
        anomaly_text,
        seq_text,
        seq_high,
    )


def _is_valid_filetime_ticks(ticks: int | None) -> bool:
    """True when FILETIME ticks contains a sane timestamp value."""
    return ticks not in (None, 0, 0x7FFFFFFFFFFFFFFF)


def _format_delta_seconds(start_ticks: int | None, end_ticks: int | None, *, allow_negative: bool = True) -> str:
    """Return whole-second delta as text, or empty when unavailable/invalid."""
    if not _is_valid_filetime_ticks(start_ticks) or not _is_valid_filetime_ticks(end_ticks):
        return ""
    delta_seconds = int((int(end_ticks) - int(start_ticks)) / 10_000_000)
    if not allow_negative and delta_seconds < 0:
        return ""
    return str(delta_seconds)


def _record_created_ticks(rec: MFTRecord) -> int | None:
    """Return FILETIME created ticks for record (SI or FN), or None if invalid."""
    si = rec.standard_info
    pfn = rec.primary_file_name()
    if si and _is_valid_filetime_ticks(si.created):
        return si.created
    if pfn and _is_valid_filetime_ticks(pfn.created):
        return pfn.created
    return None


def _record_timeline_delta_fields(
    rec: MFTRecord,
    usn_delete_ticks_by_file_ref: dict[tuple[int, int], int] | None = None,
) -> tuple[str, str, str]:
    """
    Compute timeline vectors (seconds): create->modify, create->mftchange, modify->delete.
    All timestamps are FILETIME-derived (UTC).
    """
    pfn = rec.primary_file_name()
    si = rec.standard_info

    # Keep source pairing consistent for create->modify:
    # prefer SI pair when both valid; else FN pair; avoid SI/FN mixing.
    created_ticks = None
    modified_ticks = None
    if si and _is_valid_filetime_ticks(si.created) and _is_valid_filetime_ticks(si.modified):
        created_ticks = si.created
        modified_ticks = si.modified
    elif pfn and _is_valid_filetime_ticks(pfn.created) and _is_valid_filetime_ticks(pfn.modified):
        created_ticks = pfn.created
        modified_ticks = pfn.modified

    # create->mftchange should come from SI only (same metadata source).
    si_created_ticks = si.created if (si and _is_valid_filetime_ticks(si.created)) else None
    mft_modified_ticks = si.mft_modified if (si and _is_valid_filetime_ticks(si.mft_modified)) else None
    delete_ticks = (usn_delete_ticks_by_file_ref or {}).get((rec.record_number, rec.sequence))
    return (
        _format_delta_seconds(created_ticks, modified_ticks, allow_negative=False),
        _format_delta_seconds(si_created_ticks, mft_modified_ticks, allow_negative=False),
        _format_delta_seconds(modified_ticks, delete_ticks, allow_negative=False),
    )


def _format_time_to_delete(seconds: float) -> str:
    """Format time-to-delete as human-readable (e.g. '2m 30s', '45s', '1h 5m')."""
    if seconds < 0:
        return ""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        m, sec = divmod(s, 60)
        return f"{m}m {sec}s" if sec else f"{m}m"
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    parts = [f"{h}h"]
    if m or sec:
        parts.append(f"{m}m" if m else "")
        if sec:
            parts.append(f"{sec}s")
    return " ".join(p for p in parts if p).strip()


def _compound_text_matches(text: str, pattern: str) -> bool:
    """True if pattern matches text. Empty pattern = no filter (match all). Supports * and ? glob."""
    pattern = (pattern or "").strip()
    if not pattern:
        return True
    text_lower = (text or "").lower()
    pattern_lower = pattern.lower()
    if "*" in pattern_lower or "?" in pattern_lower:
        return fnmatch.fnmatch(text_lower, pattern_lower)
    return pattern_lower in text_lower


def _mft_record_cell_values(
    rec: MFTRecord,
    path_table: dict,
    usn_delete_ticks_by_file_ref: dict[tuple[int, int], int] | None = None,
) -> list[str]:
    """Return display cell values for this record (same order as MFT columns)."""
    fields = _record_display_fields(rec, path_table)
    deltas = _record_timeline_delta_fields(rec, usn_delete_ticks_by_file_ref)
    return [str(fields[i]) for i in range(12)] + list(deltas)


def _format_time_anchor_tooltip(cell_ticks: int, anchor_ticks: int) -> str:
    """Format time difference (cell − anchor) as 'ms | min | h | d' for tooltip."""
    diff_100ns = cell_ticks - anchor_ticks
    diff_sec = diff_100ns / 10 / 1_000_000.0
    sign = "+" if diff_sec >= 0 else "−"
    abs_sec = abs(diff_sec)
    ms = abs_sec * 1000
    mn = abs_sec / 60
    h = abs_sec / 3600
    d = abs_sec / 86400
    return f"{sign}{ms:.2f} ms | {sign}{mn:.2f} min | {sign}{h:.2f} h | {sign}{d:.2f} d"


def _mft_record_time_ticks(rec: MFTRecord, col_index: int) -> int | None:
    """Return FILETIME (100ns) for the given MFT time column (5=Created, 6=Modified, 7=MFT Modified, 8=Accessed, 9=FN created), or None if invalid."""
    if col_index == 5:  # Created
        if rec.standard_info and rec.standard_info.created:
            return rec.standard_info.created
        pfn = rec.primary_file_name()
        return pfn.created if (pfn and pfn.created) else None
    if col_index == 6:  # Modified
        if rec.standard_info and rec.standard_info.modified:
            return rec.standard_info.modified
        pfn = rec.primary_file_name()
        return pfn.modified if (pfn and pfn.modified) else None
    if col_index == 7:  # MFT Modified
        return rec.standard_info.mft_modified if (rec.standard_info and rec.standard_info.mft_modified) else None
    if col_index == 8:  # Accessed
        return rec.standard_info.accessed if (rec.standard_info and rec.standard_info.accessed) else None
    if col_index == 9:  # FN created
        pfn = rec.primary_file_name()
        return pfn.created if (pfn and pfn.created) else None
    return None


def _record_passes_filter(
    rec: MFTRecord,
    filter_type: str,
    search: str,
    path_table: dict,
    criteria: list[FilterCriterion],
    time_anchor_ticks: int | None = None,
    time_anchor_seconds: int = 30,
    time_anchor_mft_col: int | None = None,
    usn_delete_ticks_by_file_ref: dict[tuple[int, int], int] | None = None,
) -> bool:
    """True if record passes the given filter type, search, compound criteria, and optional time anchor window."""
    if filter_type == "Files only" and rec.is_directory:
        return False
    if filter_type == "Directories only" and not rec.is_directory:
        return False
    if filter_type == "In-use only" and not rec.in_use:
        return False
    if filter_type == "Deleted (recycled)" and rec.in_use:
        return False
    if search and not _search_matches_record(search, rec, path_table):
        return False
    if time_anchor_ticks is not None and time_anchor_mft_col is not None:
        ticks = _mft_record_time_ticks(rec, time_anchor_mft_col)
        if ticks is None:
            return False
        delta_100ns = time_anchor_seconds * 10 * 1_000_000  # seconds -> 100ns
        if ticks < time_anchor_ticks - delta_100ns or ticks > time_anchor_ticks + delta_100ns:
            return False
    if not criteria:
        return True
    cells = _mft_record_cell_values(rec, path_table, usn_delete_ticks_by_file_ref)
    for c in criteria:
        if c.col_index < 0 or c.col_index >= len(cells):
            continue
        if not criterion_matches(cells[c.col_index], c.operator, c.value, c.col_type):
            return False
    return True


class MFTTableModel(QAbstractTableModel):
    """
    Full-count lazy model: rowCount() = total filtered records.
    Qt only calls data() for visible rows (~20-50), so this is fast even for
    millions of records. Display fields are cached per record index.
    """
    COLUMNS = [
        "MFT #", "Name", "Parent path", "Type", "Size", "Created", "Modified",
        "MFT Modified", "Accessed", "FN Created", "SI vs FN", "Seq",
        "\u0394 C\u2192M (s)", "\u0394 C\u2192MFT (s)", "\u0394 M\u2192Del (s)",
    ]
    DEFAULT_HIDDEN = {7, 8, 9, 10, 11, 12, 13, 14}
    _CACHE_SIZE = 500

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[MFTRecord] = []
        self._path_table: dict[int, str] = {}
        self._filtered_indices: list[int] = []
        self._field_cache: dict[int, tuple] = {}
        self._time_anchor_ticks: int | None = None
        self._usn_delete_ticks_by_file_ref: dict[tuple[int, int], int] = {}

    def set_data(self, records: list, path_table: dict):
        self.beginResetModel()
        self._records = records
        self._path_table = path_table or {}
        self._filtered_indices = list(range(len(records)))
        self._field_cache.clear()
        self.endResetModel()

    def set_usn_delete_ticks_map(self, usn_delete_ticks_by_file_ref: dict[tuple[int, int], int] | None):
        """Inject USN-derived delete timestamps (latest FILE_DELETE per full file reference)."""
        self.beginResetModel()
        self._usn_delete_ticks_by_file_ref = dict(usn_delete_ticks_by_file_ref or {})
        self._field_cache.clear()
        self.endResetModel()

    def set_filter(
        self,
        search: str,
        filter_type: str,
        criteria: list,
        time_anchor_ticks: int | None = None,
        time_anchor_seconds: int = 30,
        time_anchor_mft_col: int | None = None,
    ):
        self.beginResetModel()
        s = (search or "").strip().lower()
        ft = filter_type or "All"
        pt = self._path_table or {}
        self._time_anchor_ticks = time_anchor_ticks
        self._filtered_indices = [
            i for i, rec in enumerate(self._records)
            if _record_passes_filter(
                rec, ft, s, pt, criteria or [],
                time_anchor_ticks=time_anchor_ticks,
                time_anchor_seconds=time_anchor_seconds,
                time_anchor_mft_col=time_anchor_mft_col,
                usn_delete_ticks_by_file_ref=self._usn_delete_ticks_by_file_ref,
            )
        ]
        self._field_cache.clear()
        self.endResetModel()

    def total_filtered(self) -> int:
        return len(self._filtered_indices)

    def record_at(self, view_row: int) -> MFTRecord | None:
        if view_row < 0 or view_row >= len(self._filtered_indices):
            return None
        idx = self._filtered_indices[view_row]
        if 0 <= idx < len(self._records):
            return self._records[idx]
        return None

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return len(self._filtered_indices)

    def columnCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return len(self.COLUMNS)

    def _get_fields(self, view_row: int) -> tuple | None:
        if view_row < 0 or view_row >= len(self._filtered_indices):
            return None
        idx = self._filtered_indices[view_row]
        cached = self._field_cache.get(idx)
        if cached is not None:
            return cached
        if idx < 0 or idx >= len(self._records):
            return None
        fields = _record_display_fields(self._records[idx], self._path_table) + _record_timeline_delta_fields(
            self._records[idx],
            self._usn_delete_ticks_by_file_ref,
        )
        if len(self._field_cache) >= self._CACHE_SIZE:
            self._field_cache.clear()
        self._field_cache[idx] = fields
        return fields

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() < 0:
            return None
        fields = self._get_fields(index.row())
        if not fields:
            return None
        c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, seq_high, c12, c13, c14 = fields
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14][col]
        if role == RECORD_INDEX_ROLE:
            return index.row()
        if role == Qt.ItemDataRole.BackgroundRole:
            rec = self.record_at(index.row())
            if rec is not None:
                risk = _mft_row_risk_level(rec, c2, bool(c10), bool(seq_high))
                if risk and risk in _ROW_RISK_COLORS:
                    bg, _ = _ROW_RISK_COLORS[risk]
                    return QColor(bg[0], bg[1], bg[2])
        if role == Qt.ItemDataRole.ForegroundRole:
            rec = self.record_at(index.row())
            if rec is not None:
                risk = _mft_row_risk_level(rec, c2, bool(c10), bool(seq_high))
                if risk and risk in _ROW_RISK_COLORS:
                    _, fg = _ROW_RISK_COLORS[risk]
                    return QColor(fg[0], fg[1], fg[2])
        if role == Qt.ItemDataRole.ToolTipRole and self._time_anchor_ticks is not None and col in (5, 6, 7, 8, 9):
            rec = self.record_at(index.row())
            if rec is not None:
                ticks = _mft_record_time_ticks(rec, col)
                if ticks is not None:
                    return _format_time_anchor_tooltip(ticks, self._time_anchor_ticks)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(self.COLUMNS):
            return self.COLUMNS[section]
        return None

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder):
        if column < 0 or column >= len(self.COLUMNS):
            return
        pt = self._path_table or {}
        reverse = order == Qt.SortOrder.DescendingOrder

        def sort_key(idx: int):
            rec = self._records[idx]
            if column == 0:  # MFT #
                return rec.record_number
            if column == 1:  # Name
                return (rec.primary_name() or "").lower()
            if column == 2:  # Parent path
                return (parent_path_for_record(rec, pt) or "").lower()
            if column == 3:  # Type
                typ = "Dir" if rec.is_directory else "File"
                if not rec.in_use:
                    typ += " (del)"
                return typ.lower()
            if column == 4:  # Size
                return rec.size() or 0
            if column in (5, 6, 7, 8, 9):  # time columns: sort by FILETIME ticks; None last when asc
                ticks = _mft_record_time_ticks(rec, column)
                return ticks if ticks is not None else (2**63)
            if column == 10:  # SI vs FN
                anomaly = detect_timestomping_anomaly(rec)
                return (anomaly.flag_message() if anomaly else "").lower()
            if column == 11:  # Seq
                return rec.sequence
            if column in (12, 13, 14):  # timeline vectors in seconds
                cells = _mft_record_cell_values(rec, pt, self._usn_delete_ticks_by_file_ref)
                try:
                    return int(cells[column]) if cells[column] else (2**63)
                except (ValueError, IndexError):
                    return 2**63
            return 0

        self.layoutAboutToBeChanged.emit()
        self._filtered_indices.sort(key=sort_key, reverse=reverse)
        self._field_cache.clear()
        self.layoutChanged.emit()


def _search_matches_record(search: str, rec: MFTRecord, path_table: dict) -> bool:
    """Return True if search matches this record (for proxy filter)."""
    if not search:
        return True
    display_name = (rec.primary_name() or "").lower()
    all_names = [f.name for f in rec.file_names if f.name]
    mft_str = str(rec.record_number)
    parent_path = (parent_path_for_record(rec, path_table) or "").lower()
    if "*" in search or "?" in search:
        if display_name and fnmatch.fnmatch(display_name, search):
            return True
        if fnmatch.fnmatch(mft_str, search):
            return True
        return False
    hay = " ".join([mft_str, display_name, parent_path] + all_names).lower()
    return search in hay


class LoadMFTThread(QThread):
    """Load MFT and prepare path table in background; no row limit. Table uses lazy model."""
    progress = Signal(int, int)  # current, total (0 = indeterminate)
    progress_phase = Signal(str)  # "Loading..." or "Building paths..."
    finished_load = Signal(object, object)  # records, path_table
    error = Signal(str)

    def __init__(self, path: Path, max_records: int | None = None):
        super().__init__()
        self.path = path
        self.max_records = max_records  # Unused: we always load all (no cap)

    def run(self):
        try:
            records = []
            total = 0
            self.progress_phase.emit("Loading MFT records...")
            # Always pass max_records=None to load entire MFT with no limit
            for rec in iter_mft_records(self.path, max_records=None):
                records.append(rec)
                total += 1
                if total % 2000 == 0:
                    self.progress.emit(total, 0)
            self.progress.emit(total, total)
            self.progress_phase.emit("Building paths...")
            path_table = build_path_table(records)
            self.finished_load.emit(records, path_table)
        except FileNotFoundError as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"Parse error: {e}")


class TemporalBurstThread(QThread):
    """Run build_temporal_burst_report in background so MFT load and Statistics refresh stay responsive."""
    result_ready = Signal(object, object)  # poisson_list, burstiness_list (lists of dataclass instances)

    def __init__(
        self,
        records: list,
        path_table: dict,
        usn_records: list | None,
        window_seconds: int = 60,
    ):
        super().__init__()
        self._records = records
        self._path_table = path_table
        self._usn_records = usn_records or []
        self._window_seconds = window_seconds

    def run(self):
        try:
            from ..mft_parser import build_temporal_burst_report
            poisson_list, burstiness_list = build_temporal_burst_report(
                self._records,
                self._path_table,
                window_seconds=self._window_seconds,
                top_n_poisson=200,
                top_n_burstiness=200,
                usn_records=self._usn_records if self._usn_records else None,
            )
            self.result_ready.emit(poisson_list, burstiness_list)
        except Exception:
            self.result_ready.emit([], [])


class UsnTableRefreshThread(QThread):
    """Build USN table row data in a background thread; parent_paths are precomputed on main thread to match MFT table."""
    batch_ready = Signal(int, list)  # start_row, list of (ts, usn, mft, name, parent_path, reason_str)
    finished_refresh = Signal(int, str, int)  # showing_count, mft_note, total_rows_filtered (for label)

    def __init__(self, showing: list, parent_paths: list[str], mft_note: str, total_rows_filtered: int):
        super().__init__()
        self._showing = showing
        self._parent_paths = parent_paths  # same order as showing; computed on main thread from _path_table + _records
        self._mft_note = mft_note
        self._total_rows_filtered = total_rows_filtered

    def run(self):
        batch_size = 2000
        for start in range(0, len(self._showing), batch_size):
            end = min(start + batch_size, len(self._showing))
            batch = []
            for i, rec in enumerate(self._showing[start:end]):
                parent_path = self._parent_paths[start + i]
                batch.append((
                    rec.timestamp_iso(),
                    str(rec.usn),
                    str(rec.mft_record_number()),
                    rec.file_name,
                    parent_path,
                    rec.reason_string(),
                ))
            self.batch_ready.emit(start, batch)
        self.finished_refresh.emit(len(self._showing), self._mft_note, self._total_rows_filtered)


class DirectoryChurnFilesDialog(QDialog):
    """Popup listing every file in a directory churn burst with extension and risk highlights."""

    _EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".msi"}

    def __init__(self, entry: DirectoryChurnEntry, parent: QWidget | None = None):
        super().__init__(parent)
        self._entry = entry
        self.setWindowTitle(f"Directory churn — {entry.directory}")
        self.setMinimumSize(640, 380)
        self.resize(820, 520)
        layout = QVBoxLayout(self)

        header = QLabel(
            f"<b>{entry.file_count}</b> files created in <b>{entry.window_seconds:.1f}s</b> &nbsp;|&nbsp; "
            f"{entry.window_start_iso} → {entry.window_end_iso}"
        )
        header.setWordWrap(True)
        header.setStyleSheet("font-size: 10pt;")
        layout.addWidget(header)

        tags: list[str] = []
        if entry.has_executable:
            tags.append('<span style="color:#f38ba8;">EXECUTABLE</span>')
        if entry.is_persistence_path:
            tags.append('<span style="color:#fab387;">PERSISTENCE PATH</span>')
        tags.append(f'<span style="color:#89b4fa;">Risk: {entry.risk.upper()}</span>')
        tag_label = QLabel("&nbsp;&nbsp;".join(tags))
        tag_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(tag_label)

        dir_label = QLabel(f"Directory: <code>{entry.directory}</code>")
        dir_label.setTextFormat(Qt.TextFormat.RichText)
        dir_label.setStyleSheet("color: #cdd6f4; margin-top: 4px;")
        dir_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(dir_label)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filename or extension substring…")
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self._filter_edit, 1)
        self._exec_only_cb = QCheckBox("Executable only")
        self._exec_only_cb.stateChanged.connect(self._apply_filter)
        filter_row.addWidget(self._exec_only_cb)
        self._filter_count = QLabel("")
        self._filter_count.setStyleSheet("color: #9399b2; font-size: 9pt;")
        filter_row.addWidget(self._filter_count)
        layout.addLayout(filter_row)

        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(["#", "Filename", "Extension"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self._table, 1)

        close_btn = QPushButton("Close")
        close_btn.setIcon(QApplication.instance().style().standardIcon(QStyle.StandardPixmap.SP_DialogCloseButton))
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

        self._apply_filter()

    def _apply_filter(self) -> None:
        text = self._filter_edit.text().strip().lower()
        exec_only = self._exec_only_cb.isChecked()
        names = self._entry.file_names
        filtered: list[tuple[int, str, str]] = []
        for idx, name in enumerate(names):
            ext = (Path(name).suffix or "").lower()
            if exec_only and ext not in self._EXEC_EXT:
                continue
            if text and text not in name.lower() and text not in ext:
                continue
            filtered.append((idx + 1, name, ext))

        self._table.setRowCount(len(filtered))
        for row, (num, name, ext) in enumerate(filtered):
            num_item = QTableWidgetItem(str(num))
            name_item = QTableWidgetItem(name)
            ext_item = QTableWidgetItem(ext if ext else "(none)")
            if ext in self._EXEC_EXT:
                for item in (num_item, name_item, ext_item):
                    item.setForeground(QColor(0xf3, 0x8b, 0xa8))
            self._table.setItem(row, 0, num_item)
            self._table.setItem(row, 1, name_item)
            self._table.setItem(row, 2, ext_item)
        self._table.resizeColumnsToContents()
        total = len(names)
        shown = len(filtered)
        self._filter_count.setText(
            f"{shown} of {total}" if shown != total else f"{total} files"
        )


class SequenceGapReportDialog(QDialog):
    """Dialog showing records with high sequence numbers (reused MFT slots — graveyard for deleted files)."""
    def __init__(self, entries: list[SequenceGapEntry], parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Sequence gap report — high reuse slots")
        self.setMinimumSize(700, 400)
        self.resize(900, 500)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "Records with sequence number ≥ " + str(DEFAULT_SEQUENCE_GAP_THRESHOLD)
            + " (slot reused many times). Consider carving unallocated space in these directories."
        ))
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(["MFT #", "Sequence", "Path", "Name", "Status"])
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            self._table.setItem(row, 0, QTableWidgetItem(str(e.record_number)))
            self._table.setItem(row, 1, QTableWidgetItem(str(e.sequence)))
            self._table.setItem(row, 2, QTableWidgetItem(e.full_path))
            self._table.setItem(row, 3, QTableWidgetItem(e.primary_name))
            status = "in use" if e.in_use else "deleted"
            if e.is_directory:
                status += " (dir)"
            self._table.setItem(row, 4, QTableWidgetItem(status))
        layout.addWidget(self._table)
        close_btn = QPushButton("Close")
        close_btn.setIcon(QApplication.instance().style().standardIcon(QStyle.StandardPixmap.SP_DialogCloseButton))
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class LoadUsnThread(QThread):
    """Load USN Journal ($J) in background — all update reasons by default."""
    progress = Signal(int, int)
    progress_phase = Signal(str)
    finished_load = Signal(object, object)  # usn_records, usn_by_mft
    error = Signal(str)

    def __init__(self, path: Path, max_records: int | None = 500_000, close_only: bool = False):
        super().__init__()
        self.path = path
        self.max_records = max_records
        self.close_only = close_only

    def run(self):
        try:
            self.progress_phase.emit("Loading USN Journal ($J)...")
            records = load_usn_records(
                self.path,
                max_records=self.max_records,
                close_only=self.close_only,
            )
            self.progress.emit(len(records), len(records))
            self.progress_phase.emit("Indexing by MFT...")
            by_mft = usn_close_events_by_mft(records)
            self.finished_load.emit(records, by_mft)
        except FileNotFoundError as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"USN parse error: {e}")


def _usn_reason_badge_color(reason: int) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    """Return ( (bg_r,bg_g,bg_b), (fg_r,fg_g,fg_b) ) for reason badge."""
    if reason & USN_REASON_CLOSE:
        return ((0x1e, 0x3a, 0x5f), (0x93, 0xc5, 0xfd))
    if reason & USN_REASON_FILE_DELETE:
        return ((0x45, 0x1a, 0x1a), (0xf3, 0x8c, 0xa8))
    if reason & USN_REASON_FILE_CREATE:
        return ((0x1a, 0x3d, 0x2e), (0xa6, 0xe3, 0xa8))
    if reason & USN_REASON_RENAME_OLD_NAME or reason & USN_REASON_RENAME_NEW_NAME:
        return ((0x42, 0x2e, 0x1a), (0xfa, 0xcd, 0x9e))
    if reason & USN_REASON_DATA_OVERWRITE or reason & USN_REASON_DATA_EXTEND:
        return ((0x31, 0x2e, 0x3e), (0xcb, 0xb4, 0xfa))
    if reason & USN_REASON_BASIC_INFO_CHANGE:
        return ((0x2e, 0x34, 0x40), (0x89, 0xb4, 0xfa))
    return ((0x31, 0x32, 0x44), (0xa6, 0xad, 0xc8))


class SortableTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem that compares by UserRole sort key when present."""

    def __lt__(self, other):
        if isinstance(other, QTableWidgetItem):
            left = self.data(Qt.ItemDataRole.UserRole)
            right = other.data(Qt.ItemDataRole.UserRole)
            if left is not None and right is not None:
                try:
                    return left < right
                except TypeError:
                    return str(left) < str(right)
        return super().__lt__(other)


def _build_usn_row_items(rec: UsnRecord, parent_path: str, anchor_ticks: int | None = None) -> list[QTableWidgetItem]:
    """Build sortable USN row items with typed sort keys for stable click re-sorting."""
    ts_item = SortableTableWidgetItem(rec.timestamp_iso())
    ts_item.setData(Qt.ItemDataRole.UserRole, int(rec.timestamp))
    if anchor_ticks is not None:
        ts_item.setToolTip(_format_time_anchor_tooltip(rec.timestamp, anchor_ticks))

    usn_item = SortableTableWidgetItem(str(rec.usn))
    usn_item.setData(Qt.ItemDataRole.UserRole, int(rec.usn))

    mft_item = SortableTableWidgetItem(str(rec.mft_record_number()))
    mft_item.setData(Qt.ItemDataRole.UserRole, int(rec.mft_record_number()))

    name_item = SortableTableWidgetItem(rec.file_name or "")
    name_item.setData(Qt.ItemDataRole.UserRole, (rec.file_name or "").lower())

    parent_item = SortableTableWidgetItem(parent_path or "\\")
    parent_item.setData(Qt.ItemDataRole.UserRole, (parent_path or "\\").lower())

    reason_text = rec.reason_string()
    reason_item = SortableTableWidgetItem(reason_text)
    reason_item.setData(Qt.ItemDataRole.UserRole, reason_text.lower())

    return [ts_item, usn_item, mft_item, name_item, parent_item, reason_item]


def _application_help_html() -> str:
    """HTML content for the Application Help dialog."""
    return """
    <html><head><style>
    body { font-family: sans-serif; color: #a6adc8; background: #1e1e2e; padding: 14px; line-height: 1.55; }
    h1 { color: #89b4fa; font-size: 1.35em; margin-top: 18px; margin-bottom: 10px; border-bottom: 1px solid #313244; padding-bottom: 4px; }
    h2 { color: #b4befe; font-size: 1.12em; margin-top: 14px; margin-bottom: 8px; }
    h3 { color: #cdd6f4; font-size: 1.02em; margin-top: 10px; margin-bottom: 5px; }
    p { margin: 7px 0; }
    ul, ol { margin: 7px 0; padding-left: 22px; }
    li { margin: 3px 0; }
    dt { font-weight: bold; color: #89b4fa; margin-top: 8px; }
    dd { margin-left: 18px; margin-bottom: 6px; }
    .tip { background: #313244; padding: 8px 12px; border-radius: 6px; margin: 10px 0; color: #a6e3a1; font-size: 0.95em; }
    .colname { font-family: monospace; color: #f9e2af; }
    table.help { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 0.92em; }
    table.help th, table.help td { border: 1px solid #45475a; padding: 5px 8px; text-align: left; }
    table.help th { background: #313244; color: #89b4fa; }
    </style></head><body>
    <h1>MFT Reader — Application Help</h1>
    <p>This application is a <b>forensic $MFT analysis tool</b> for NTFS volumes. It parses the Master File Table ($MFT) and optionally the USN Change Journal ($J) to extract file metadata, timestamps, and file-system activity for incident response, triage, and timeline reconstruction.</p>
    <p><b>What is the MFT?</b> The Master File Table is the heart of NTFS: every file and directory has at least one 1024-byte record. Each record holds attributes such as $STANDARD_INFORMATION (timestamps, flags), $FILE_NAME (name, parent, more timestamps), and $DATA (size, allocation). Parsing $MFT gives you a complete picture of what existed on the volume at the time the $MFT was captured.</p>
    <p><b>What is the USN Journal ($J)?</b> The Update Sequence Number Journal is a log of file-system changes: creates, deletes, renames, and data modifications. Loading $J alongside $MFT lets you correlate MFT records with actual change events and build richer timelines.</p>
    <p><b>Typical workflow:</b> (1) Open $MFT (from an image or extracted file). (2) Optionally open $J. (3) Use the MFT tab to browse and filter; use the Analysis tab for anomaly reports. (4) Save a session to resume later, or export filtered results to CSV.</p>

    <h2>File menu</h2>
    <dl>
    <dt>Open $MFT... (Ctrl+O)</dt>
    <dd>Load an NTFS $MFT file (raw $MFT from a live system or from a forensic image). The tool reads sequentially and builds an in-memory index; the table uses a lazy model so scrolling through millions of records stays responsive.</dd>
    <dt>Open $J (USN Journal)...</dt>
    <dd>Load the USN Journal ($J) for the same volume. When both are loaded, the app correlates USN events with MFT record numbers and enables Analysis features that depend on USN (extension change, survival metrics, USN counts in the tree).</dd>
    <dt>Save session... (Ctrl+S)</dt>
    <dd>Save paths to $MFT and $J, filter state, time anchor, and column visibility to a session file (JSON). Resume an investigation without re-opening dialogs.</dd>
    <dt>Load session... (Ctrl+L)</dt>
    <dd>Open a previously saved session file and restore $MFT (and $J if stored) and UI state.</dd>
    <dt>Export CSV...</dt>
    <dd>Export the <b>currently visible/filtered</b> MFT table rows to CSV. Only rows that pass the current MFT tab filters and time anchor are exported.</dd>
    <dt>Exit (Ctrl+Q)</dt>
    <dd>Close the application.</dd>
    </dl>

    <h2>MFT tab</h2>
    <p>Displays every file record from the loaded $MFT in a sortable table. You can filter by compound criteria, restrict by time window, and inspect each record in detail. Rows may be highlighted by <b>risk level</b> (Critical / High / Medium) based on timestomping, executable names in suspicious paths, or high sequence numbers.</p>

    <h3>MFT table columns (reference)</h3>
    <table class="help">
    <tr><th>Column</th><th>Description</th></tr>
    <tr><td class="colname">MFT #</td><td>Record number (index in the MFT). Stable identifier for the file/directory.</td></tr>
    <tr><td class="colname">Name</td><td>Primary filename from the $FILE_NAME attribute (often the long name).</td></tr>
    <tr><td class="colname">Parent path</td><td>Full path of the parent directory (reconstructed from the path table).</td></tr>
    <tr><td class="colname">Type</td><td>Directory or file.</td></tr>
    <tr><td class="colname">Size</td><td>Logical size from $DATA (or 0 for directories).</td></tr>
    <tr><td class="colname">Created</td><td>Creation time from $STANDARD_INFORMATION (SI).</td></tr>
    <tr><td class="colname">Modified</td><td>Last write time from SI.</td></tr>
    <tr><td class="colname">MFT Modified</td><td>Last MFT record change (e.g. rename, attribute change).</td></tr>
    <tr><td class="colname">Accessed</td><td>Last access time from SI.</td></tr>
    <tr><td class="colname">FN Created</td><td>Creation time from $FILE_NAME (FN). FN and SI can differ.</td></tr>
    <tr><td class="colname">SI vs FN</td><td>Highlights when SI and FN timestamps disagree (possible timestomping). Shows which field differs.</td></tr>
    <tr><td class="colname">Seq</td><td>Sequence number. High values mean the slot was reused (deleted-file graveyard).</td></tr>
    <tr><td class="colname">Δ C→M (s)</td><td>Seconds from Created to Modified. Very small or zero can indicate copied/backdated files.</td></tr>
    <tr><td class="colname">Δ C→MFT (s)</td><td>Seconds from Created to MFT Modified.</td></tr>
    <tr><td class="colname">Δ M→Del (s)</td><td>Seconds from Modified to deletion (when USN is loaded). Short-lived files may be temporary.</td></tr>
    </table>

    <h3>Compound filter panel</h3>
    <p>Build multi-criterion filters that are <b>ANDed</b> together. <b>Drag a column header</b> into the filter area or use <b>Add filter</b> to pick a column and set operator and value. Text columns: contains, equals, starts with, ends with, glob (* ?). Number columns: equals, not equals, &lt;, &gt;, &lt;=, &gt;=. Drag filter rows to reorder. Use <b>Copy to USN Journal</b> to replicate filters on the USN tab.</p>

    <h3>Time anchor</h3>
    <p>Restrict the table to records whose chosen timestamp falls within a time window. Select which timestamp to use (e.g. MFT: Created or Modified), enter an <b>anchor time</b> (YYYY-MM-DD HH:MM:SS), and set ± seconds. <b>Set from selection</b> uses the timestamp from the selected row. The <b>risk legend</b> (Critical / High / Medium) refers to row highlighting in MFT and USN tables.</p>

    <h3>Record details (bottom panel)</h3>
    <p>When you select a row: <b>Summary</b> — human-readable timestamps, sizes, flags, SI vs FN note. <b>Attributes</b> — parsed $STANDARD_INFORMATION, $FILE_NAME, $DATA, etc. <b>Raw record (hex)</b> — full MFT record in hex.</p>

    <h3>Context menus</h3>
    <p><b>Right-click column header</b> — Show/hide columns, Show all, Reset to default. <b>Right-click a row</b> — Copy cell contents.</p>

    <h3>Sequence gap report...</h3>
    <p>Lists MFT records with <b>high sequence numbers</b> (reused slots). High seq indicates the slot was reused many times—useful to find graveyard entries. The dialog has its own filter and an Executables only option.</p>

    <h2>USN Journal tab</h2>
    <p>Shows USN Change Journal events in a table: <b>Timestamp</b>, <b>USN</b>, <b>MFT #</b>, <b>Filename</b>, <b>Parent path</b>, and <b>Reason</b>. The same compound filter panel and time anchor bar are available; you can copy filters to or from the MFT tab.</p>

    <h3>USN reason codes (summary)</h3>
    <p>Each event has a reason bitmask. Common values: <b>FILE_CREATE</b> — file or directory created. <b>FILE_DELETE</b> — deleted. <b>RENAME_OLD_NAME</b> / <b>RENAME_NEW_NAME</b> — rename (old and new may appear as separate events). <b>DATA_OVERWRITE</b> / <b>DATA_EXTEND</b> — data overwritten or extended. <b>CLOSE</b> — handle closed (often after writes or renames). <b>BASIC_INFO_CHANGE</b> — attributes or timestamps changed. Filtering by reason (e.g. only FILE_DELETE or DATA_EXTEND) helps focus on creation, deletion, or write activity.</p>

    <h3>Open in dialog (filter by reason)</h3>
    <p>Opens a larger dialog with the full list of USN events. In the dialog you can choose a <b>reason filter</b> from a dropdown (All, FILE_CREATE, FILE_DELETE, etc.) to show only matching events. Useful when the main tab is filtered or when you want to scan a specific type of activity.</p>

    <h2>File System Tree tab</h2>
    <p>Presents a <b>reconstructed directory tree</b> from the MFT path table. Each node is a file or directory with columns summarizing MFT and, if $J is loaded, USN activity. The tree is built on demand: click <b>Rebuild file system tree</b> after loading $MFT (and optionally $J). Top-level items load first; children load when you expand a node (lazy loading for performance).</p>

    <h3>Tree columns (summary)</h3>
    <p><b>Name</b>, <b>MFT #</b>, <b>Type</b> (dir/file), <b>Size</b>, <b>Created</b>, <b>Modified</b>, <b>Seq</b>, <b>In use</b> (yes/no). Then forensic hints: <b>Timestomp?</b> (SI vs FN or similar anomaly), <b>High seq?</b> (reused slot), <b>Suspicious path?</b> (e.g. Temp, Public, $Recycle.Bin, Startup, Tasks), <b>Executable?</b> (extension in .exe, .dll, .ps1, etc.). If USN is loaded: <b>USN Create</b>, <b>USN Delete</b>, <b>USN Rename</b>, <b>USN Data</b> (counts of events per MFT record). Rows can be risk-colored (Critical/High/Medium) like the MFT table.</p>

    <h3>Jump to MFT row</h3>
    <p>Right-click any item in the tree and choose <b>Jump to MFT row</b>. The application switches to the MFT tab and selects the corresponding record for detailed inspection.</p>

    <h2>Analysis tab — Forensic investigation leads</h2>
    <p>This tab provides <b>precomputed reports</b> over the full MFT (and USN, when loaded) dataset. Results are <b>independent of the MFT/USN tab filters</b>; they use the complete loaded data. Use the sub-tabs and each panel’s filter to narrow results. After loading $MFT (and $J where needed), use <b>Refresh</b> or <b>Refresh (compute in background)</b> to (re)generate the data.</p>

    <h3>Anomaly sequences</h3>
    <p>Table of <b>suspicious anomaly sequences</b> detected from MFT and USN: time range (Start–End), Path, Archive flag, Payload, Persistence artifact, Pattern, and Score. Designed to flag patterns that may indicate malware or persistence (e.g. writes to known staging or startup locations). Use the collapsible filter panel above the table to filter by path, score, or other columns.</p>

    <h3>Extension change</h3>
    <p>Lists <b>renames where the file extension changed</b> (e.g. .txt→.exe, .doc→.exe). Such renames can indicate disguised executables. <b>Requires the USN Journal</b> with rename events. Columns: MFT #, Old name, New name, Extension change, Timestamp, Parent path.</p>

    <h3>Entropy / novelty</h3>
    <p><b>High filename entropy</b> — Shannon entropy computed on the filename (excluding path). High entropy suggests random or machine-generated names (e.g. malware drops, temp files). Table: Entropy, Filename, Parent path, MFT #. <b>Extension entropy per directory</b> — For each directory, the diversity of file extensions (entropy) and counts. Unusually high extension diversity in a single folder can be worth investigating.</p>

    <h3>Directory churn</h3>
    <p>Identifies <b>directories where many files were created within a short time window</b> (e.g. 120 seconds). Useful for dropper activity, payload extraction, or bulk persistence installation. Set <b>Window (seconds)</b> (e.g. 5–3600; type a value and press Refresh) and <b>Min files</b> (minimum files in that window to list the directory). Table: Directory, Files (count), First file (burst), Last file (burst), Duration (s), Executable?, Persistence?, Files in burst. <b>Double-click a row</b> to open a dialog listing every file in that burst (with extension and risk highlights).</p>
    <p><b>Persistence column</b> — A path-based check: the directory path is compared against known file-based persistence and staging locations. If the path contains any of these markers (case-insensitive), Persistence? shows <b>YES</b>:</p>
    <ul>
    <li><code>\\startup\\</code>, <code>\\windows\\system32\\tasks\\</code>, <code>\\windows\\tasks\\</code></li>
    <li><code>\\appdata\\roaming\\...\\startup\\</code>, <code>\\programdata\\...\\startup\\</code></li>
    <li><code>\\appdata\\local\\temp\\</code>, <code>\\windows\\temp\\</code></li>
    <li><code>\\users\\public\\</code>, <code>\\programdata\\</code>, <code>\\$recycle.bin\\</code></li>
    </ul>
    <p><b>Scope and limitations</b> — These markers cover common file-based persistence and staging locations. They do <b>not</b> cover: (1) <b>Registry-based persistence</b> (Run, RunOnce, Services, WMI subscriptions, etc.), which requires separate registry analysis; (2) other file-based locations such as WMI repository (<code>\\windows\\system32\\wbem\\repository\\</code>), fonts (<code>\\windows\\fonts\\</code>), drivers (<code>\\windows\\system32\\drivers\\</code>), downloads, or Office add-ins. Broader paths (e.g. <code>\\appdata\\roaming\\</code>) would increase coverage but also false positives from legitimate software.</p>

    <h3>Temporal burst</h3>
    <p>Two views: (1) <b>Unusual file-creation spikes (Poisson)</b> — Time windows where the number of file creations is far above the expected rate; highlights possible mass creation (e.g. dropper, extractor). (2) <b>Activity pattern by directory (burstiness)</b> — For each directory, whether creation activity is <b>bursty</b> (many in short bursts—suspicious), <b>random</b> (normal), or <b>periodic</b> (regular intervals). Click <b>Refresh (compute in background)</b> to run the analysis in a background thread; progress is shown while computing.</p>

    <h3>Survival metrics</h3>
    <p>Focuses on <b>deleted files</b> and their <b>time to delete</b> (from creation to USN FILE_DELETE). <b>Requires USN Journal.</b> Table: MFT #, Name, Path, Created, Deleted, Time to delete. A <b>histogram</b> of short-lived files (&lt; 5 minutes) helps spot temporary or staged files that were quickly removed.</p>

    <h2>Kill Chain tab</h2>
    <p>Map files to the <b>Lockheed Martin Cyber Kill Chain</b> (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command &amp; Control, Actions on Objectives) for attack-lifecycle analysis. Right-click a file row in the <b>MFT</b>, <b>USN Journal</b>, <b>File System Tree</b>, or in <b>Analysis</b> sub-tabs that show MFT # (Extension change, Filename entropy, Survival metrics) and choose <b>Add to Kill Chain Phase</b> → select a phase. The file is added to that phase in the Kill Chain tab. In the tab, select a row to see full file details; right-click a row to remove it from the phase, move it to another phase, or jump to the MFT row. Kill chain assignments are saved and restored with the session.</p>

    <h2>Keyboard shortcuts</h2>
    <ul>
    <li><b>Ctrl+O</b> — Open $MFT</li>
    <li><b>Ctrl+S</b> — Save session</li>
    <li><b>Ctrl+L</b> — Load session</li>
    <li><b>Ctrl+Q</b> — Exit</li>
    <li><b>F1</b> — Application Help (this window)</li>
    </ul>

    <p class="tip"><b>Tip:</b> For the richest analysis, load both $MFT and $J when available. Many Analysis features (extension change, survival metrics, USN attribution in the tree) depend on the USN Journal. Session save/load preserves both paths so you can resume quickly.</p>
    </body></html>
    """


class ApplicationHelpDialog(QDialog):
    """Modal dialog showing application help: feature descriptions and usage."""
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Application Help")
        self.setMinimumSize(580, 520)
        self.resize(720, 640)
        layout = QVBoxLayout(self)
        browser = QTextBrowser(self)
        browser.setOpenExternalLinks(False)
        browser.setHtml(_application_help_html())
        layout.addWidget(browser)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)


class UsnJournalDialog(QDialog):
    """Dialog showing all USN Journal events with full reason; filter by reason. Optional MFT correlation by record # and file name."""
    def __init__(
        self,
        usn_records: list[UsnRecord],
        path_table: dict[int, str],
        parent: QWidget | None = None,
        *,
        rec_by_num: dict[int, MFTRecord] | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("USN Journal — All update reasons")
        self.setMinimumSize(900, 500)
        self.resize(1100, 600)
        self._all_records = usn_records
        self._path_table = path_table or {}
        self._rec_by_num = rec_by_num or {}
        self._sort_column = 0
        self._sort_order = Qt.SortOrder.DescendingOrder
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "All USN change journal events. CLOSE = handle closed (file was opened); FILE_CREATE / FILE_DELETE / RENAME_* / DATA_* etc. "
            "Filter by reason to focus on specific activity."
        ))
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter by reason:"))
        self._reason_combo = QComboBox()
        self._reason_combo.addItem("All reasons", None)
        for flag, name in USN_REASON_NAMES.items():
            self._reason_combo.addItem(name, flag)
        self._reason_combo.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self._reason_combo, 0)
        self._count_label = QLabel("")
        filter_row.addWidget(self._count_label, 1)
        layout.addLayout(filter_row)
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels([
            "Timestamp", "USN", "MFT #", "Filename", "Parent path", "Reason"
        ])
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.setSortingEnabled(False)
        self._table.horizontalHeader().setSortIndicatorShown(True)
        self._table.horizontalHeader().setSortIndicator(self._sort_column, self._sort_order)
        self._table.horizontalHeader().sectionClicked.connect(self._on_header_clicked)
        layout.addWidget(self._table)
        close_btn = QPushButton("Close")
        close_btn.setIcon(QApplication.instance().style().standardIcon(QStyle.StandardPixmap.SP_DialogCloseButton))
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        self._apply_filter()

    def _sort_key(self, rec: UsnRecord, parent_path: str, column: int):
        if column == 0:
            return int(rec.timestamp)
        if column == 1:
            return int(rec.usn)
        if column == 2:
            return int(rec.mft_record_number())
        if column == 3:
            return (rec.file_name or "").lower()
        if column == 4:
            return (parent_path or "\\").lower()
        if column == 5:
            return rec.reason_string().lower()
        return int(rec.timestamp)

    def _on_header_clicked(self, logical_index: int):
        if logical_index < 0 or logical_index >= 6:
            return
        if logical_index == self._sort_column:
            self._sort_order = (
                Qt.SortOrder.DescendingOrder
                if self._sort_order == Qt.SortOrder.AscendingOrder
                else Qt.SortOrder.AscendingOrder
            )
        else:
            self._sort_column = logical_index
            self._sort_order = Qt.SortOrder.AscendingOrder
        self._table.horizontalHeader().setSortIndicator(self._sort_column, self._sort_order)
        self._apply_filter()

    def _apply_filter(self):
        reason_filter = self._reason_combo.currentData()
        if reason_filter is None:
            rows = list(self._all_records)
        else:
            rows = [r for r in self._all_records if r.reason & reason_filter]
        reverse = self._sort_order == Qt.SortOrder.DescendingOrder
        display_limit = 100_000
        path_table = self._path_table or {}
        rec_by_num = self._rec_by_num or {}
        has_mft_loaded = bool(rec_by_num)
        no_path_hint = "(Load $MFT first to see path)" if not has_mft_loaded else None
        pairs = []
        for rec in rows:
            parent_path = parent_path_for_usn_record(rec, path_table, rec_by_num) if has_mft_loaded else no_path_hint
            pairs.append((rec, parent_path if parent_path else "\\"))
        pairs.sort(key=lambda rp: self._sort_key(rp[0], rp[1], self._sort_column), reverse=reverse)
        showing = pairs[:display_limit]
        self._table.setRowCount(len(showing))
        for row, (rec, parent_path) in enumerate(showing):
            row_items = _build_usn_row_items(rec, parent_path)
            _apply_row_risk_colors(row_items, _usn_row_risk_level(rec, parent_path))
            for col_idx, item in enumerate(row_items):
                self._table.setItem(row, col_idx, item)
        if len(rows) > display_limit:
            self._count_label.setText(f"Showing first {display_limit:,} of {len(rows):,} (filtered)")
        else:
            self._count_label.setText(f"{len(rows):,} events")


class MFTReaderMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MFT Reader — DFIR | $MFT & USN Journal")
        self.setMinimumSize(1100, 700)
        self.resize(1280, 800)
        self._records: list[MFTRecord] = []
        self._path_table: dict[int, str] = {}
        self._current_path: Path | None = None
        self._session_file_path: Path | None = None  # current session file (for Save)
        self._load_thread: LoadMFTThread | None = None
        self._progress: QProgressDialog | None = None
        self._usn_records: list[UsnRecord] = []
        self._usn_by_mft: dict[int, list[UsnRecord]] = {}
        self._usn_path: Path | None = None
        self._load_usn_thread: LoadUsnThread | None = None
        self._usn_refresh_id = 0
        self._usn_refresh_thread: UsnTableRefreshThread | None = None
        self._usn_full_parent_paths: list[str] = []
        self._usn_lazy_showing: list = []
        self._usn_lazy_parent_paths: list[str] = []
        self._usn_lazy_loaded_count = 0
        self._usn_lazy_loading = False
        self._usn_lazy_total_filtered = 0
        self._usn_anchor_ticks: int | None = None  # FILETIME for time anchor; None = no anchor
        self._usn_anchor_seconds = 30  # ± seconds around anchor for time window
        self._usn_sort_column = 0
        self._usn_sort_order = Qt.SortOrder.DescendingOrder
        self._fs_tree_data: FsTreeData | None = None
        self._fs_tree_rec_to_index: dict[int, int] = {}  # record_number -> index in _records
        self._fs_tree_populated = False
        self._kill_chain_entries: dict[str, list[int]] = {p: [] for p in KILL_CHAIN_PHASES}
        self._kill_chain_tab_index = -1  # set when tab is added
        self._report_tab_index = -1  # set when Analysis Report tab is added
        self._setup_ui()
        self._apply_style()

    def _setup_ui(self):
        # --- Application menu bar ---
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        open_mft_act = QAction("Open $MFT...", self)
        open_mft_act.setShortcut("Ctrl+O")
        open_mft_act.triggered.connect(self._on_open_mft)
        file_menu.addAction(open_mft_act)
        open_usn_act = QAction("Open $J (USN Journal)...", self)
        open_usn_act.triggered.connect(self._on_open_usn)
        file_menu.addAction(open_usn_act)
        file_menu.addSeparator()
        save_session_act = QAction("Save session...", self)
        save_session_act.setShortcut("Ctrl+S")
        save_session_act.setEnabled(False)
        save_session_act.triggered.connect(self._on_save_session)
        file_menu.addAction(save_session_act)
        self._menu_save_session_act = save_session_act
        save_session_as_act = QAction("Save session as...", self)
        save_session_as_act.setShortcut("Ctrl+Shift+S")
        save_session_as_act.setEnabled(False)
        save_session_as_act.triggered.connect(self._on_save_session_as)
        file_menu.addAction(save_session_as_act)
        self._menu_save_session_as_act = save_session_as_act
        load_session_act = QAction("Load session...", self)
        load_session_act.setShortcut("Ctrl+L")
        load_session_act.triggered.connect(self._on_load_session)
        file_menu.addAction(load_session_act)
        file_menu.addSeparator()
        export_csv_act = QAction("Export CSV...", self)
        export_csv_act.setEnabled(False)
        export_csv_act.triggered.connect(self._on_export_csv)
        file_menu.addAction(export_csv_act)
        self._menu_export_csv_act = export_csv_act
        file_menu.addSeparator()
        exit_act = QAction("E&xit", self)
        exit_act.setShortcut("Ctrl+Q")
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        help_menu = menubar.addMenu("&Help")
        help_act = QAction("Application &Help...", self)
        help_act.setShortcut("F1")
        help_act.triggered.connect(self._on_application_help)
        help_menu.addAction(help_act)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # --- Main tabs: MFT | USN Journal | Analysis ---
        self._main_tabs = QTabWidget()
        self._main_tabs.setDocumentMode(True)
        self._usn_tab_index = 1  # index of "USN Journal" tab; set before connect so handler can run on early signal
        self._main_tabs.currentChanged.connect(self._on_main_tab_changed)

        # ---- MFT tab ----
        mft_tab = QWidget()
        mft_layout = QVBoxLayout(mft_tab)
        mft_layout.setContentsMargins(0, 6, 0, 0)

        # Toolbar row (Open $MFT and Export CSV are in File menu)
        toolbar = QWidget()
        tlayout = QHBoxLayout(toolbar)
        tlayout.setContentsMargins(0, 0, 0, 6)

        self._btn_seq_report = QPushButton("Sequence gap report...")
        self._btn_seq_report.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
        self._btn_seq_report.setEnabled(False)
        self._btn_seq_report.setToolTip("List records with high sequence numbers (reused slots — graveyard for deleted files)")
        self._btn_seq_report.clicked.connect(self._on_sequence_gap_report)
        tlayout.addWidget(self._btn_seq_report)

        tlayout.addStretch()
        mft_layout.addWidget(toolbar)

        # Compound filter panel: drag column headers here or Add filter; drag rows to reorder
        self._mft_filter_panel = CompoundFilterPanel("mft", MFT_COLUMNS, copy_to_target="USN Journal")
        self._mft_filter_panel.filters_changed.connect(self._on_filter_changed)
        self._mft_filter_panel.copy_requested.connect(self._copy_mft_search_to_usn)
        mft_layout.addWidget(self._mft_filter_panel)

        # Time anchor bar (only shown in MFT/USN tabs; reparented on tab change)
        self._time_anchor_row = self._build_time_anchor_row()
        self._mft_tab = mft_tab
        mft_layout.insertWidget(2, self._time_anchor_row)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Table: QAbstractTableModel reports full row count; Qt only calls data() for
        # visible rows (~20-50), so scrolling through millions of records is fast.
        self._mft_model = MFTTableModel(self)
        self._table = QTableView()
        self._table.setModel(self._mft_model)
        make_header_draggable(self._table, "mft", MFTTableModel.COLUMNS)
        self._mft_row_drag_filter = TableRowDragFilter(
            self._table, "mft",
            lambda r, c: str(self._mft_model.data(self._mft_model.index(r, c), Qt.ItemDataRole.DisplayRole) or ""),
        )
        self._table.viewport().installEventFilter(self._mft_row_drag_filter)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        _MFT_COL_WIDTHS = {
            0: 68,   # MFT #
            3: 72,   # Type
            4: 88,   # Size
            5: 172,  # Created
            6: 172,  # Modified
            7: 172,  # MFT Modified
            8: 172,  # Accessed
            9: 172,  # FN Created
            10: 180, # SI vs FN
            11: 60,  # Seq
            12: 88,  # Δ C→M
            13: 96,  # Δ C→MFT
            14: 88,  # Δ M→Del
        }
        for col, w in _MFT_COL_WIDTHS.items():
            self._table.setColumnWidth(col, w)
        for col in MFTTableModel.DEFAULT_HIDDEN:
            self._table.setColumnHidden(col, True)
        hdr.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        hdr.customContextMenuRequested.connect(self._on_mft_header_context_menu)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(False)
        self._table.setSortingEnabled(True)
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        self._table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self._table.setWordWrap(False)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_table_context_menu)
        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self._table.verticalHeader().setDefaultSectionSize(24)
        splitter.addWidget(self._table)

        # Detail panel (tabs: Summary, Attributes, Hex)
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 4, 0, 0)
        detail_label = QLabel("Record details")
        detail_layout.addWidget(detail_label)
        self._detail_tabs = QTabWidget()
        self._detail_summary = QTextEdit()
        self._detail_summary.setReadOnly(True)
        self._detail_attrs = QTextEdit()
        self._detail_attrs.setReadOnly(True)
        self._detail_hex = QTextEdit()
        self._detail_hex.setReadOnly(True)
        self._detail_tabs.addTab(self._detail_summary, "Summary")
        self._detail_tabs.addTab(self._detail_attrs, "Attributes")
        self._detail_tabs.addTab(self._detail_hex, "Raw record (hex)")
        detail_layout.addWidget(self._detail_tabs)
        splitter.addWidget(detail_widget)
        splitter.setSizes([400, 280])

        mft_layout.addWidget(splitter, 1)
        self._main_tabs.addTab(mft_tab, "MFT")

        # ---- USN Journal tab ----
        usn_tab = QWidget()
        usn_layout = QVBoxLayout(usn_tab)
        usn_layout.setContentsMargins(0, 6, 0, 0)

        # Toolbar row (Open $J is in File menu)
        usn_toolbar = QWidget()
        usn_tlayout = QHBoxLayout(usn_toolbar)
        usn_tlayout.setContentsMargins(0, 0, 0, 6)
        self._btn_usn_report = QPushButton("Open in dialog (filter by reason)...")
        self._btn_usn_report.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
        self._btn_usn_report.setEnabled(False)
        self._btn_usn_report.setToolTip("All update reasons; filter in dialog")
        self._btn_usn_report.clicked.connect(self._on_usn_report)
        usn_tlayout.addWidget(self._btn_usn_report)
        self._usn_count_label = QLabel("")
        usn_tlayout.addWidget(self._usn_count_label, 1)
        usn_layout.addWidget(usn_toolbar)

        # Compound filter panel (same as MFT tab)
        self._usn_filter_panel = CompoundFilterPanel("usn", USN_COLUMNS, copy_to_target="MFT")
        self._usn_filter_panel.filters_changed.connect(self._on_usn_tab_filter)
        self._usn_filter_panel.copy_requested.connect(self._copy_usn_search_to_mft)
        usn_layout.addWidget(self._usn_filter_panel)

        self._usn_tab = usn_tab

        usn_splitter = QSplitter(Qt.Orientation.Vertical)
        self._usn_table = QTableWidget()
        self._usn_table.setColumnCount(6)
        self._usn_table.setHorizontalHeaderLabels(["Timestamp", "USN", "MFT #", "Filename", "Parent path", "Reason"])
        make_header_draggable(self._usn_table, "usn", ["Timestamp", "USN", "MFT #", "Filename", "Parent path", "Reason"])
        self._usn_row_drag_filter = TableRowDragFilter(
            self._usn_table, "usn",
            lambda r, c: (self._usn_table.item(r, c).text() if self._usn_table.item(r, c) else ""),
        )
        self._usn_table.viewport().installEventFilter(self._usn_row_drag_filter)
        self._usn_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._usn_table.setWordWrap(True)
        self._usn_table.setSortingEnabled(False)  # sort manually on backing data to keep lazy loading correct
        self._usn_table.horizontalHeader().setSortIndicatorShown(True)
        self._usn_table.horizontalHeader().setSortIndicator(self._usn_sort_column, self._usn_sort_order)
        self._usn_table.horizontalHeader().sectionClicked.connect(self._on_usn_header_clicked)
        self._usn_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._usn_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._usn_table.customContextMenuRequested.connect(self._on_usn_table_context_menu)
        usn_splitter.addWidget(self._usn_table)
        usn_layout.addWidget(usn_splitter, 1)
        self._main_tabs.addTab(usn_tab, "USN Journal")
        self._fs_tree_tab_index = 2
        self._stats_tab_index = 3

        # ---- File System Tree tab (MFT + USN attribution for forensic triage) ----
        fs_tree_tab = QWidget()
        fs_tree_layout = QVBoxLayout(fs_tree_tab)
        fs_tree_layout.setContentsMargins(0, 6, 0, 0)
        fs_tree_hint = QLabel(
            "Reconstructed file system tree from $MFT and path table; enriched with USN Journal activity. "
            "Use attribution columns to spot suspicious paths, executables, timestomping, and high USN activity."
        )
        fs_tree_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        fs_tree_hint.setWordWrap(True)
        fs_tree_layout.addWidget(fs_tree_hint)
        fs_tree_toolbar = QWidget()
        fs_tree_toolbar_layout = QHBoxLayout(fs_tree_toolbar)
        fs_tree_toolbar_layout.setContentsMargins(0, 4, 0, 4)
        self._btn_rebuild_fs_tree = QPushButton("Rebuild file system tree")
        self._btn_rebuild_fs_tree.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self._btn_rebuild_fs_tree.setToolTip("Build tree from loaded $MFT (and $J if loaded). Run after loading to avoid slowing initial load.")
        self._btn_rebuild_fs_tree.setEnabled(False)
        self._btn_rebuild_fs_tree.clicked.connect(self._on_rebuild_fs_tree)
        fs_tree_toolbar_layout.addWidget(self._btn_rebuild_fs_tree)
        fs_tree_toolbar_layout.addStretch()
        fs_tree_layout.addWidget(fs_tree_toolbar)
        self._fs_tree_widget = QTreeWidget()
        _fs_tree_cols = [
            "Name", "MFT #", "Type", "Size", "Created", "Modified", "Seq", "In use",
            "Timestomp?", "High seq?", "Suspicious path?", "Executable?",
            "USN Create", "USN Delete", "USN Rename", "USN Data",
        ]
        self._fs_tree_widget.setColumnCount(len(_fs_tree_cols))
        self._fs_tree_widget.setHeaderLabels(_fs_tree_cols)
        self._fs_tree_widget.setAlternatingRowColors(True)
        self._fs_tree_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._fs_tree_widget.customContextMenuRequested.connect(self._on_fs_tree_context_menu)
        self._fs_tree_widget.itemExpanded.connect(self._on_fs_tree_item_expanded)
        fs_tree_header = self._fs_tree_widget.header()
        fs_tree_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        fs_tree_header.setStretchLastSection(False)
        fs_tree_layout.addWidget(self._fs_tree_widget, 1)
        self._main_tabs.addTab(fs_tree_tab, "File System Tree")

        # ---- Analysis tab (sub-tabs: Anomaly sequences | Survival metrics) ----
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        stats_layout.setContentsMargins(0, 6, 0, 0)
        stats_layout.setSpacing(8)

        stats_header = QLabel("Forensic investigation leads")
        stats_header.setStyleSheet("font-size: 11pt; color: #89b4fa; font-weight: bold;")
        stats_layout.addWidget(stats_header)
        stats_hint = QLabel(
            "Suspicious anomaly sequences and file survival metrics from the full MFT/USN dataset (independent of filters)."
        )
        stats_hint.setStyleSheet("color: #9399b2;")
        stats_layout.addWidget(stats_hint)

        self._stats_sub_tabs = QTabWidget()
        self._stats_sub_tabs.setDocumentMode(True)

        # ---- Anomaly sequences sub-tab ----
        _anomaly_cols = ["Score", "Risk", "Start", "End", "Path", "Pattern"]
        anomaly_tab = QWidget()
        anomaly_layout = QVBoxLayout(anomaly_tab)
        anomaly_layout.setContentsMargins(0, 4, 0, 0)
        anomaly_header = QWidget()
        anomaly_header_layout = QHBoxLayout(anomaly_header)
        anomaly_header_layout.setContentsMargins(0, 0, 0, 4)
        anomaly_header_layout.addWidget(QLabel("Anomaly sequences (MFT + USN)"))
        anomaly_header_layout.addStretch()
        self._anomaly_refresh_btn = QPushButton("Refresh")
        self._anomaly_refresh_btn.setToolTip("Recompute anomaly sequence detection from MFT + USN Journal.")
        self._anomaly_refresh_btn.clicked.connect(self._refresh_anomaly_sequences)
        anomaly_header_layout.addWidget(self._anomaly_refresh_btn)
        anomaly_layout.addWidget(anomaly_header)
        self._anomaly_filter = CollapsibleStatsFilter("stat_anomaly", ANOMALY_SEQ_COLUMNS)
        self._anomaly_filter.filters_changed.connect(self._apply_anomaly_filter)
        anomaly_layout.addWidget(self._anomaly_filter)
        anomaly_splitter = QSplitter(Qt.Orientation.Vertical)
        self._stats_sequence_table = QTableWidget()
        self._stats_sequence_table.setColumnCount(6)
        self._stats_sequence_table.setHorizontalHeaderLabels(_anomaly_cols)
        make_header_draggable(self._stats_sequence_table, "stat_anomaly", _anomaly_cols)
        self._stats_sequence_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._stats_sequence_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._stats_sequence_table.verticalHeader().setVisible(False)
        self._stats_sequence_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._stats_sequence_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._stats_sequence_table.setSortingEnabled(True)
        self._stats_sequence_table.setWordWrap(True)
        self._stats_sequence_table.setTextElideMode(Qt.TextElideMode.ElideNone)
        self._stats_sequence_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._stats_sequence_table.selectionModel().selectionChanged.connect(self._on_anomaly_selection_changed)
        self._anomaly_drag = TableRowDragFilter(
            self._stats_sequence_table, "stat_anomaly",
            lambda r, c: (self._stats_sequence_table.item(r, c).text() if self._stats_sequence_table.item(r, c) else ""),
        )
        self._stats_sequence_table.viewport().installEventFilter(self._anomaly_drag)
        anomaly_splitter.addWidget(self._stats_sequence_table)
        anomaly_detail_widget = QWidget()
        anomaly_detail_layout = QVBoxLayout(anomaly_detail_widget)
        anomaly_detail_layout.setContentsMargins(0, 4, 0, 0)
        anomaly_detail_layout.addWidget(QLabel("Narrative / Evidence"))
        self._anomaly_detail_text = QTextEdit()
        self._anomaly_detail_text.setReadOnly(True)
        self._anomaly_detail_text.setPlaceholderText("Select a row to view narrative (chains) or evidence (single findings).")
        anomaly_detail_layout.addWidget(self._anomaly_detail_text)
        anomaly_splitter.addWidget(anomaly_detail_widget)
        anomaly_splitter.setSizes([350, 200])
        anomaly_layout.addWidget(anomaly_splitter, 2)
        self._anomaly_seq_raw_data: list[tuple[list[str], str]] = []
        self._anomaly_seq_detail_data: list[AttackChain | SequenceFinding] = []
        self._stats_sub_tabs.addTab(anomaly_tab, "Anomaly sequences")

        # ---- Extension change sub-tab (rename where extension changed, e.g. .txt→.exe) ----
        _ext_chg_cols = ["MFT #", "Old name", "New name", "Ext change", "Timestamp", "Parent path"]
        ext_change_tab = QWidget()
        ext_change_layout = QVBoxLayout(ext_change_tab)
        ext_change_layout.setContentsMargins(0, 4, 0, 0)
        ext_change_hint = QLabel(
            "Renames where the file extension changed (e.g. .exe\u2192.dll, .txt\u2192.exe). Requires USN Journal with rename events. "
            "Rows where extension changed executable\u2194any are highlighted with a thick box."
        )
        ext_change_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        ext_change_hint.setWordWrap(True)
        ext_change_layout.addWidget(ext_change_hint)
        exec_swap_legend = QHBoxLayout()
        exec_swap_legend.addWidget(QLabel("Exec↔any:"))
        exec_swap_legend.addWidget(_make_risk_legend_chip("executable ↔ non-executable", _EXEC_SWAP_HIGHLIGHT[0], _EXEC_SWAP_HIGHLIGHT[1]))
        self._ext_change_only_highlight_cb = QCheckBox("Show only highlighted (Exec↔any)")
        self._ext_change_only_highlight_cb.setChecked(False)
        self._ext_change_only_highlight_cb.stateChanged.connect(lambda: self._apply_ext_change_filter())
        exec_swap_legend.addWidget(self._ext_change_only_highlight_cb)
        exec_swap_legend.addStretch()
        ext_change_layout.addLayout(exec_swap_legend)
        self._ext_change_filter = CollapsibleStatsFilter("stat_ext_change", EXT_CHANGE_COLUMNS)
        self._ext_change_filter.filters_changed.connect(self._apply_ext_change_filter)
        ext_change_layout.addWidget(self._ext_change_filter)
        self._stats_extension_change_table = QTableWidget()
        self._stats_extension_change_table.setColumnCount(6)
        self._stats_extension_change_table.setHorizontalHeaderLabels(_ext_chg_cols)
        make_header_draggable(self._stats_extension_change_table, "stat_ext_change", _ext_chg_cols)
        self._stats_extension_change_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._stats_extension_change_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._stats_extension_change_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._stats_extension_change_table.verticalHeader().setVisible(False)
        self._stats_extension_change_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._stats_extension_change_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._stats_extension_change_table.setSortingEnabled(True)
        self._ext_change_drag = TableRowDragFilter(
            self._stats_extension_change_table, "stat_ext_change",
            lambda r, c: (self._stats_extension_change_table.item(r, c).text() if self._stats_extension_change_table.item(r, c) else ""),
        )
        self._stats_extension_change_table.viewport().installEventFilter(self._ext_change_drag)
        self._stats_extension_change_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._stats_extension_change_table.customContextMenuRequested.connect(
            lambda pos: self._on_analysis_table_kill_chain_menu(pos, self._stats_extension_change_table, 0)
        )
        self._stats_extension_change_table.setItemDelegate(ExecSwapHighlightDelegate())
        ext_change_layout.addWidget(self._stats_extension_change_table, 1)
        self._ext_change_raw_data: list[tuple[list[str], bool]] = []
        self._stats_sub_tabs.addTab(ext_change_tab, "Extension change")

        # ---- Entropy / novelty sub-tab (filename entropy, extension entropy per directory) ----
        _fn_ent_cols = ["Entropy", "Filename", "Parent path", "MFT #"]
        _ext_ent_cols = ["Directory", "Ext. entropy", "Files", "Distinct ext."]
        entropy_tab = QWidget()
        entropy_layout = QVBoxLayout(entropy_tab)
        entropy_layout.setContentsMargins(0, 4, 0, 0)
        entropy_hint = QLabel(
            "Filename entropy (Shannon) highlights random-looking names. Extension entropy per directory shows diversity of file types per folder."
        )
        entropy_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        entropy_hint.setWordWrap(True)
        entropy_layout.addWidget(entropy_hint)
        entropy_layout.addWidget(QLabel("High filename entropy (random-looking names)"))
        self._filename_entropy_filter = CollapsibleStatsFilter("stat_fn_entropy", FILENAME_ENTROPY_COLUMNS)
        self._filename_entropy_filter.filters_changed.connect(self._apply_filename_entropy_filter)
        entropy_layout.addWidget(self._filename_entropy_filter)
        self._stats_filename_entropy_table = QTableWidget()
        self._stats_filename_entropy_table.setColumnCount(4)
        self._stats_filename_entropy_table.setHorizontalHeaderLabels(_fn_ent_cols)
        make_header_draggable(self._stats_filename_entropy_table, "stat_fn_entropy", _fn_ent_cols)
        self._stats_filename_entropy_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._stats_filename_entropy_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._stats_filename_entropy_table.verticalHeader().setVisible(False)
        self._stats_filename_entropy_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._stats_filename_entropy_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._stats_filename_entropy_table.setSortingEnabled(True)
        self._fn_entropy_drag = TableRowDragFilter(
            self._stats_filename_entropy_table, "stat_fn_entropy",
            lambda r, c: (self._stats_filename_entropy_table.item(r, c).text() if self._stats_filename_entropy_table.item(r, c) else ""),
        )
        self._stats_filename_entropy_table.viewport().installEventFilter(self._fn_entropy_drag)
        self._stats_filename_entropy_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._stats_filename_entropy_table.customContextMenuRequested.connect(
            lambda pos: self._on_analysis_table_kill_chain_menu(pos, self._stats_filename_entropy_table, 3)
        )
        entropy_layout.addWidget(self._stats_filename_entropy_table, 1)
        self._filename_entropy_raw_data: list[list[str]] = []
        entropy_layout.addWidget(QLabel("Extension entropy per directory"))
        self._ext_entropy_filter = CollapsibleStatsFilter("stat_ext_entropy", EXT_ENTROPY_COLUMNS)
        self._ext_entropy_filter.filters_changed.connect(self._apply_ext_entropy_filter)
        entropy_layout.addWidget(self._ext_entropy_filter)
        self._stats_ext_entropy_table = QTableWidget()
        self._stats_ext_entropy_table.setColumnCount(4)
        self._stats_ext_entropy_table.setHorizontalHeaderLabels(_ext_ent_cols)
        make_header_draggable(self._stats_ext_entropy_table, "stat_ext_entropy", _ext_ent_cols)
        self._stats_ext_entropy_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._stats_ext_entropy_table.verticalHeader().setVisible(False)
        self._stats_ext_entropy_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._stats_ext_entropy_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._stats_ext_entropy_table.setSortingEnabled(True)
        self._ext_entropy_drag = TableRowDragFilter(
            self._stats_ext_entropy_table, "stat_ext_entropy",
            lambda r, c: (self._stats_ext_entropy_table.item(r, c).text() if self._stats_ext_entropy_table.item(r, c) else ""),
        )
        self._stats_ext_entropy_table.viewport().installEventFilter(self._ext_entropy_drag)
        entropy_layout.addWidget(self._stats_ext_entropy_table, 1)
        self._ext_entropy_raw_data: list[list[str]] = []
        self._stats_sub_tabs.addTab(entropy_tab, "Entropy / novelty")

        # ---- Directory churn sub-tab (dropper / staging detection) ----
        churn_tab = QWidget()
        churn_layout = QVBoxLayout(churn_tab)
        churn_layout.setContentsMargins(0, 4, 0, 0)
        churn_hint = QLabel(
            "Directories where many files were created in a short burst (configurable window). "
            "May indicate dropper extraction, payload staging, or persistence installation. "
            "First/Last file = timestamps of the first and last file in the burst; Duration is always ≤ your window."
        )
        churn_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        churn_hint.setWordWrap(True)
        churn_layout.addWidget(churn_hint)

        churn_controls = QHBoxLayout()
        churn_controls.addWidget(QLabel("Window (seconds):"))
        self._churn_window_edit = QLineEdit("120")
        self._churn_window_edit.setFixedWidth(70)
        self._churn_window_edit.setToolTip("Time window in seconds (5\u20133600). Type a value and press Refresh.")
        self._churn_window_edit.setValidator(QIntValidator(5, 3600))
        self._churn_window_edit.textChanged.connect(self._update_churn_minutes_label)
        churn_controls.addWidget(self._churn_window_edit)
        self._churn_minutes_label = QLabel("(2.00 min)")
        self._churn_minutes_label.setStyleSheet("color: #9399b2; font-size: 9pt; min-width: 70px;")
        churn_controls.addWidget(self._churn_minutes_label)
        churn_controls.addWidget(QLabel("Min files:"))
        self._churn_min_files_spin = QSpinBox()
        self._churn_min_files_spin.setRange(2, 100)
        self._churn_min_files_spin.setValue(3)
        self._churn_min_files_spin.setToolTip("Minimum number of files created in the window to flag the directory")
        churn_controls.addWidget(self._churn_min_files_spin)
        self._churn_refresh_btn = QPushButton("Refresh")
        self._churn_refresh_btn.clicked.connect(self._refresh_statistics_tab)
        churn_controls.addWidget(self._churn_refresh_btn)
        churn_controls.addStretch()
        churn_layout.addLayout(churn_controls)

        self._churn_summary_label = QLabel("")
        self._churn_summary_label.setStyleSheet("color: #a6e3a1;")
        churn_layout.addWidget(self._churn_summary_label)

        _churn_cols = ["Directory", "Files", "First file (burst)", "Last file (burst)", "Duration (s) ≤ window", "Executable?", "Persistence?", "Files in burst"]
        self._churn_filter = CollapsibleStatsFilter("stat_churn", CHURN_COLUMNS)
        self._churn_filter.filters_changed.connect(self._apply_churn_filter)
        churn_layout.addWidget(self._churn_filter)

        self._churn_table = QTableWidget()
        self._churn_table.setColumnCount(8)
        self._churn_table.setHorizontalHeaderLabels(_churn_cols)
        make_header_draggable(self._churn_table, "stat_churn", _churn_cols)
        self._churn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._churn_table.horizontalHeader().setStretchLastSection(True)
        self._churn_table.verticalHeader().setVisible(False)
        self._churn_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._churn_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._churn_table.setSortingEnabled(True)
        self._churn_table.cellDoubleClicked.connect(self._on_churn_table_double_click)
        self._churn_drag = TableRowDragFilter(
            self._churn_table, "stat_churn",
            lambda r, c: (self._churn_table.item(r, c).text() if self._churn_table.item(r, c) else ""),
        )
        self._churn_table.viewport().installEventFilter(self._churn_drag)
        self._churn_report_data: list[DirectoryChurnEntry] = []
        self._churn_raw_data: list[tuple[list[str], str]] = []
        churn_layout.addWidget(self._churn_table, 1)
        self._stats_sub_tabs.addTab(churn_tab, "Directory churn")

        # ---- Temporal burst sub-tab (Poisson + burstiness B) ----
        temporal_burst_tab = QWidget()
        tb_layout = QVBoxLayout(temporal_burst_tab)
        tb_layout.setContentsMargins(0, 4, 0, 0)
        tb_hint = QLabel(
            "Spike detection: (1) Time windows where many more files were created than usual (possible dropper or mass activity). "
            "(2) Per-directory activity pattern: bursty = many files in short bursts (suspicious), random = normal, periodic = regular intervals."
        )
        tb_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        tb_hint.setWordWrap(True)
        tb_layout.addWidget(tb_hint)
        self._temporal_burst_summary_label = QLabel("")
        self._temporal_burst_summary_label.setStyleSheet("color: #a6e3a1;")
        tb_layout.addWidget(self._temporal_burst_summary_label)

        self._temporal_burst_progress_bar = QProgressBar()
        self._temporal_burst_progress_bar.setRange(0, 100)
        self._temporal_burst_progress_bar.setValue(0)
        self._temporal_burst_progress_bar.setVisible(False)
        self._temporal_burst_progress_bar.setFixedHeight(6)
        self._temporal_burst_progress_bar.setTextVisible(False)
        tb_layout.addWidget(self._temporal_burst_progress_bar)

        self._temporal_burst_progress_timer = QTimer(self)
        self._temporal_burst_progress_timer.setInterval(120)
        self._temporal_burst_progress_timer.timeout.connect(self._on_temporal_burst_progress_tick)

        tb_controls = QHBoxLayout()
        self._temporal_burst_refresh_btn = QPushButton("Refresh (compute in background)")
        self._temporal_burst_refresh_btn.setToolTip("Run temporal burst detection in a background thread. Does not block MFT load.")
        self._temporal_burst_refresh_btn.clicked.connect(self._start_temporal_burst_computation)
        tb_controls.addWidget(self._temporal_burst_refresh_btn)
        tb_controls.addStretch()
        tb_layout.addLayout(tb_controls)

        tb_layout.addWidget(QLabel("Unusual file-creation spikes (time windows with far more activity than normal)"))
        self._temporal_burst_poisson_filter = CollapsibleStatsFilter("stat_tb_poisson", TEMPORAL_BURST_POISSON_COLUMNS)
        self._temporal_burst_poisson_filter.filters_changed.connect(self._apply_temporal_burst_poisson_filter)
        tb_layout.addWidget(self._temporal_burst_poisson_filter)
        _tb_poisson_cols = [c[1] for c in TEMPORAL_BURST_POISSON_COLUMNS]
        self._temporal_burst_poisson_table = QTableWidget()
        self._temporal_burst_poisson_table.setColumnCount(len(_tb_poisson_cols))
        self._temporal_burst_poisson_table.setHorizontalHeaderLabels(_tb_poisson_cols)
        make_header_draggable(self._temporal_burst_poisson_table, "stat_tb_poisson", _tb_poisson_cols)
        self._temporal_burst_poisson_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._temporal_burst_poisson_table.horizontalHeader().setStretchLastSection(True)
        self._temporal_burst_poisson_table.verticalHeader().setVisible(False)
        self._temporal_burst_poisson_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._temporal_burst_poisson_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._temporal_burst_poisson_table.setSortingEnabled(True)
        tb_layout.addWidget(self._temporal_burst_poisson_table)

        tb_layout.addWidget(QLabel("Activity pattern by directory (bursty = suspicious, random = normal, periodic = regular)"))
        self._temporal_burst_burstiness_filter = CollapsibleStatsFilter("stat_tb_burstiness", TEMPORAL_BURST_BURSTINESS_COLUMNS)
        self._temporal_burst_burstiness_filter.filters_changed.connect(self._apply_temporal_burst_burstiness_filter)
        tb_layout.addWidget(self._temporal_burst_burstiness_filter)
        _tb_burst_cols = [c[1] for c in TEMPORAL_BURST_BURSTINESS_COLUMNS]
        self._temporal_burst_burstiness_table = QTableWidget()
        self._temporal_burst_burstiness_table.setColumnCount(len(_tb_burst_cols))
        self._temporal_burst_burstiness_table.setHorizontalHeaderLabels(_tb_burst_cols)
        make_header_draggable(self._temporal_burst_burstiness_table, "stat_tb_burstiness", _tb_burst_cols)
        self._temporal_burst_burstiness_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._temporal_burst_burstiness_table.horizontalHeader().setStretchLastSection(True)
        self._temporal_burst_burstiness_table.verticalHeader().setVisible(False)
        self._temporal_burst_burstiness_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._temporal_burst_burstiness_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._temporal_burst_burstiness_table.setSortingEnabled(True)
        tb_layout.addWidget(self._temporal_burst_burstiness_table, 1)
        self._temporal_burst_poisson_raw_data: list[list[str]] = []
        self._temporal_burst_burstiness_raw_data: list[list[str]] = []
        self._temporal_burst_computed = False
        self._temporal_burst_thread: TemporalBurstThread | None = None
        self._temporal_burst_tab_index = self._stats_sub_tabs.addTab(temporal_burst_tab, "Temporal burst")

        # ---- Survival metrics sub-tab ----
        survival_tab = QWidget()
        survival_layout = QVBoxLayout(survival_tab)
        survival_layout.setContentsMargins(0, 4, 0, 0)
        survival_hint = QLabel(
            "Time-to-delete for deleted files (create \u2192 USN delete). Histogram: short-lived files (&lt; 5 minutes)."
        )
        survival_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        survival_hint.setWordWrap(True)
        survival_layout.addWidget(survival_hint)
        self._survival_summary_label = QLabel("")
        self._survival_summary_label.setStyleSheet("color: #a6e3a1;")
        survival_layout.addWidget(self._survival_summary_label)
        survival_layout.addWidget(QLabel("Deleted files with known time to delete"))
        _surv_cols = ["MFT #", "Name", "Path", "Created", "Deleted", "Time to delete"]
        self._survival_filter = CollapsibleStatsFilter("stat_survival", SURVIVAL_COLUMNS)
        self._survival_filter.filters_changed.connect(self._apply_survival_filter)
        survival_layout.addWidget(self._survival_filter)
        self._survival_table = QTableWidget()
        self._survival_table.setColumnCount(6)
        self._survival_table.setHorizontalHeaderLabels(_surv_cols)
        make_header_draggable(self._survival_table, "stat_survival", _surv_cols)
        self._survival_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._survival_table.verticalHeader().setVisible(False)
        self._survival_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._survival_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._survival_table.setSortingEnabled(True)
        self._survival_drag = TableRowDragFilter(
            self._survival_table, "stat_survival",
            lambda r, c: (self._survival_table.item(r, c).text() if self._survival_table.item(r, c) else ""),
        )
        self._survival_table.viewport().installEventFilter(self._survival_drag)
        self._survival_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._survival_table.customContextMenuRequested.connect(
            lambda pos: self._on_analysis_table_kill_chain_menu(pos, self._survival_table, 0)
        )
        survival_layout.addWidget(self._survival_table, 1)
        self._survival_raw_data: list[list[str]] = []
        self._survival_histogram_label = QLabel("Short-lived files (&lt; 5 min) \u2014 histogram")
        survival_layout.addWidget(self._survival_histogram_label)
        self._survival_histogram_table = QTableWidget()
        self._survival_histogram_table.setColumnCount(3)
        self._survival_histogram_table.setHorizontalHeaderLabels(["Lifespan bucket", "Count", "Bar"])
        self._survival_histogram_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._survival_histogram_table.verticalHeader().setVisible(False)
        self._survival_histogram_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._survival_histogram_table.setSortingEnabled(True)
        survival_layout.addWidget(self._survival_histogram_table, 1)
        self._stats_sub_tabs.addTab(survival_tab, "Survival metrics")
        self._stats_sub_tabs.currentChanged.connect(self._on_stats_sub_tab_changed)
        stats_layout.addWidget(self._stats_sub_tabs, 1)
        self._main_tabs.addTab(stats_tab, "Analysis")

        # ---- Kill Chain tab (Cyber Kill Chain phases) ----
        kill_chain_tab = QWidget()
        kill_chain_layout = QVBoxLayout(kill_chain_tab)
        kill_chain_layout.setContentsMargins(0, 6, 0, 0)
        kill_chain_hint = QLabel(
            "Map files to the Lockheed Martin Cyber Kill Chain. Right-click a file in MFT, USN Journal, "
            "File System Tree, or Analysis tables and choose \"Add to Kill Chain Phase\" → phase."
        )
        kill_chain_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        kill_chain_hint.setWordWrap(True)
        kill_chain_layout.addWidget(kill_chain_hint)
        kill_chain_scroll = QScrollArea()
        kill_chain_scroll.setWidgetResizable(True)
        kill_chain_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        kill_chain_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        kill_chain_scroll_content = QWidget()
        kill_chain_scroll_layout = QHBoxLayout(kill_chain_scroll_content)
        kill_chain_scroll_layout.setContentsMargins(4, 4, 4, 4)
        kill_chain_scroll_layout.setSpacing(8)
        self._kill_chain_tables: dict[str, QTableWidget] = {}
        _kc_cols = ["Filename"]
        for phase in KILL_CHAIN_PHASES:
            gb = QGroupBox(phase)
            tbl = QTableWidget()
            tbl.setColumnCount(1)
            tbl.setHorizontalHeaderLabels(_kc_cols)
            tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            tbl.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            tbl.customContextMenuRequested.connect(lambda pos, t=tbl, ph=phase: self._on_kill_chain_table_context_menu(pos, t, ph))
            tbl.selectionModel().selectionChanged.connect(self._on_kill_chain_selection_changed)
            gb_layout = QVBoxLayout(gb)
            # Add extra top margin so the group box title does not overlap the table header.
            gb_layout.setContentsMargins(6, 24, 6, 6)
            gb_layout.addWidget(tbl)
            kill_chain_scroll_layout.addWidget(gb)
            self._kill_chain_tables[phase] = tbl
        kill_chain_scroll.setWidget(kill_chain_scroll_content)
        kill_chain_layout.addWidget(kill_chain_scroll, 1)
        detail_panel = QWidget()
        detail_panel_layout = QVBoxLayout(detail_panel)
        detail_panel_layout.setContentsMargins(0, 4, 0, 0)
        detail_panel_layout.addWidget(QLabel("File details (select a row above)"))
        self._kill_chain_detail_tabs = QTabWidget()
        self._kill_chain_detail_summary = QTableWidget()
        self._kill_chain_detail_summary.setColumnCount(2)
        self._kill_chain_detail_summary.setHorizontalHeaderLabels(["Field", "Value"])
        self._kill_chain_detail_summary.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._kill_chain_detail_summary.verticalHeader().setVisible(False)
        self._kill_chain_detail_summary.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._kill_chain_detail_summary.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self._kill_chain_detail_summary.setWordWrap(True)

        self._kill_chain_detail_attrs = QTableWidget()
        self._kill_chain_detail_attrs.setColumnCount(4)
        self._kill_chain_detail_attrs.setHorizontalHeaderLabels(["Type", "Name", "Resident", "Length"])
        self._kill_chain_detail_attrs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._kill_chain_detail_attrs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._kill_chain_detail_attrs.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._kill_chain_detail_attrs.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._kill_chain_detail_attrs.verticalHeader().setVisible(False)
        self._kill_chain_detail_attrs.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._kill_chain_detail_attrs.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self._kill_chain_detail_attrs.setWordWrap(True)

        self._kill_chain_detail_hex = QTextEdit()
        self._kill_chain_detail_hex.setReadOnly(True)
        self._kill_chain_detail_tabs.addTab(self._kill_chain_detail_summary, "Summary")
        self._kill_chain_detail_tabs.addTab(self._kill_chain_detail_attrs, "Attributes")
        self._kill_chain_detail_tabs.addTab(self._kill_chain_detail_hex, "Raw record (hex)")
        detail_panel_layout.addWidget(self._kill_chain_detail_tabs)
        kill_chain_layout.addWidget(detail_panel)
        self._kill_chain_tab_index = self._main_tabs.addTab(kill_chain_tab, "Kill Chain")
        # ---- Analysis Report tab (textual DFIR summary) ----
        report_tab = QWidget()
        report_layout = QVBoxLayout(report_tab)
        report_layout.setContentsMargins(0, 6, 0, 0)
        report_layout.setSpacing(6)

        report_header = QLabel("Forensic analysis report (MFT, USN, Kill Chain)")
        report_header.setStyleSheet("font-size: 11pt; color: #89b4fa; font-weight: bold;")
        report_layout.addWidget(report_header)

        report_hint = QLabel(
            "Textual report combining Analysis tab findings and Kill Chain assignments. "
            "Click \"Refresh report\" after updating Analysis or Kill Chain."
        )
        report_hint.setStyleSheet("color: #9399b2; font-size: 9pt;")
        report_hint.setWordWrap(True)
        report_layout.addWidget(report_hint)

        report_btn_row = QHBoxLayout()
        self._btn_refresh_report = QPushButton("Refresh report")
        self._btn_refresh_report.clicked.connect(self._refresh_analysis_report)
        report_btn_row.addWidget(self._btn_refresh_report)
        report_btn_row.addStretch()
        report_layout.addLayout(report_btn_row)

        self._report_text = QTextEdit()
        self._report_text.setReadOnly(True)
        self._report_text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        report_layout.addWidget(self._report_text, 1)
        self._report_tab_index = self._main_tabs.addTab(report_tab, "Analysis Report")

        layout.addWidget(self._main_tabs, 1)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready. Open $MFT to begin; add $J for USN timeline.")

    def _build_time_anchor_row(self) -> QWidget:
        """Build the time anchor bar (and risk legend). Shown only in MFT and USN Journal tabs."""
        time_anchor_row = QWidget()
        time_anchor_row.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        time_anchor_layout = QHBoxLayout(time_anchor_row)
        time_anchor_layout.setContentsMargins(0, 4, 0, 4)
        time_anchor_layout.addWidget(QLabel("Time anchor:"))
        self._usn_time_column_combo = QComboBox()
        for label, tid, cidx in (
            ("USN: Timestamp", "usn", 0),
            ("MFT: Created", "mft", 5),
            ("MFT: Modified", "mft", 6),
            ("MFT: MFT Modified", "mft", 7),
            ("MFT: Accessed", "mft", 8),
            ("MFT: FN created", "mft", 9),
        ):
            self._usn_time_column_combo.addItem(label, [tid, cidx])
        self._usn_time_column_combo.setMinimumWidth(160)
        time_anchor_layout.addWidget(self._usn_time_column_combo)
        time_anchor_layout.addWidget(QLabel("Anchor time:"))
        self._usn_anchor_time_edit = QLineEdit()
        self._usn_anchor_time_edit.setPlaceholderText("Set from selection or type ISO (YYYY-MM-DD HH:MM:SS)")
        self._usn_anchor_time_edit.setClearButtonEnabled(True)
        self._usn_anchor_time_edit.setMinimumWidth(220)
        self._usn_anchor_time_edit.textChanged.connect(self._on_usn_anchor_time_edited)
        time_anchor_layout.addWidget(self._usn_anchor_time_edit, 1)
        time_anchor_layout.addWidget(QLabel("±"))
        self._usn_anchor_seconds_spin = QSpinBox()
        self._usn_anchor_seconds_spin.setRange(1, 86400)
        self._usn_anchor_seconds_spin.setValue(30)
        self._usn_anchor_seconds_spin.setSuffix(" sec")
        self._usn_anchor_seconds_spin.valueChanged.connect(self._on_usn_anchor_seconds_changed)
        time_anchor_layout.addWidget(self._usn_anchor_seconds_spin)
        self._btn_usn_set_anchor = QPushButton("Set from selection")
        self._btn_usn_set_anchor.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        self._btn_usn_set_anchor.setToolTip("Use selected row's time (from chosen column). Select a row in MFT or USN table, then click.")
        self._btn_usn_set_anchor.clicked.connect(self._on_usn_set_anchor_from_selection)
        time_anchor_layout.addWidget(self._btn_usn_set_anchor)
        time_anchor_layout.addStretch()
        legend_label = QLabel("Risk legend:")
        legend_label.setStyleSheet("color: #9399b2; font-size: 9pt;")
        legend_label.setToolTip("Row risk highlights used in both MFT and USN tables.")
        time_anchor_layout.addWidget(legend_label)
        for level, title in (("critical", "Critical"), ("high", "High"), ("medium", "Medium")):
            bg, fg = _ROW_RISK_COLORS[level]
            time_anchor_layout.addWidget(_make_risk_legend_chip(title, bg, fg))
        return time_anchor_row

    def _set_stat_table_row(
        self,
        table: QTableWidget,
        row: int,
        values: list[str],
        risk_level: str | None = None,
        exec_swap_highlight: bool = False,
    ) -> None:
        items = []
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            table.setItem(row, col, item)
            items.append(item)
        if risk_level:
            _apply_row_risk_colors(items, risk_level)
        elif exec_swap_highlight:
            bg, fg = _EXEC_SWAP_HIGHLIGHT
            for item in items:
                item.setBackground(QColor(bg[0], bg[1], bg[2]))
                item.setForeground(QColor(fg[0], fg[1], fg[2]))
            if items:
                items[0].setData(EXEC_SWAP_ROLE, True)

    def _rebuild_full_usn_parent_paths(self) -> None:
        """Precompute parent paths for the full USN record set (independent of filters/lazy loading)."""
        all_usn = self._usn_records or []
        if not all_usn:
            self._usn_full_parent_paths = []
            return
        path_table = self._path_table or {}
        rec_by_num = {r.record_number: r for r in self._records} if self._records else {}
        has_mft = bool(self._records)
        paths: list[str] = []
        for rec in all_usn:
            pp = parent_path_for_usn_record(rec, path_table, rec_by_num) if has_mft else "\\"
            paths.append(pp if pp else "\\")
        self._usn_full_parent_paths = paths

    def _fs_tree_node_row_values(self, record_number: int, parent_path: str) -> tuple[list[str], str | None]:
        """Return (list of column strings, risk_level) for a FS tree node by record number."""
        idx = self._fs_tree_rec_to_index.get(record_number, -1)
        if idx < 0 or idx >= len(self._records or []):
            return [str(record_number), "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""], None
        rec = self._records[idx]
        u = (self._fs_tree_data and self._fs_tree_data.usn_summaries.get(record_number)) if self._fs_tree_data else None
        timestomp = detect_timestomping_anomaly(rec) is not None
        seq_high = is_high_sequence(rec, DEFAULT_SEQUENCE_GAP_THRESHOLD)
        risk = _mft_row_risk_level(rec, parent_path, timestomp, seq_high)
        usn_create = str(u.create) if u else ""
        usn_delete = str(u.delete) if u else ""
        usn_rename = (str((u.rename_old or 0) + (u.rename_new or 0)) if u else "") or ""
        usn_data = (str((u.data_overwrite or 0) + (u.data_extend or 0)) if u else "") or ""
        return [
            rec.primary_name(),
            str(rec.record_number),
            "dir" if rec.is_directory else "file",
            str(rec.size()) if not rec.is_directory else "",
            rec.created_iso() or "",
            rec.modified_iso() or "",
            str(rec.sequence),
            "yes" if rec.in_use else "no",
            "yes" if timestomp else "",
            "yes" if seq_high else "",
            "yes" if _is_suspicious_parent_path(parent_path) else "",
            "yes" if _is_executable_name(rec.primary_name()) else "",
            usn_create,
            usn_delete,
            usn_rename,
            usn_data,
        ], risk

    def _on_rebuild_fs_tree(self) -> None:
        """Build file system tree from loaded MFT (and USN if loaded), then populate the tree view (lazy children)."""
        if not self._records or not self._path_table:
            self._status.showMessage("Load $MFT first, then click Rebuild.")
            return
        self._status.showMessage("Rebuilding file system tree...")
        QApplication.processEvents()
        self._fs_tree_data = build_fs_tree(
            self._records,
            self._path_table,
            self._usn_by_mft if self._usn_by_mft else None,
        )
        self._fs_tree_rec_to_index = {r.record_number: i for i, r in enumerate(self._records)}
        self._fs_tree_populated = False
        self._fs_tree_widget.clear()
        self._populate_fs_tree_if_needed()
        n = len(self._fs_tree_data.root_record_numbers)
        self._status.showMessage(f"File system tree built ({n} root(s)). Lazy load on expand.")

    def _populate_fs_tree_if_needed(self) -> None:
        """Populate File System Tree tab: only top-level items; children loaded on expand (lazy) to save memory."""
        if not getattr(self, "_fs_tree_data", None) or not getattr(self, "_fs_tree_widget", None):
            return
        if self._fs_tree_populated:
            return
        tree = self._fs_tree_widget
        tree.clear()
        path_table = self._path_table or {}
        data = self._fs_tree_data
        children_map = data.children_map

        for record_number in data.root_record_numbers:
            idx = self._fs_tree_rec_to_index.get(record_number, -1)
            rec = self._records[idx] if 0 <= idx < len(self._records) else None
            fn = rec.primary_file_name() if rec else None
            parent_path = path_table.get(fn.parent_ref, "\\") if fn else "\\"
            values, risk = self._fs_tree_node_row_values(record_number, parent_path)
            row = QTreeWidgetItem(values)
            row.setData(0, RECORD_INDEX_ROLE, idx)
            if risk and risk in _ROW_RISK_COLORS:
                bg, fg = _ROW_RISK_COLORS[risk]
                for c in range(row.columnCount()):
                    row.setBackground(c, QColor(bg[0], bg[1], bg[2]))
                    row.setForeground(c, QColor(fg[0], fg[1], fg[2]))
            has_children = record_number in children_map and len(children_map[record_number]) > 0
            row.setChildIndicatorPolicy(
                QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator
                if has_children
                else QTreeWidgetItem.ChildIndicatorPolicy.DontShowIndicatorWhenChildless
            )
            if rec:
                row.setData(5, Qt.ItemDataRole.ToolTipRole, _modified_minus_created_tooltip(rec))
            tree.addTopLevelItem(row)
        self._fs_tree_populated = True

    def _collect_fs_tree_expanded(self) -> set[int]:
        """Collect record numbers of all expanded nodes in the file system tree (for session save)."""
        expanded: set[int] = set()
        tree = getattr(self, "_fs_tree_widget", None)
        if not tree or not self._records:
            return expanded

        def walk(item: QTreeWidgetItem) -> None:
            idx = item.data(0, RECORD_INDEX_ROLE)
            if idx is not None and 0 <= idx < len(self._records):
                record_number = self._records[idx].record_number
                if item.isExpanded():
                    expanded.add(record_number)
            for i in range(item.childCount()):
                walk(item.child(i))

        for i in range(tree.topLevelItemCount()):
            walk(tree.topLevelItem(i))
        return expanded

    def _restore_fs_tree_expanded(self, expanded_record_numbers: list[int]) -> None:
        """Restore expanded state of file system tree nodes (after session load). Children load lazily on expand."""
        if not expanded_record_numbers or not getattr(self, "_fs_tree_widget", None):
            return
        expanded_set = set(expanded_record_numbers)
        tree = self._fs_tree_widget

        changed = [False]  # use list so inner function can mutate

        def walk(item: QTreeWidgetItem) -> None:
            idx = item.data(0, RECORD_INDEX_ROLE)
            if idx is not None and 0 <= idx < len(self._records):
                record_number = self._records[idx].record_number
                if record_number in expanded_set and not item.isExpanded():
                    item.setExpanded(True)
                    changed[0] = True
            for i in range(item.childCount()):
                walk(item.child(i))

        def expand_matching() -> bool:
            changed[0] = False
            for i in range(tree.topLevelItemCount()):
                walk(tree.topLevelItem(i))
            return changed[0]

        while expand_matching():
            QApplication.processEvents()

    def _on_fs_tree_item_expanded(self, item: QTreeWidgetItem) -> None:
        """Lazy-load children when a node is expanded; only create items for this level."""
        if not self._fs_tree_data or not self._records:
            return
        idx = item.data(0, RECORD_INDEX_ROLE)
        if idx is None or idx < 0:
            return
        record_number = self._records[idx].record_number
        children = self._fs_tree_data.children_map.get(record_number)
        if not children or item.childCount() > 0:
            return
        path_table = self._path_table or {}
        parent_path = path_table.get(record_number, "\\")
        for child_record_number in children:
            values, risk = self._fs_tree_node_row_values(child_record_number, parent_path)
            child_item = QTreeWidgetItem(item, values)
            child_idx = self._fs_tree_rec_to_index.get(child_record_number, -1)
            child_item.setData(0, RECORD_INDEX_ROLE, child_idx)
            if risk and risk in _ROW_RISK_COLORS:
                bg, fg = _ROW_RISK_COLORS[risk]
                for c in range(child_item.columnCount()):
                    child_item.setBackground(c, QColor(bg[0], bg[1], bg[2]))
                    child_item.setForeground(c, QColor(fg[0], fg[1], fg[2]))
            has_children = child_record_number in self._fs_tree_data.children_map and len(
                self._fs_tree_data.children_map[child_record_number]
            ) > 0
            child_item.setChildIndicatorPolicy(
                QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator
                if has_children
                else QTreeWidgetItem.ChildIndicatorPolicy.DontShowIndicatorWhenChildless
            )
            child_rec = self._records[child_idx] if 0 <= child_idx < len(self._records) else None
            if child_rec:
                child_item.setData(5, Qt.ItemDataRole.ToolTipRole, _modified_minus_created_tooltip(child_rec))

    def _on_fs_tree_context_menu(self, pos):
        """Context menu on File System Tree: Jump to MFT row, Add to Kill Chain Phase."""
        tree = self._fs_tree_widget
        item = tree.itemAt(pos)
        if not item:
            return
        idx = item.data(0, RECORD_INDEX_ROLE)
        if idx is None or idx < 0:
            return
        rec = self._records[idx] if 0 <= idx < len(self._records) else None
        if not rec:
            return
        mft_num = rec.record_number
        menu = QMenu(self)
        jump = QAction("Jump to MFT row", self)
        jump.triggered.connect(lambda: self._fs_tree_jump_to_mft(idx))
        menu.addAction(jump)
        kill_sub = QMenu("Add to Kill Chain Phase", self)
        for phase in KILL_CHAIN_PHASES:
            act = QAction(phase, self)
            act.triggered.connect(lambda checked=False, m=mft_num, p=phase: self._add_file_to_kill_chain_phase(m, p))
            kill_sub.addAction(act)
        menu.addMenu(kill_sub)
        menu.exec(tree.viewport().mapToGlobal(pos))

    def _fs_tree_jump_to_mft(self, record_index: int) -> None:
        """Switch to MFT tab and select the row for the given record index."""
        self._main_tabs.setCurrentIndex(0)
        target_rec = self._records[record_index] if 0 <= record_index < len(self._records) else None
        if not target_rec:
            return
        model = self._mft_model
        for row in range(model.rowCount()):
            if model.record_at(row) is target_rec:
                self._table.selectionModel().clearSelection()
                self._table.selectRow(row)
                self._table.scrollTo(model.index(row, 0))
                break

    def _refresh_anomaly_sequences(self) -> None:
        """Recompute anomaly sequence detection (chains + unlinked findings) from MFT + USN.
        Requires USN Journal to be loaded. Call this to refresh the Anomaly sequences table.
        """
        if not hasattr(self, "_stats_sequence_table"):
            return
        records = list(self._records or [])
        path_table = getattr(self, "_path_table", None) or {}
        all_usn = self._usn_records or []

        def _score_to_risk(score: float) -> str:
            if score >= 0.80:
                return "critical"
            if score >= 0.60:
                return "high"
            if score >= 0.40:
                return "medium"
            return "low"

        self._anomaly_seq_raw_data = []
        self._anomaly_seq_detail_data = []
        if all_usn:
            chains, unlinked, usn_gap_alerts = build_abnormal_sequence_pipeline(
                records, all_usn, path_table
            )
            for chain in chains:
                start_iso = chain.start_time.isoformat(sep=" ")[:26]
                end_iso = chain.end_time.isoformat(sep=" ")[:26]
                path = chain.findings[0].path if chain.findings else "-"
                pattern = " -> ".join(chain.patterns)
                score_str = f"{chain.chain_score:.2f}"
                risk = _score_to_risk(chain.chain_score)
                vals = [score_str, risk, start_iso, end_iso, path, pattern]
                self._anomaly_seq_raw_data.append((vals, risk))
                self._anomaly_seq_detail_data.append(chain)
            for finding in unlinked:
                start_iso = finding.start_time.isoformat(sep=" ")[:26]
                end_iso = finding.end_time.isoformat(sep=" ")[:26]
                risk = _score_to_risk(finding.composite_score)
                vals = [
                    f"{finding.composite_score:.2f}", risk,
                    start_iso, end_iso, finding.path, finding.pattern,
                ]
                self._anomaly_seq_raw_data.append((vals, risk))
                self._anomaly_seq_detail_data.append(finding)
            if usn_gap_alerts and hasattr(self, "_anomaly_gap_label"):
                self._anomaly_gap_label.setText("⚠ " + "; ".join(usn_gap_alerts[:3]))
        self._apply_anomaly_filter()

    def _refresh_statistics_tab(self):
        """Recompute anomaly statistics for analyst triage.

        All calculations use the FULL unfiltered MFT and USN datasets so
        results are independent of any table filters or lazy-loading limits.
        """
        if not hasattr(self, "_stats_sequence_table"):
            return

        records = list(self._records or [])
        path_table = getattr(self, "_path_table", None) or {}
        all_usn = self._usn_records or []
        full_pp = self._usn_full_parent_paths or []
        usn_pairs: list[tuple[UsnRecord, str]] = []
        if all_usn and len(full_pp) == len(all_usn):
            usn_pairs = list(zip(all_usn, full_pp))

        self._refresh_anomaly_sequences()

        if hasattr(self, "_stats_extension_change_table"):
            usn_list = [rec for rec, _ in usn_pairs] if usn_pairs else []
            ext_change_report = build_extension_change_report(usn_list, path_table)
            self._ext_change_raw_data = []
            for entry in ext_change_report:
                vals = [
                    str(entry.mft_record_number), entry.old_name, entry.new_name,
                    entry.flag_message(), entry.timestamp_iso, entry.parent_path,
                ]
                is_exec_swap = _is_exec_swap(entry.old_ext, entry.new_ext)
                self._ext_change_raw_data.append((vals, is_exec_swap))
            self._apply_ext_change_filter()

        if hasattr(self, "_stats_filename_entropy_table") and hasattr(self, "_stats_ext_entropy_table"):
            path_table = getattr(self, "_path_table", None) or {}
            filename_entropy_rows = filename_entropy_report(records, path_table, top_n=200)
            self._filename_entropy_raw_data = []
            for mft_num, name, parent_path, entropy in filename_entropy_rows:
                self._filename_entropy_raw_data.append([f"{entropy:.4f}", name, parent_path, str(mft_num)])
            self._apply_filename_entropy_filter()
            ext_entropy_rows = extension_entropy_per_directory(records, path_table, min_files=2, top_n=200)
            self._ext_entropy_raw_data = []
            for entry in ext_entropy_rows:
                self._ext_entropy_raw_data.append([
                    entry.directory, f"{entry.entropy:.4f}", str(entry.file_count), str(entry.distinct_extensions),
                ])
            self._apply_ext_entropy_filter()

        # Directory churn: directories with many files created in a short burst.
        # Uses the FULL unfiltered USN record set (self._usn_records), not the
        # display-filtered subset, so churn detection is independent of USN tab filters.
        if hasattr(self, "_churn_table"):
            path_table = getattr(self, "_path_table", None) or {}
            try:
                churn_window = int(self._churn_window_edit.text()) if hasattr(self, "_churn_window_edit") else 120
            except (ValueError, TypeError):
                churn_window = 120
            churn_min = self._churn_min_files_spin.value() if hasattr(self, "_churn_min_files_spin") else 3
            all_usn = getattr(self, "_usn_records", None) or None
            all_mft = list(self._records or []) if hasattr(self, "_records") else records
            churn_report = build_directory_churn_report(
                all_mft, path_table,
                window_seconds=churn_window,
                min_files=churn_min,
                top_n=200,
                usn_records=all_usn,
            )
            crit = sum(1 for e in churn_report if e.risk == "critical")
            high = sum(1 for e in churn_report if e.risk == "high")
            source = "MFT + USN Journal" if all_usn else "MFT only (load USN for better coverage)"
            self._churn_summary_label.setText(
                f"{len(churn_report)} directories with burst activity  "
                f"({crit} critical, {high} high risk)  |  window={churn_window}s  min={churn_min} files  |  source: {source}"
            )
            self._churn_report_data = churn_report
            self._churn_raw_data = []
            for entry in churn_report:
                names_display = "; ".join(entry.file_names[:15])
                if len(entry.file_names) > 15:
                    names_display += f"  \u2026 +{len(entry.file_names) - 15} more"
                vals = [
                    entry.directory, str(entry.file_count),
                    entry.window_start_iso, entry.window_end_iso,
                    f"{entry.window_seconds:.1f}",
                    "YES" if entry.has_executable else "",
                    "YES" if entry.is_persistence_path else "",
                    names_display,
                ]
                self._churn_raw_data.append((vals, entry.risk))
            self._apply_churn_filter()

        # Temporal burst: not computed here (would block load). User runs it via Refresh on the Temporal burst tab (background thread).
        if hasattr(self, "_temporal_burst_summary_label"):
            self._temporal_burst_computed = False
            self._temporal_burst_summary_label.setText(
                "Not computed. Click \"Refresh (compute in background)\" below to run temporal burst detection without blocking."
            )

        # Survival metrics: time-to-delete for deleted files, histogram of short-lived (< 5 min).
        # Prefer USN-based lifecycle (create->delete) so results still exist even if the MFT slot was reused.
        if hasattr(self, "_survival_table"):
            self._refresh_survival_tab(records, usn_pairs)

        # Keep Analysis Report tab in sync with latest statistics.
        if hasattr(self, "_report_text"):
            self._refresh_analysis_report()

    def _refresh_survival_tab(
        self,
        records: list,
        usn_pairs: list[tuple[UsnRecord, str]],
    ) -> None:
        """Populate Survival metrics: time-to-delete table and short-lived (< 5 min) histogram."""
        # 100ns per second
        TICKS_PER_SEC = 10_000_000
        SHORT_LIVED_MAX_SEC = 300  # 5 minutes

        rows: list[tuple[int, str, str, str, str, float]] = []

        if usn_pairs:
            # USN lifecycle reconstruction by file reference (includes sequence, so it tracks a specific file instance).
            # For each file_ref: track earliest create (if present), earliest seen, and latest delete.
            lifecycle: dict[int, dict] = {}
            for evt, parent_path in sorted(usn_pairs, key=lambda rp: rp[0].timestamp):
                file_ref = int(evt.file_ref)
                st = lifecycle.get(file_ref)
                if st is None:
                    st = {
                        "mft_num": evt.mft_record_number(),
                        "name": evt.file_name or "",
                        "path": parent_path or "\\",
                        "first_ts": None,
                        "first_iso": "",
                        "create_ts": None,
                        "create_iso": "",
                        "delete_ts": None,
                        "delete_iso": "",
                    }
                    lifecycle[file_ref] = st
                # Keep the most recent name/path we saw (often best at delete).
                if evt.file_name:
                    st["name"] = evt.file_name
                if parent_path:
                    st["path"] = parent_path

                if st["first_ts"] is None or evt.timestamp < st["first_ts"]:
                    st["first_ts"] = evt.timestamp
                    st["first_iso"] = evt.timestamp_iso()
                if evt.reason & USN_REASON_FILE_CREATE:
                    if st["create_ts"] is None or evt.timestamp < st["create_ts"]:
                        st["create_ts"] = evt.timestamp
                        st["create_iso"] = evt.timestamp_iso()
                if evt.reason & USN_REASON_FILE_DELETE:
                    if st["delete_ts"] is None or evt.timestamp > st["delete_ts"]:
                        st["delete_ts"] = evt.timestamp
                        st["delete_iso"] = evt.timestamp_iso()

            for st in lifecycle.values():
                if st["delete_ts"] is None:
                    continue
                start_ts = st["create_ts"] if st["create_ts"] is not None else st["first_ts"]
                start_iso = st["create_iso"] if st["create_ts"] is not None else (st["first_iso"] + " (first seen)" if st["first_iso"] else "")
                if start_ts is None:
                    continue
                delta_ticks = int(st["delete_ts"]) - int(start_ts)
                if delta_ticks < 0:
                    continue
                rows.append((
                    int(st["mft_num"]),
                    str(st["name"] or "(no name)"),
                    str(st["path"] or "\\"),
                    str(start_iso or ""),
                    str(st["delete_iso"] or ""),
                    delta_ticks / TICKS_PER_SEC,
                ))
        else:
            # No USN data: show empty results but keep a clear hint in the summary label.
            pass

        rows.sort(key=lambda r: r[5])
        self._survival_raw_data = []
        for mft_num, name, parent_path, created_iso, delete_iso, ttd_sec in rows:
            ttd_display = _format_time_to_delete(ttd_sec) + f" ({int(ttd_sec)}s)"
            self._survival_raw_data.append([str(mft_num), name, parent_path, created_iso, delete_iso, ttd_display])
        self._apply_survival_filter()

        short_lived = [r for r in rows if r[5] < SHORT_LIVED_MAX_SEC]
        buckets = [
            (0, 30, "0\u201330 s"),
            (30, 60, "30 s\u20131 min"),
            (60, 120, "1\u20132 min"),
            (120, 180, "2\u20133 min"),
            (180, 240, "3\u20134 min"),
            (240, 300, "4\u20135 min"),
        ]
        counts = []
        for lo, hi, _ in buckets:
            count = sum(1 for _, _, _, _, _, sec in short_lived if lo <= sec < hi)
            counts.append(count)
        max_count = max(counts, default=1)
        self._survival_histogram_table.setSortingEnabled(False)
        self._survival_histogram_table.setRowCount(len(buckets))
        for row_idx, ((lo, hi, label), count) in enumerate(zip(buckets, counts)):
            self._survival_histogram_table.setItem(row_idx, 0, QTableWidgetItem(label))
            self._survival_histogram_table.setItem(row_idx, 1, QTableWidgetItem(str(count)))
            bar_len = int(round(24 * count / max_count)) if max_count else 0
            bar_str = "\u2588" * bar_len
            self._survival_histogram_table.setItem(row_idx, 2, QTableWidgetItem(bar_str))
        self._survival_histogram_table.resizeColumnsToContents()
        self._survival_histogram_table.setSortingEnabled(True)

        hint = ""
        if records and not usn_pairs:
            hint = " (Open $J (USN Journal) to compute delete lifetimes.)"
        elif usn_pairs and not rows:
            hint = " (No create\u2192delete lifecycles found in the USN Journal data.)"
        self._survival_summary_label.setText(
            f"Deleted files with known time to delete: {len(rows)}. "
            f"Short-lived (&lt; 5 min): {len(short_lived)}.{hint}"
        )

    def _on_churn_table_double_click(self, row: int, _col: int) -> None:
        # row is visual row (affected by sort); resolve entry from first cell's UserRole
        item = self._churn_table.item(row, 0) if row >= 0 else None
        entry = item.data(Qt.ItemDataRole.UserRole) if item else None
        if entry is None:
            return
        dlg = DirectoryChurnFilesDialog(entry, parent=self)
        dlg.exec()

    def _update_churn_minutes_label(self, text: str = "") -> None:
        try:
            value = int(text or self._churn_window_edit.text())
        except (ValueError, TypeError):
            self._churn_minutes_label.setText("")
            return
        minutes = value / 60.0
        self._churn_minutes_label.setText(f"({minutes:.2f} min)")

    def _refresh_analysis_report(self) -> None:
        """Build or refresh the textual Analysis Report tab from current data."""
        if not hasattr(self, "_report_text"):
            return
        text = self._build_analysis_report_text()
        self._report_text.setPlainText(text)

    def _build_analysis_report_text(self) -> str:
        """Return an AI-compatible DFIR report: structured, with glossary and clear sections."""
        lines: list[str] = []

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        mft_source = str(self._current_path) if self._current_path else "(no $MFT loaded)"
        usn_source = str(self._usn_path) if getattr(self, "_usn_path", None) else "(no USN Journal loaded)"

        # --- AI instruction block (helps LLMs interpret the report) ---
        lines.append("---")
        lines.append("DOCUMENT_TYPE: Forensic Analysis Report (NTFS $MFT and USN Journal)")
        lines.append("PURPOSE: Summarize file-system anomalies and Kill Chain mappings for incident response.")
        lines.append("INSTRUCTIONS: Use this report to explain findings, assess risk, suggest next steps, and answer questions about the evidence. Refer to the GLOSSARY for term definitions.")
        lines.append("---")
        lines.append("")

        lines.append("# Forensic Investigation Report")
        lines.append("")
        lines.append(f"**Generated:** {now_utc}")
        lines.append("")

        records = list(self._records or [])
        if not records:
            lines.append("No $MFT records are currently loaded. Open an $MFT file to generate a report.")
            return "\n".join(lines)

        # Timeframe from MFT created timestamps.
        created_times = [rec.created_iso() for rec in records if getattr(rec, "created_iso", None) and rec.created_iso()]
        mft_first = min(created_times) if created_times else ""
        mft_last = max(created_times) if created_times else ""

        # Timeframe from USN events (if loaded).
        usn_records = list(self._usn_records or [])
        try:
            usn_times = [evt.timestamp_iso() for evt in usn_records if hasattr(evt, "timestamp_iso")]
        except Exception:
            usn_times = []
        usn_first = min(usn_times) if usn_times else ""
        usn_last = max(usn_times) if usn_times else ""

        # Analysis tab statistics.
        anomaly_rows = list(getattr(self, "_anomaly_seq_raw_data", []))
        ext_change_rows = list(getattr(self, "_ext_change_raw_data", []))
        fn_entropy_rows = list(getattr(self, "_filename_entropy_raw_data", []))
        ext_entropy_rows = list(getattr(self, "_ext_entropy_raw_data", []))
        churn_rows = list(getattr(self, "_churn_raw_data", []))
        survival_rows = list(getattr(self, "_survival_raw_data", []))
        total_kc = sum(len(self._kill_chain_entries.get(p, [])) for p in KILL_CHAIN_PHASES)

        # --- Glossary (AI can reference these definitions) ---
        lines.append("## Glossary")
        lines.append("")
        lines.append("| Term | Definition |")
        lines.append("|------|------------|")
        lines.append("| **$MFT** | Master File Table: NTFS metadata for every file/directory on the volume. Each record holds timestamps, size, attributes. |")
        lines.append("| **USN Journal ($J)** | Update Sequence Number Journal: log of file-system changes (create, delete, rename, write). Used to reconstruct timelines. |")
        lines.append("| **Kill Chain** | Lockheed Martin Cyber Kill Chain: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives. |")
        lines.append("| **Timestomping** | Tampering with file timestamps (e.g., backdating) to evade detection. Detected when $STANDARD_INFORMATION and $FILE_NAME timestamps disagree. |")
        lines.append("| **Filename entropy** | Shannon entropy of the filename. High entropy suggests random/machine-generated names (e.g., malware drops). |")
        lines.append("| **Extension-change rename** | File renamed so extension changed (e.g., .txt→.exe). Often used to disguise executables. |")
        lines.append("| **Directory churn** | Many files created in one directory within a short time window. May indicate dropper extraction or payload staging. |")
        lines.append("| **Survival metrics** | Time from file creation to deletion. Short-lived files may be temporary malware artifacts. |")
        lines.append("| **Risk levels** | **Critical**: timestomping, or executable in suspicious path. **High**: executable OR suspicious path. **Medium**: high MFT sequence (reused slot). |")
        lines.append("")

        # --- Investigation scope (structured metadata) ---
        lines.append("## 1. Investigation Scope")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| MFT source | {mft_source} |")
        lines.append(f"| USN Journal | {usn_source} |")
        lines.append(f"| MFT record count | {len(records):,} |")
        lines.append(f"| USN event count | {len(usn_records):,} |")
        if mft_first or mft_last:
            lines.append(f"| Timeframe (MFT created) | {mft_first or 'N/A'} to {mft_last or 'N/A'} |")
        if usn_first or usn_last:
            lines.append(f"| Timeframe (USN events) | {usn_first or 'N/A'} to {usn_last or 'N/A'} |")
        lines.append("")

        # --- Executive summary (AI can expand on this) ---
        lines.append("## 2. Executive Summary")
        lines.append("")
        lines.append("This report summarizes file-system anomalies derived from $MFT and USN Journal analysis. Key counts:")
        lines.append("")
        lines.append("| Finding category | Count | Interpretation |")
        lines.append("|------------------|-------|----------------|")
        lines.append(f"| Anomaly sequences (pattern detection) | {len(anomaly_rows)} | DROPPER_CLEANUP, MASQUERADE_RENAME, STAGED_DROPPER, etc. |")
        lines.append(f"| Extension-change renames | {len(ext_change_rows)} | Possible disguised executables |")
        lines.append(f"| High filename-entropy files | {len(fn_entropy_rows)} | Random-looking names (malware drops, temp files) |")
        lines.append(f"| High extension-entropy directories | {len(ext_entropy_rows)} | Unusual mix of file types in one folder |")
        lines.append(f"| Burst-activity directories (churn) | {len(churn_rows)} | Dropper extraction or bulk file creation |")
        lines.append(f"| Deleted files with known lifetime | {len(survival_rows)} | Short-lived files may be staged payloads |")
        lines.append(f"| Files mapped to Kill Chain phases | {total_kc} | Analyst-tagged attack lifecycle artifacts |")
        lines.append("")
        lines.append("**Suggested AI analysis:** Explain what each finding category means in the context of incident response. Which items warrant immediate triage? What additional artifacts (e.g., Prefetch, Event Logs) would help confirm or refute malicious activity?")
        lines.append("")

        # --- Detailed findings (structured for AI parsing) ---
        lines.append("## 3. Detailed Findings")
        lines.append("")

        # Build quick lookup maps by MFT # for cross-referencing.
        ext_change_by_mft: dict[int, list[list[str]]] = {}
        for row in ext_change_rows:
            vals = row[0] if isinstance(row, (list, tuple)) and len(row) == 2 else row
            if not vals:
                continue
            try:
                mft_num = int(vals[0])
            except (ValueError, TypeError):
                continue
            ext_change_by_mft.setdefault(mft_num, []).append(vals)

        fn_entropy_by_mft: dict[int, list[list[str]]] = {}
        for row in fn_entropy_rows:
            if len(row) < 4:
                continue
            try:
                mft_num = int(row[3])
            except (ValueError, TypeError):
                continue
            fn_entropy_by_mft.setdefault(mft_num, []).append(row)

        survival_by_mft: dict[int, list[str]] = {}
        for row in survival_rows:
            if not row:
                continue
            try:
                mft_num = int(row[0])
            except (ValueError, TypeError):
                continue
            survival_by_mft[mft_num] = row

        # Churn directories (path prefix matches).
        churn_dirs: list[tuple[str, str]] = []
        for vals, risk in churn_rows:
            if not vals:
                continue
            directory = str(vals[0] or "").lower()
            churn_dirs.append((directory, risk))

        # Reverse Kill Chain mapping: MFT # -> [phases].
        phases_by_mft: dict[int, list[str]] = {}
        for phase, mft_list in self._kill_chain_entries.items():
            for mft_num in mft_list:
                phases_by_mft.setdefault(int(mft_num), []).append(phase)

        def _tags_for_mft(rec: MFTRecord | None, mft_num: int, parent_path: str) -> list[str]:
            tags: list[str] = []
            if mft_num in ext_change_by_mft:
                tags.append("extension-change rename")
            if mft_num in fn_entropy_by_mft:
                # Use highest recorded entropy value.
                try:
                    ent_vals = [float(r[0]) for r in fn_entropy_by_mft[mft_num] if r and r[0]]
                except Exception:
                    ent_vals = []
                if ent_vals:
                    tags.append(f"high filename entropy (max {max(ent_vals):.4f})")
                else:
                    tags.append("high filename entropy")
            surv = survival_by_mft.get(mft_num)
            if surv:
                ttd = surv[5] if len(surv) >= 6 else ""
                tags.append(f"deleted file, time-to-delete={ttd}")
            parent_lower = (parent_path or "\\").lower()
            for churn_dir, risk in churn_dirs:
                if churn_dir and parent_lower.startswith(churn_dir):
                    tags.append(f"in burst-activity directory (churn risk={risk})")
                    break
            if rec is not None:
                anomaly = detect_timestomping_anomaly(rec)
                seq_high = is_high_sequence(rec, DEFAULT_SEQUENCE_GAP_THRESHOLD)
                risk_level = _mft_row_risk_level(rec, parent_path, bool(anomaly), seq_high)
                if risk_level:
                    tags.append(f"MFT row risk={risk_level}")
                if anomaly:
                    tags.append(f"timestomping anomaly: {anomaly.flag_message()}")
            return tags

        # Anomaly sequences (top 10).
        lines.append("### 3.1 Anomaly Sequences (pattern detection per abnormal_sequence_spec)")
        lines.append("")
        lines.append("*Definition:* MFT+USN pattern detection: DROPPER_CLEANUP, MASQUERADE_RENAME, STAGED_DROPPER, OVERWRITE_THEN_DELETE, RAPID_MASS_DELETION, EXECUTABLE_IN_SUSPICIOUS_PATH, TIMESTOMP_WITH_WRITE.")
        lines.append("")
        if not anomaly_rows:
            lines.append("No anomaly sequences computed. Load MFT + USN Journal, then Analysis tab → Refresh.")
        else:
            lines.append(f"**Total:** {len(anomaly_rows)} | **Shown:** top 10 by score")
            lines.append("")
            lines.append("| # | Score | Risk | Start | End | Path | Pattern |")
            lines.append("|---|-------|------|-------|-----|------|---------|")
            for idx, item in enumerate(anomaly_rows[:10], start=1):
                if not item:
                    continue
                vals, risk = item
                if not vals or len(vals) < 6:
                    continue
                score, _, start_iso, end_iso, path, pattern = vals
                path_esc = (path or "").replace("|", "\\|")[:50]
                pattern_esc = (pattern or "").replace("|", "\\|")[:35]
                lines.append(f"| {idx} | {score} | {risk.upper()} | {start_iso} | {end_iso} | {path_esc} | {pattern_esc} |")
        lines.append("")

        # Extension change (top 20).
        lines.append("### 3.2 Extension-Change Renames")
        lines.append("*Definition:* Renames where the file extension changed (e.g., .txt→.exe). Often used to disguise executables.")
        lines.append("")
        if not ext_change_rows:
            lines.append("No extension-change renames. USN Journal may not be loaded.")
        else:
            lines.append(f"**Total:** {len(ext_change_rows)} | **Shown:** first 20")
            lines.append("")
            lines.append("| # | MFT # | Old name | New name | Flag | Timestamp | Parent path | Kill Chain | Tags |")
            lines.append("|---|-------|----------|----------|------|-----------|-------------|------------|------|")
            for idx, row in enumerate(ext_change_rows[:20], start=1):
                if len(row) < 6:
                    continue
                try:
                    mft_num = int(row[0])
                except (ValueError, TypeError):
                    mft_num = -1
                old_name, new_name, flag_msg, ts, parent_path = row[1], row[2], row[3], row[4], row[5]
                rec = self._mft_record_by_number(mft_num) if mft_num >= 0 else None
                tags = _tags_for_mft(rec, mft_num, parent_path)
                kc_phases = phases_by_mft.get(mft_num, [])
                kc_str = ", ".join(kc_phases) if kc_phases else "-"
                tags_str = "; ".join(tags[:3]) if tags else "-"
                path_esc = (parent_path or "").replace("|", "\\|")[:40]
                lines.append(f"| {idx} | {mft_num} | {old_name[:20]} | {new_name[:20]} | {flag_msg[:15]} | {ts} | {path_esc} | {kc_str[:25]} | {tags_str[:30]} |")
        lines.append("")

        # High filename entropy (top 20).
        lines.append("### 3.3 High Filename-Entropy Files")
        lines.append("*Definition:* Shannon entropy of filename. High values suggest random/machine-generated names (malware drops, temp files).")
        lines.append("")
        if not fn_entropy_rows:
            lines.append("No filename-entropy report computed.")
        else:
            lines.append(f"**Total:** {len(fn_entropy_rows)} | **Shown:** first 20")
            lines.append("")
            lines.append("| # | MFT # | Entropy | Full path | Kill Chain | Tags |")
            lines.append("|---|-------|---------|-----------|------------|------|")
            for idx, row in enumerate(fn_entropy_rows[:20], start=1):
                if len(row) < 4:
                    continue
                entropy_str, name, parent_path, mft_str = row
                try:
                    mft_num = int(mft_str)
                except (ValueError, TypeError):
                    mft_num = -1
                rec = self._mft_record_by_number(mft_num) if mft_num >= 0 else None
                tags = _tags_for_mft(rec, mft_num, parent_path)
                kc_phases = phases_by_mft.get(mft_num, [])
                full_path = f"{(parent_path or '')}{name}"
                full_path_esc = full_path.replace("|", "\\|")[:50]
                kc_str = ", ".join(kc_phases) if kc_phases else "-"
                tags_str = "; ".join(tags[:2]) if tags else "-"
                lines.append(f"| {idx} | {mft_num} | {entropy_str} | {full_path_esc} | {kc_str[:20]} | {tags_str[:25]} |")
        lines.append("")

        # Directory churn (top 20).
        lines.append("### 3.4 Directory Churn (burst-activity)")
        lines.append("*Definition:* Directories where many files were created in a short time window. May indicate dropper extraction or payload staging.")
        lines.append("")
        if not churn_rows:
            lines.append("No directory-churn report computed.")
        else:
            lines.append(f"**Total:** {len(churn_rows)} | **Shown:** first 20")
            lines.append("")
            lines.append("| # | Risk | Directory | Files | Window start | Window end | Duration | Exec? | Persist? | Sample files |")
            lines.append("|---|------|-----------|-------|--------------|------------|----------|-------|----------|--------------|")
            for idx, item in enumerate(churn_rows[:20], start=1):
                vals, risk = item
                if not vals or len(vals) < 8:
                    continue
                directory, files, first_ts, last_ts, duration_s, has_exec, is_persist, names_display = vals
                dir_esc = (directory or "").replace("|", "\\|")[:35]
                names_esc = (names_display or "").replace("|", "\\|")[:40]
                lines.append(f"| {idx} | {risk.upper()} | {dir_esc} | {files} | {first_ts} | {last_ts} | {duration_s}s | {has_exec or 'NO'} | {is_persist or 'NO'} | {names_esc} |")
        lines.append("")

        # Survival metrics (top 20 shortest lifetimes).
        lines.append("### 3.5 Survival Metrics (deleted files, time-to-delete)")
        lines.append("*Definition:* Time from file creation to deletion (USN). Short-lived files may be temporary malware artifacts.")
        lines.append("")
        if not survival_rows:
            lines.append("No survival-metrics data. USN Journal may not be loaded or no create→delete lifecycles.")
        else:
            lines.append(f"**Total:** {len(survival_rows)} | **Shown:** first 20 shortest lifetimes")
            lines.append("")
            lines.append("| # | MFT # | Path | Created | Deleted | Time to delete | Kill Chain | Tags |")
            lines.append("|---|-------|------|--------|---------|----------------|------------|------|")
            for idx, row in enumerate(survival_rows[:20], start=1):
                if len(row) < 6:
                    continue
                try:
                    mft_num = int(row[0])
                except (ValueError, TypeError):
                    mft_num = -1
                name, parent_path, created_iso, delete_iso, ttd_display = row[1], row[2], row[3], row[4], row[5]
                rec = self._mft_record_by_number(mft_num) if mft_num >= 0 else None
                tags = _tags_for_mft(rec, mft_num, parent_path)
                kc_phases = phases_by_mft.get(mft_num, [])
                full_path = f"{(parent_path or '')}{name}"
                full_path_esc = full_path.replace("|", "\\|")[:45]
                kc_str = ", ".join(kc_phases) if kc_phases else "-"
                tags_str = "; ".join(tags[:2]) if tags else "-"
                lines.append(f"| {idx} | {mft_num} | {full_path_esc} | {created_iso} | {delete_iso} | {ttd_display} | {kc_str[:20]} | {tags_str[:25]} |")
        lines.append("")

        # Kill Chain by phase.
        lines.append("## 4. Kill Chain Findings by Phase")
        lines.append("*Definition:* Analyst-mapped files to Lockheed Martin Cyber Kill Chain phases.")
        lines.append("")
        if total_kc == 0:
            lines.append("No Kill Chain assignments yet. Right-click files in MFT/USN/Analysis tables → Add to Kill Chain Phase.")
        else:
            for phase in KILL_CHAIN_PHASES:
                mft_list = self._kill_chain_entries.get(phase, [])
                if not mft_list:
                    continue
                lines.append(f"### {phase} ({len(mft_list)} file(s))")
                lines.append("")
                lines.append("| # | MFT # | Full path | SI Created | SI Modified | Size | In use | Tags |")
                lines.append("|---|-------|-----------|------------|-------------|------|--------|------|")
                for idx, mft_num in enumerate(mft_list[:20], start=1):
                    rec = self._mft_record_by_number(mft_num)
                    if not rec:
                        lines.append(f"| {idx} | {mft_num} | (record not found) | - | - | - | - | - |")
                        continue
                    parent_path = parent_path_for_record(rec, self._path_table or {})
                    name = rec.primary_name() or ""
                    full_path = f"{parent_path}{name}"
                    full_path_esc = full_path.replace("|", "\\|")[:50]
                    si_created = rec.standard_info.created_iso() if rec.standard_info else ""
                    si_modified = rec.standard_info.modified_iso() if rec.standard_info else ""
                    tags = _tags_for_mft(rec, int(mft_num), parent_path)
                    tags_str = "; ".join(tags[:2]) if tags else "-"
                    lines.append(f"| {idx} | {mft_num} | {full_path_esc} | {si_created} | {si_modified} | {rec.size()} | {bool(rec.in_use)} | {tags_str[:30]} |")
                if len(mft_list) > 20:
                    lines.append(f"*... and {len(mft_list) - 20} more*")
                lines.append("")
        lines.append("")

        # Indicators of Compromise.
        lines.append("## 5. Indicators of Compromise (file paths)")
        ioc_paths: set[str] = set()
        for phase, mft_list in self._kill_chain_entries.items():
            for mft_num in mft_list:
                rec = self._mft_record_by_number(mft_num)
                if not rec:
                    continue
                parent_path = parent_path_for_record(rec, self._path_table or {})
                full_path = f"{parent_path}{rec.primary_name() or ''}"
                if full_path:
                    ioc_paths.add(full_path)
        if not ioc_paths:
            lines.append("No file paths flagged as IOCs in the Kill Chain tab.")
        else:
            lines.append("Candidate file IOCs (from Kill Chain mappings). Validate with hash lookup and malware analysis:")
            lines.append("")
            for path in sorted(ioc_paths):
                lines.append(f"- `{path}`")
        lines.append("")

        lines.append("## 6. Recommendations")
        lines.append("")
        if total_kc > 0 or anomaly_rows or ext_change_rows or fn_entropy_rows or churn_rows or survival_rows:
            lines.append("1. **Correlate** file-system findings with host telemetry (process execution, network connections, Security Event Log).")
            lines.append("2. **Prioritize** critical/high-risk items: timestomping, executables in Temp/Public/Startup, burst-activity directories.")
            lines.append("3. **Acquire** copies of flagged files for malware analysis and hash lookup (VirusTotal, internal sandbox).")
            lines.append("4. **Review** user accounts, logon events (4624/4625), and lateral movement artifacts (RDP, PSExec).")
            lines.append("")
            lines.append("**Suggested AI analysis:** For the highest-risk findings above, suggest specific MITRE ATT&CK techniques, detection rules (Sigma/YARA), and triage steps.")
        else:
            lines.append("No anomaly statistics or Kill Chain mappings yet. Populate the Analysis and Kill Chain tabs, then refresh this report.")
        lines.append("")

        lines.append("## 7. Questions for AI Analysis")
        lines.append("")
        lines.append("When sharing this report with an AI assistant, you may ask:")
        lines.append("- *Explain what each finding category means and why it matters for incident response.*")
        lines.append("- *Which items should I triage first, and why?*")
        lines.append("- *What MITRE ATT&CK techniques might apply to these findings?*")
        lines.append("- *What additional artifacts (Prefetch, Amcache, Event Logs) would help confirm or refute malicious activity?*")
        lines.append("- *Suggest Sigma or YARA rules to detect similar activity in the future.*")

        return "\n".join(lines)

    # -- Generic stats table filter helper --

    def _apply_stats_filter(
        self,
        table: QTableWidget,
        raw_data_attr: str,
        filter_widget: CollapsibleStatsFilter,
        has_risk: bool = False,
    ) -> None:
        """Re-populate *table* from stored raw data, keeping only rows matching *filter_widget*."""
        raw = getattr(self, raw_data_attr, [])
        if has_risk:
            filtered = [(vals, risk) for vals, risk in raw if filter_widget.match_row(vals)]
        else:
            filtered = [vals for vals in raw if filter_widget.match_row(vals)]
        table.setSortingEnabled(False)
        table.setRowCount(len(filtered))
        for idx, item in enumerate(filtered):
            if has_risk:
                vals, risk = item
                self._set_stat_table_row(table, idx, vals, risk_level=risk)
            else:
                self._set_stat_table_row(table, idx, item)
        table.resizeColumnsToContents()
        table.setSortingEnabled(True)
        total = len(raw)
        shown = len(filtered)
        filter_widget.set_count_text(f"Showing {shown} of {total}" if shown != total else "")

    def _apply_anomaly_filter(self) -> None:
        raw = getattr(self, "_anomaly_seq_raw_data", [])
        detail = getattr(self, "_anomaly_seq_detail_data", [])
        filt = self._anomaly_filter
        filtered = [(vals, risk) for vals, risk in raw if filt.match_row(vals)]
        filtered_details: list[AttackChain | SequenceFinding] = []
        if len(detail) == len(raw):
            for i, (vals, risk) in enumerate(raw):
                if filt.match_row(vals):
                    filtered_details.append(detail[i])
        self._stats_sequence_table.setSortingEnabled(False)
        self._stats_sequence_table.setRowCount(len(filtered))
        for idx, (vals, risk) in enumerate(filtered):
            self._set_stat_table_row(self._stats_sequence_table, idx, vals, risk_level=risk)
            first = self._stats_sequence_table.item(idx, 0)
            if first is not None and idx < len(filtered_details):
                first.setData(Qt.ItemDataRole.UserRole, filtered_details[idx])
        self._stats_sequence_table.resizeColumnsToContents()
        self._stats_sequence_table.setSortingEnabled(True)
        total = len(raw)
        shown = len(filtered)
        filt.set_count_text(f"Showing {shown} of {total}" if shown != total else "")

    def _on_anomaly_selection_changed(self) -> None:
        """Show narrative (chains) or evidence (findings) in the detail panel."""
        text = getattr(self, "_anomaly_detail_text", None)
        if not text:
            return
        table = self._stats_sequence_table
        rows = table.selectionModel().selectedRows()
        if not rows:
            text.clear()
            return
        row = rows[0].row()
        first = table.item(row, 0)
        if first is None:
            text.clear()
            return
        obj = first.data(Qt.ItemDataRole.UserRole)
        if obj is None:
            text.clear()
            return
        if isinstance(obj, AttackChain):
            text.setPlainText(obj.narrative)
        else:
            lines = ["Evidence:"]
            for e in obj.evidence:
                lines.append(f"  • {e}")
            text.setPlainText("\n".join(lines))

    def _apply_ext_change_filter(self) -> None:
        raw = getattr(self, "_ext_change_raw_data", [])
        filt = self._ext_change_filter
        only_highlight = getattr(self, "_ext_change_only_highlight_cb", None)
        only_highlighted = only_highlight.isChecked() if only_highlight else False
        filtered = [
            (vals, is_exec_swap)
            for vals, is_exec_swap in raw
            if filt.match_row(vals) and (not only_highlighted or is_exec_swap)
        ]
        table = self._stats_extension_change_table
        table.setSortingEnabled(False)
        table.setRowCount(len(filtered))
        for idx, (vals, is_exec_swap) in enumerate(filtered):
            self._set_stat_table_row(table, idx, vals, exec_swap_highlight=is_exec_swap)
        table.resizeColumnsToContents()
        table.setSortingEnabled(True)
        total = len(raw)
        shown = len(filtered)
        filt.set_count_text(f"Showing {shown} of {total}" if shown != total else "")

    def _apply_filename_entropy_filter(self) -> None:
        self._apply_stats_filter(
            self._stats_filename_entropy_table, "_filename_entropy_raw_data", self._filename_entropy_filter,
        )

    def _apply_ext_entropy_filter(self) -> None:
        self._apply_stats_filter(
            self._stats_ext_entropy_table, "_ext_entropy_raw_data", self._ext_entropy_filter,
        )

    def _apply_churn_filter(self) -> None:
        raw = getattr(self, "_churn_raw_data", [])
        filt = self._churn_filter
        filtered = [(vals, risk) for vals, risk in raw if filt.match_row(vals)]
        self._churn_table.setSortingEnabled(False)
        self._churn_table.setRowCount(len(filtered))
        # Build parallel filtered DirectoryChurnEntry list for double-click handler
        filtered_entries: list[DirectoryChurnEntry] = []
        raw_entries = getattr(self, "_churn_report_data", [])
        if len(raw_entries) == len(raw):
            for i, (vals, risk) in enumerate(raw):
                if filt.match_row(vals):
                    filtered_entries.append(raw_entries[i])
        self._churn_filtered_data = filtered_entries
        for idx, (vals, risk) in enumerate(filtered):
            self._set_stat_table_row(self._churn_table, idx, vals, risk_level=risk)
            # Store entry in first cell so double-click resolves correct row after sorting
            first = self._churn_table.item(idx, 0)
            if first is not None:
                first.setData(Qt.ItemDataRole.UserRole, filtered_entries[idx])
        self._churn_table.resizeColumnsToContents()
        self._churn_table.setSortingEnabled(True)
        total = len(raw)
        shown = len(filtered)
        filt.set_count_text(f"Showing {shown} of {total}" if shown != total else "")

    def _on_stats_sub_tab_changed(self, index: int) -> None:
        """When user switches to Temporal burst tab, auto-start computation once if not yet done."""
        if index != getattr(self, "_temporal_burst_tab_index", -1):
            return
        if getattr(self, "_temporal_burst_computed", True):
            return
        if self._temporal_burst_thread is not None and self._temporal_burst_thread.isRunning():
            return
        if not (self._records and len(self._records) > 0):
            return
        self._start_temporal_burst_computation()

    def _on_temporal_burst_progress_tick(self) -> None:
        bar = getattr(self, '_temporal_burst_progress_bar', None)
        if bar is None or not bar.isVisible():
            return
        maximum = bar.maximum() or 100
        step = max(1, maximum // 40)
        value = (bar.value() + step) % (maximum + 1)
        bar.setValue(value)

    def _start_temporal_burst_computation(self) -> None:
        """Run temporal burst report in a background thread so UI stays responsive."""
        if self._temporal_burst_thread is not None and self._temporal_burst_thread.isRunning():
            return
        records = list(self._records or [])
        if not records:
            self._temporal_burst_summary_label.setText("Load MFT first.")
            return
        path_table = getattr(self, "_path_table", None) or {}
        all_usn = getattr(self, "_usn_records", None) or []
        try:
            tb_window = int(getattr(self, "_churn_window_edit", None) and self._churn_window_edit.text() or 60)
        except (ValueError, TypeError):
            tb_window = 60
        self._temporal_burst_refresh_btn.setEnabled(False)
        self._temporal_burst_summary_label.setText("Computing in background…")
        self._temporal_burst_progress_bar.setValue(0)
        self._temporal_burst_progress_bar.setVisible(True)
        if hasattr(self, '_temporal_burst_progress_timer'):
            self._temporal_burst_progress_timer.start()
        self._temporal_burst_thread = TemporalBurstThread(records, path_table, all_usn, tb_window)
        self._temporal_burst_thread.result_ready.connect(self._on_temporal_burst_result)
        self._temporal_burst_thread.finished.connect(self._on_temporal_burst_thread_finished)
        self._temporal_burst_thread.start()

    def _on_temporal_burst_result(self, poisson_list: list, burstiness_list: list) -> None:
        """Update Temporal burst tables from background thread result (called on main thread)."""

        def _full_decimal(x: float, max_decimals: int = 10) -> str:
            """Format float as full decimal (no scientific notation); strip trailing zeros."""
            s = f"{x:.{max_decimals}f}".rstrip("0").rstrip(".")
            return s if s else "0"

        try:
            tb_window = int(getattr(self, "_churn_window_edit", None) and self._churn_window_edit.text() or 60)
        except (ValueError, TypeError):
            tb_window = 60
        self._temporal_burst_computed = True
        if hasattr(self, '_temporal_burst_progress_timer'):
            self._temporal_burst_progress_timer.stop()
        self._temporal_burst_progress_bar.setVisible(False)
        self._temporal_burst_summary_label.setText(
            f"{len(poisson_list)} unusual activity windows  |  "
            f"{len(burstiness_list)} directories with bursty pattern  |  window={tb_window}s"
        )
        self._temporal_burst_poisson_raw_data = []
        for e in poisson_list:
            self._temporal_burst_poisson_raw_data.append([
                e.window_start_iso,
                e.window_end_iso,
                str(e.observed_count),
                _full_decimal(e.baseline_per_min, 4),
                _full_decimal(e.p_value),
                "Yes" if e.is_anomaly else "",
            ])
        self._temporal_burst_burstiness_raw_data = []
        for e in burstiness_list:
            self._temporal_burst_burstiness_raw_data.append([
                e.directory,
                _full_decimal(e.burstiness_b, 4),
                e.interpretation,
                str(e.event_count),
                _full_decimal(e.mean_inter_arrival_sec, 2),
                _full_decimal(e.std_inter_arrival_sec, 2),
            ])
        self._apply_temporal_burst_poisson_filter()
        self._apply_temporal_burst_burstiness_filter()

    def _on_temporal_burst_thread_finished(self) -> None:
        if hasattr(self, '_temporal_burst_progress_timer'):
            self._temporal_burst_progress_timer.stop()
        self._temporal_burst_progress_bar.setVisible(False)
        self._temporal_burst_refresh_btn.setEnabled(True)
        self._temporal_burst_thread = None

    def _apply_temporal_burst_poisson_filter(self) -> None:
        self._apply_stats_filter(
            self._temporal_burst_poisson_table, "_temporal_burst_poisson_raw_data",
            self._temporal_burst_poisson_filter,
        )

    def _apply_temporal_burst_burstiness_filter(self) -> None:
        self._apply_stats_filter(
            self._temporal_burst_burstiness_table, "_temporal_burst_burstiness_raw_data",
            self._temporal_burst_burstiness_filter,
        )

    def _apply_survival_filter(self) -> None:
        self._apply_stats_filter(
            self._survival_table, "_survival_raw_data", self._survival_filter,
        )

    def _apply_style(self):
        # Unified professional theme: one font and palette for all buttons, tables, and text
        font_family = "Ubuntu"
        font_size = "10pt"
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: #1e1e2e;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QWidget {{
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QTableView, QTableWidget {{
                background-color: #313244;
                gridline-color: #45475a;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 6px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QTableView::item:selected, QTableWidget::item:selected {{
                background-color: #45475a;
                color: #cdd6f4;
            }}
            QTableView::item:alternate, QTableWidget::item:alternate {{
                background-color: #2a2a3e;
            }}
            QHeaderView::section {{
                background-color: #45475a;
                color: #a6adc8;
                padding: 8px;
                border: none;
                font-weight: bold;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QPushButton {{
                background-color: #45475a;
                color: #cdd6f4;
                border: none;
                padding: 8px 14px;
                border-radius: 6px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QPushButton:hover {{ background-color: #585b70; }}
            QPushButton:pressed {{ background-color: #89b4fa; color: #1e1e2e; }}
            QPushButton:disabled {{ color: #6c7086; }}
            QLineEdit, QComboBox {{
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 6px;
                min-height: 20px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QComboBox::drop-down {{ border: none; }}
            QTextEdit {{
                background-color: #11111b;
                color: #a6adc8;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 8px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QTabWidget::pane {{
                border: 1px solid #313244;
                border-radius: 6px;
                top: -1px;
                background-color: #1e1e2e;
            }}
            QTabBar::tab {{
                background-color: #313244;
                color: #a6adc8;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QTabBar::tab:selected {{
                background-color: #45475a;
                color: #89b4fa;
                font-weight: bold;
            }}
            QTabBar::tab:hover:!selected {{ background-color: #3a3a4a; }}
            QGroupBox {{
                color: #a6adc8;
                font-weight: bold;
                border: 1px solid #313244;
                border-radius: 4px;
                margin-top: 8px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QLabel {{
                color: #a6adc8;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QStatusBar {{
                background-color: #181825;
                color: #6c7086;
                border-top: 1px solid #313244;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QProgressDialog {{
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QListWidget {{
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QFrame#compoundFilterPanel {{
                background-color: #252637;
                border: 1px solid #45475a;
                border-radius: 8px;
            }}
            QLabel#filterDropHint {{
                color: #9399b2;
                padding-left: 2px;
            }}
            QListWidget#compoundFilterList {{
                background-color: #2a2b3d;
                border: 1px dashed #585b70;
                border-radius: 6px;
                padding: 2px;
            }}
            QListWidget#compoundFilterList::item {{
                margin: 1px 0px;
            }}
            QWidget#filterRow {{
                background-color: #313244;
                border: 1px solid #45475a;
                border-radius: 6px;
            }}
            QLabel#filterColumnLabel {{
                color: #bac2de;
                font-weight: 600;
            }}
            QSpinBox {{
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 4px;
                font-family: {font_family};
                font-size: {font_size};
            }}
            QFrame#statsFilterBar {{
                background-color: #252637;
                border: 1px solid #3b3d54;
                border-radius: 6px;
                padding: 0px;
            }}
            QPushButton#statsFilterToggle {{
                color: #89b4fa;
                font-weight: bold;
                font-size: 9pt;
                text-align: left;
                padding: 2px 6px;
                border: none;
                background: transparent;
            }}
            QPushButton#statsFilterToggle:hover {{
                color: #b4d0fb;
            }}
            QLabel#statsFilterCount {{
                color: #9399b2;
                font-size: 9pt;
                padding-left: 4px;
            }}
            QPushButton#statsFilterBtn {{
                font-size: 9pt;
                padding: 2px 10px;
                border-radius: 4px;
                background-color: #3b3d54;
                color: #cdd6f4;
                border: none;
            }}
            QPushButton#statsFilterBtn:hover {{
                background-color: #505270;
            }}
            QWidget#statsFilterRow {{
                background-color: #2a2b3d;
                border: 1px solid #3b3d54;
                border-radius: 4px;
            }}
            QFrame#compoundFilterPanel {{
                background-color: #252637;
                border: 1px solid #3b3d54;
                border-radius: 6px;
            }}
            QPushButton#compoundFilterToggle {{
                color: #89b4fa;
                font-weight: bold;
                font-size: 9pt;
                text-align: left;
                padding: 2px 6px;
                border: none;
                background: transparent;
            }}
            QPushButton#compoundFilterToggle:hover {{
                color: #b4d0fb;
            }}
            QPushButton#compoundFilterBtn {{
                font-size: 9pt;
                padding: 2px 10px;
                border-radius: 4px;
                background-color: #3b3d54;
                color: #cdd6f4;
                border: none;
            }}
            QPushButton#compoundFilterBtn:hover {{
                background-color: #505270;
            }}
        """)

    def _on_application_help(self):
        dialog = ApplicationHelpDialog(self)
        dialog.exec()

    def _on_open_mft(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select $MFT file",
            str(Path.home()),
            "All files (*);;MFT (*)",
        )
        if not path:
            return
        self._load_mft_file(Path(path))

    def _load_mft_file(self, path: Path):
        # Opening a new $MFT starts a fresh, unsaved session.
        self._session_file_path = None
        self._status.showMessage(f"Loading {path.name}...")
        self._progress = QProgressDialog("Loading MFT records...", None, 0, 0, self)
        self._progress.setWindowTitle("MFT Reader")
        self._progress.setMinimumDuration(0)
        self._progress.setWindowModality(Qt.WindowModality.WindowModal)
        # No limit: load full MFT (table uses lazy model)
        self._load_thread = LoadMFTThread(path, max_records=None)
        self._load_thread.progress.connect(self._on_load_progress)
        self._load_thread.progress_phase.connect(self._on_load_phase)
        self._load_thread.finished_load.connect(self._on_load_finished)
        self._load_thread.error.connect(self._on_load_error)
        self._load_thread.start()

    def _on_load_progress(self, current: int, total: int):
        progress = self._progress
        if progress is None:
            return
        try:
            if total > 0:
                progress.setMaximum(total)
                progress.setValue(current)
            progress.setLabelText(f"Loaded {current:,} records...")
        except (AttributeError, RuntimeError):
            pass

    def _on_load_phase(self, phase: str):
        if self._progress:
            try:
                self._progress.setLabelText(phase)
            except (AttributeError, RuntimeError):
                pass

    def _on_load_finished(self, records: list, path_table: dict):
        self._records = records
        self._path_table = path_table
        self._current_path = getattr(self._load_thread, "path", None) if self._load_thread else None
        self._btn_seq_report.setEnabled(True)
        self._menu_save_session_act.setEnabled(True)
        if hasattr(self, "_menu_save_session_as_act"):
            self._menu_save_session_as_act.setEnabled(True)
        self._menu_export_csv_act.setEnabled(True)
        self._mft_model.set_usn_delete_ticks_map(self._build_usn_delete_ticks_by_file_ref())
        self._mft_model.set_data(records, path_table)
        self._rebuild_full_usn_parent_paths()
        self._btn_rebuild_fs_tree.setEnabled(True)
        if self._progress:
            self._progress.close()
            self._progress = None
        self._on_filter_changed()
        valid_sigs = sum(1 for r in records if not r.parse_error)
        with_names = sum(1 for r in records if r.file_names)
        resolved = sum(1 for v in path_table.values() if v and v != "\\")
        self._status.showMessage(
            f"Loaded {len(records):,} MFT records  |  valid: {valid_sigs:,}  |  "
            f"with names: {with_names:,}  |  paths resolved: {resolved:,}"
        )
        self._refresh_statistics_tab()
        if self._usn_records:
            self._on_usn_tab_filter()

    def _build_usn_delete_ticks_by_file_ref(self) -> dict[tuple[int, int], int]:
        """
        Build (MFT#, sequence) -> latest USN FILE_DELETE timestamp (FILETIME ticks, UTC-based).
        Latest delete is used so timeline vectors reflect the most recent known lifecycle.
        """
        if not self._usn_by_mft:
            return {}
        out: dict[tuple[int, int], int] = {}
        for _mft_num, events in self._usn_by_mft.items():
            for evt in events:
                if not (evt.reason & USN_REASON_FILE_DELETE):
                    continue
                file_ref_key = (evt.mft_record_number(), (evt.file_ref >> 48) & 0xFFFF)
                prev = out.get(file_ref_key)
                if prev is None or evt.timestamp > prev:
                    out[file_ref_key] = evt.timestamp
        return out

    def _on_load_error(self, msg: str):
        if self._progress:
            self._progress.close()
            self._progress = None
        QMessageBox.critical(self, "MFT Reader", msg)
        self._status.showMessage("Load failed.")

    def _build_session_state(self) -> dict:
        """Build state dict for saving to SQLite (records, path_table, filters, stats, ui_state)."""
        filters = {
            "mft": [criterion_to_dict(c) for c in self._mft_filter_panel.get_filters()],
            "usn": [criterion_to_dict(c) for c in self._usn_filter_panel.get_filters()],
            "stat_anomaly": [criterion_to_dict(c) for c in self._anomaly_filter.get_filters()],
            "stat_ext_change": [criterion_to_dict(c) for c in self._ext_change_filter.get_filters()],
            "stat_fn_entropy": [criterion_to_dict(c) for c in self._filename_entropy_filter.get_filters()],
            "stat_ext_entropy": [criterion_to_dict(c) for c in self._ext_entropy_filter.get_filters()],
            "stat_churn": [criterion_to_dict(c) for c in self._churn_filter.get_filters()],
            "stat_tb_poisson": [criterion_to_dict(c) for c in self._temporal_burst_poisson_filter.get_filters()],
            "stat_tb_burstiness": [criterion_to_dict(c) for c in self._temporal_burst_burstiness_filter.get_filters()],
            "stat_survival": [criterion_to_dict(c) for c in self._survival_filter.get_filters()],
        }
        stats = {
            "anomaly_raw": getattr(self, "_anomaly_seq_raw_data", []),
            "anomaly_detail_data": getattr(self, "_anomaly_seq_detail_data", []),
            "ext_change_raw": getattr(self, "_ext_change_raw_data", []),
            "fn_entropy_raw": getattr(self, "_filename_entropy_raw_data", []),
            "ext_entropy_raw": getattr(self, "_ext_entropy_raw_data", []),
            "churn_raw": getattr(self, "_churn_raw_data", []),
            "churn_report_data": getattr(self, "_churn_report_data", []),
            "poisson_raw": getattr(self, "_temporal_burst_poisson_raw_data", []),
            "burstiness_raw": getattr(self, "_temporal_burst_burstiness_raw_data", []),
            "survival_raw": getattr(self, "_survival_raw_data", []),
            "survival_histogram": self._survival_histogram_snapshot(),
        }
        hdr = self._table.horizontalHeader()
        n_mft_cols = len(MFTTableModel.COLUMNS)
        ui_state = {
            "mft_sort_column": hdr.sortIndicatorSection() if hdr.sortIndicatorSection() >= 0 else 0,
            "mft_sort_order": "descending" if hdr.sortIndicatorOrder() == Qt.SortOrder.DescendingOrder else "ascending",
            "mft_column_widths": [self._table.columnWidth(c) for c in range(n_mft_cols)],
            "mft_hidden_columns": [c for c in range(n_mft_cols) if self._table.isColumnHidden(c)],
            "mft_scroll_value": self._table.verticalScrollBar().value(),
            "usn_sort_column": getattr(self, "_usn_sort_column", 0),
            "usn_sort_order": "descending" if getattr(self, "_usn_sort_order", Qt.SortOrder.DescendingOrder) == Qt.SortOrder.DescendingOrder else "ascending",
            "usn_anchor_ticks": self._usn_anchor_ticks,
            "usn_anchor_seconds": self._usn_anchor_seconds_spin.value(),
            "usn_anchor_time_text": self._usn_anchor_time_edit.text(),
            "churn_window": self._churn_window_edit.text(),
            "churn_min_files": self._churn_min_files_spin.value(),
            "ext_change_only_highlight": getattr(self, "_ext_change_only_highlight_cb", None) and self._ext_change_only_highlight_cb.isChecked(),
        }
        fs_tree_state = None
        if getattr(self, "_fs_tree_data", None) is not None:
            expanded = self._collect_fs_tree_expanded()
            fs_tree_state = {"data": self._fs_tree_data, "expanded": list(expanded)}
        kill_chain_flat = []
        for phase in KILL_CHAIN_PHASES:
            for mft_num in self._kill_chain_entries.get(phase, []):
                kill_chain_flat.append({"phase": phase, "mft_record_number": mft_num})
        forensic_report_text = ""
        if hasattr(self, "_report_text"):
            forensic_report_text = self._report_text.toPlainText() or ""
        return {
            "mft_records": self._records,
            "path_table": self._path_table,
            "usn_records": self._usn_records if self._usn_records else [],
            "filters": filters,
            "stats": stats,
            "ui_state": ui_state,
            "fs_tree": fs_tree_state,
            "kill_chain": kill_chain_flat,
            "forensic_report_text": forensic_report_text,
        }

    def _survival_histogram_snapshot(self) -> list[tuple[str, int]]:
        """Capture current survival histogram as (label, count) for session save."""
        out = []
        tbl = getattr(self, "_survival_histogram_table", None)
        if tbl and tbl.rowCount() > 0:
            for row in range(tbl.rowCount()):
                label_item = tbl.item(row, 0)
                count_item = tbl.item(row, 1)
                if label_item and count_item:
                    try:
                        out.append((label_item.text(), int(count_item.text())))
                    except ValueError:
                        pass
        return out

    def _on_save_session(self):
        if not self._records:
            self._status.showMessage("Load $MFT first before saving a session.")
            return
        target_path = self._session_file_path
        if target_path is None:
            default_name = (self._current_path.stem if self._current_path else "session") + ".mftsession"
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Save session",
                default_name,
                SESSION_FILE_FILTER,
            )
            if not path:
                return
            target_path = Path(path)
            self._session_file_path = target_path
        try:
            state = self._build_session_state()
            name = target_path.stem
            save_session_to_file(
                target_path,
                state,
                name=name,
                mft_path=str(self._current_path) if self._current_path else None,
                usn_path=str(self._usn_path) if self._usn_path else None,
            )
            self._status.showMessage(f"Session saved to {target_path}. Use File → Load session to restore.")
            QMessageBox.information(self, "MFT Reader", f"Session saved successfully to:\n{target_path}")
        except Exception as e:
            QMessageBox.critical(self, "MFT Reader", f"Failed to save session: {e}")
            self._status.showMessage("Save session failed.")

    def _on_save_session_as(self):
        """Save current session state to a new session file (always prompts for path)."""
        if not self._records:
            self._status.showMessage("Load $MFT first before saving a session.")
            return
        default_name = (self._current_path.stem if self._current_path else "session") + ".mftsession"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save session as",
            default_name,
            SESSION_FILE_FILTER,
        )
        if not path:
            return
        target_path = Path(path)
        try:
            state = self._build_session_state()
            name = target_path.stem
            save_session_to_file(
                target_path,
                state,
                name=name,
                mft_path=str(self._current_path) if self._current_path else None,
                usn_path=str(self._usn_path) if self._usn_path else None,
            )
            # Update current session file to this new path so subsequent "Save session" overwrites it.
            self._session_file_path = target_path
            self._status.showMessage(f"Session saved to {target_path}. Use File → Load session to restore.")
            QMessageBox.information(self, "MFT Reader", f"Session saved successfully to:\n{target_path}")
        except Exception as e:
            QMessageBox.critical(self, "MFT Reader", f"Failed to save session: {e}")
            self._status.showMessage("Save session (as) failed.")

    def _on_load_session(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load session",
            "",
            SESSION_FILE_FILTER,
        )
        if not path:
            return
        try:
            state = load_session_from_file(path)
            self._session_file_path = Path(path)
            self._apply_loaded_session(state)
            self._status.showMessage(f"Session loaded from {path}. No recalculation needed.")
        except Exception as e:
            QMessageBox.critical(self, "MFT Reader", f"Failed to load session: {e}")
            self._status.showMessage("Load session failed.")

    def _apply_loaded_session(self, state: dict) -> None:
        """Restore full UI state from a loaded session (no MFT/USN re-parse or stats recompute)."""
        records = state["mft_records"]
        path_table = state["path_table"]
        usn_records = state.get("usn_records") or []
        self._records = records
        self._path_table = path_table
        self._current_path = Path(state["mft_path"]) if state.get("mft_path") else None
        self._usn_records = usn_records
        self._usn_by_mft = usn_close_events_by_mft(usn_records) if usn_records else {}
        self._usn_path = Path(state["usn_path"]) if state.get("usn_path") else None
        # Restore file system tree state if it was saved
        fs_tree_state = state.get("fs_tree")
        if fs_tree_state and isinstance(fs_tree_state, dict) and fs_tree_state.get("data") is not None:
            self._fs_tree_data = fs_tree_state["data"]
            self._fs_tree_rec_to_index = {r.record_number: i for i, r in enumerate(self._records)}
            self._fs_tree_populated = False
            self._fs_tree_widget.clear()
            self._populate_fs_tree_if_needed()
            expanded = fs_tree_state.get("expanded") or []
            if expanded:
                self._restore_fs_tree_expanded(expanded)
        else:
            self._fs_tree_data = None
            self._fs_tree_populated = False
        self._mft_model.set_usn_delete_ticks_map(self._build_usn_delete_ticks_by_file_ref())
        self._mft_model.set_data(records, path_table)
        self._rebuild_full_usn_parent_paths()
        self._btn_seq_report.setEnabled(True)
        self._menu_save_session_act.setEnabled(True)
        if hasattr(self, "_menu_save_session_as_act"):
            self._menu_save_session_as_act.setEnabled(True)
        self._menu_export_csv_act.setEnabled(True)
        self._btn_rebuild_fs_tree.setEnabled(True)
        # Restore filters (order matters: set filters then apply)
        filters = state.get("filters") or {}
        for panel_id, criteria_dicts in filters.items():
            criteria = [dict_to_criterion(d, FilterCriterion) for d in criteria_dicts]
            if panel_id == "mft" and hasattr(self, "_mft_filter_panel"):
                self._mft_filter_panel.set_filters(criteria)
            elif panel_id == "usn" and hasattr(self, "_usn_filter_panel"):
                self._usn_filter_panel.set_filters(criteria)
            elif panel_id == "stat_anomaly":
                self._anomaly_filter.set_filters(criteria)
            elif panel_id == "stat_ext_change":
                self._ext_change_filter.set_filters(criteria)
            elif panel_id == "stat_fn_entropy":
                self._filename_entropy_filter.set_filters(criteria)
            elif panel_id == "stat_ext_entropy":
                self._ext_entropy_filter.set_filters(criteria)
            elif panel_id == "stat_churn":
                self._churn_filter.set_filters(criteria)
            elif panel_id == "stat_tb_poisson":
                self._temporal_burst_poisson_filter.set_filters(criteria)
            elif panel_id == "stat_tb_burstiness":
                self._temporal_burst_burstiness_filter.set_filters(criteria)
            elif panel_id == "stat_survival":
                self._survival_filter.set_filters(criteria)
        # UI state
        ui = state.get("ui_state") or {}
        sort_col = ui.get("mft_sort_column", 0)
        sort_order = Qt.SortOrder.DescendingOrder if ui.get("mft_sort_order") == "descending" else Qt.SortOrder.AscendingOrder
        self._table.horizontalHeader().setSortIndicator(sort_col, sort_order)
        self._usn_sort_column = int(ui.get("usn_sort_column", 0))
        self._usn_sort_order = Qt.SortOrder.DescendingOrder if ui.get("usn_sort_order") == "descending" else Qt.SortOrder.AscendingOrder
        self._usn_anchor_ticks = ui.get("usn_anchor_ticks")
        self._usn_anchor_seconds_spin.setValue(int(ui.get("usn_anchor_seconds", 30)))
        self._usn_anchor_time_edit.setText(ui.get("usn_anchor_time_text") or "")
        if "churn_window" in ui:
            self._churn_window_edit.setText(str(ui["churn_window"]))
        if "churn_min_files" in ui:
            self._churn_min_files_spin.setValue(int(ui["churn_min_files"]))
        if "ext_change_only_highlight" in ui and hasattr(self, "_ext_change_only_highlight_cb"):
            self._ext_change_only_highlight_cb.setChecked(bool(ui["ext_change_only_highlight"]))
        self._on_filter_changed()
        # Restore MFT table view state (column widths, hidden columns, scroll)
        mft_widths = ui.get("mft_column_widths")
        if mft_widths and len(mft_widths) <= len(MFTTableModel.COLUMNS):
            for c, w in enumerate(mft_widths):
                if c < len(MFTTableModel.COLUMNS):
                    self._table.setColumnWidth(c, max(20, int(w)))
        mft_hidden = ui.get("mft_hidden_columns")
        if mft_hidden is not None:
            for c in range(len(MFTTableModel.COLUMNS)):
                self._table.setColumnHidden(c, c in mft_hidden)
        mft_scroll = ui.get("mft_scroll_value")
        if mft_scroll is not None and isinstance(mft_scroll, (int, float)):
            self._table.verticalScrollBar().setValue(int(mft_scroll))
        # Stats raw data and tables (no recompute)
        stats = state.get("stats") or {}
        self._anomaly_seq_raw_data = stats.get("anomaly_raw", [])
        self._anomaly_seq_detail_data = stats.get("anomaly_detail_data", [])
        ext_raw = stats.get("ext_change_raw", [])
        # Normalize: support both old format (list of lists) and new (list of [vals, is_exec_swap])
        self._ext_change_raw_data = []
        for item in ext_raw:
            if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[1], bool):
                self._ext_change_raw_data.append((list(item[0]), item[1]))
            elif isinstance(item, (list, tuple)) and item:
                self._ext_change_raw_data.append((list(item), False))
        self._filename_entropy_raw_data = stats.get("fn_entropy_raw", [])
        self._ext_entropy_raw_data = stats.get("ext_entropy_raw", [])
        self._churn_raw_data = stats.get("churn_raw", [])
        self._churn_report_data = stats.get("churn_report_data", [])
        self._temporal_burst_poisson_raw_data = stats.get("poisson_raw", [])
        self._temporal_burst_burstiness_raw_data = stats.get("burstiness_raw", [])
        self._temporal_burst_computed = bool(self._temporal_burst_poisson_raw_data or self._temporal_burst_burstiness_raw_data)
        self._survival_raw_data = stats.get("survival_raw", [])
        self._apply_anomaly_filter()
        self._apply_ext_change_filter()
        self._apply_filename_entropy_filter()
        self._apply_ext_entropy_filter()
        self._apply_churn_filter()
        self._apply_temporal_burst_poisson_filter()
        self._apply_temporal_burst_burstiness_filter()
        self._apply_survival_filter()
        # Survival histogram
        hist = stats.get("survival_histogram") or []
        if hist and hasattr(self, "_survival_histogram_table"):
            self._survival_histogram_table.setSortingEnabled(False)
            self._survival_histogram_table.setRowCount(len(hist))
            for row_idx, (label, count) in enumerate(hist):
                self._survival_histogram_table.setItem(row_idx, 0, QTableWidgetItem(label))
                self._survival_histogram_table.setItem(row_idx, 1, QTableWidgetItem(str(count)))
                max_count = max((c for _, c in hist), default=1)
                bar_len = int(round(24 * count / max_count)) if max_count else 0
                self._survival_histogram_table.setItem(row_idx, 2, QTableWidgetItem("\u2588" * bar_len))
            self._survival_histogram_table.setSortingEnabled(True)
        n_survival = len(self._survival_raw_data)
        if hasattr(self, "_survival_summary_label"):
            self._survival_summary_label.setText(
                f"Deleted files with known time to delete: {n_survival} (from saved session)."
            )
        # Restore Kill Chain tab
        self._kill_chain_entries = {p: [] for p in KILL_CHAIN_PHASES}
        for entry in state.get("kill_chain") or []:
            ph = entry.get("phase")
            mft_num = entry.get("mft_record_number")
            if ph in self._kill_chain_entries and mft_num is not None:
                self._kill_chain_entries[ph].append(mft_num)
        if hasattr(self, "_kill_chain_tables") and self._kill_chain_tab_index >= 0:
            self._refresh_kill_chain_tab()
        if self._usn_records:
            self._on_usn_tab_filter()
        # Restore forensic analysis report: use saved text if present, else regenerate
        if hasattr(self, "_report_text"):
            saved_report = state.get("forensic_report_text")
            if saved_report:
                self._report_text.setPlainText(saved_report)
            else:
                self._refresh_analysis_report()
        valid_sigs = sum(1 for r in records if not r.parse_error)
        with_names = sum(1 for r in records if r.file_names)
        resolved = sum(1 for v in path_table.values() if v and v != "\\")
        self._status.showMessage(
            f"Session loaded: {len(records):,} MFT records  |  valid: {valid_sigs:,}  |  paths: {resolved:,}"
        )

    def _on_main_tab_changed(self, index: int):
        """When switching to USN Journal tab, refresh table so parent paths and filter match current MFT state.
        Reparent time anchor bar so it is only visible in MFT (0) or USN Journal (1) tabs."""
        mft_tab_index = 0
        row = getattr(self, "_time_anchor_row", None)
        if index == mft_tab_index:
            if row:
                # Only reparent if currently in another tab; avoid remove+skip-insert on first load (would leave row out of layout)
                if row.parent() != self._mft_tab and row.parent() and row.parent().layout():
                    row.parent().layout().removeWidget(row)
                if getattr(self, "_mft_tab", None) and (not row.parent() or row.parent() != self._mft_tab):
                    self._mft_tab.layout().insertWidget(2, row)
                row.show()
        elif index == self._usn_tab_index:
            if row:
                if row.parent() != self._usn_tab and row.parent() and row.parent().layout():
                    row.parent().layout().removeWidget(row)
                if getattr(self, "_usn_tab", None) and (not row.parent() or row.parent() != self._usn_tab):
                    self._usn_tab.layout().insertWidget(2, row)
                row.show()
            if self._usn_records:
                QTimer.singleShot(0, self._on_usn_tab_filter)
        else:
            if row and row.parent() and row.parent().layout():
                row.parent().layout().removeWidget(row)
            if row:
                row.hide()
        if getattr(self, "_fs_tree_tab_index", -1) >= 0 and index == self._fs_tree_tab_index:
            self._populate_fs_tree_if_needed()
        # Analysis tab: do not auto-refresh on switch (would block UI ~1 min). Data is already
        # computed after MFT/USN load; user can click Refresh in sub-tabs (e.g. Directory churn) to recompute.

    def _on_usn_anchor_time_edited(self):
        """Update _usn_anchor_ticks from the anchor time line edit (ISO string)."""
        text = (self._usn_anchor_time_edit.text() or "").strip()
        self._usn_anchor_ticks = iso_to_win_timestamp(text) if text else None

    def _on_usn_anchor_seconds_changed(self, value: int):
        self._usn_anchor_seconds = value

    def _on_usn_set_anchor_from_selection(self):
        """Set anchor time from the selected row's time column. Uses selection from MFT or USN table based on chosen time column (no need to be on that tab)."""
        data = self._usn_time_column_combo.currentData()
        if data is None or not isinstance(data, (list, tuple)) or len(data) < 2:
            return
        table_id, col_index = data[0], int(data[1])
        iso_value: str | None = None
        if table_id == "mft":
            rows = self._table.selectionModel().selectedRows()
            if not rows:
                self._status.showMessage("Select a row in the MFT table, then click Set from selection.")
                return
            view_row = rows[0].row()
            rec = self._mft_model.record_at(view_row)
            if rec is None:
                return
            if col_index == 5:
                iso_value = rec.created_iso()
            elif col_index == 6:
                iso_value = rec.modified_iso()
            elif col_index == 7:
                iso_value = rec.standard_info.mft_modified_iso() if rec.standard_info else ""
            elif col_index == 8:
                iso_value = rec.standard_info.accessed_iso() if rec.standard_info else ""
            elif col_index == 9:
                pfn = rec.primary_file_name()
                iso_value = pfn.created_iso() if pfn else ""
            if not iso_value:
                self._status.showMessage("Selected row has no value for that time column.")
                return
        else:
            rows = self._usn_table.selectionModel().selectedRows()
            if not rows:
                self._status.showMessage("Select a row in the USN Journal table, then click Set from selection.")
                return
            row = rows[0].row()
            item = self._usn_table.item(row, col_index)
            iso_value = item.text() if item else ""
            if not iso_value:
                self._status.showMessage("Selected row has no timestamp.")
                return
        self._usn_anchor_time_edit.setText(iso_value)
        ticks = iso_to_win_timestamp(iso_value)
        self._usn_anchor_ticks = ticks
        self._status.showMessage(f"Time anchor set to {iso_value}. Apply filter to show ±{self._usn_anchor_seconds} sec.")

    def _usn_record_matches_search(self, rec: UsnRecord, parent_path: str, search_lower: str, use_glob: bool) -> bool:
        """Return True if this USN record matches the search (same columns as table). Supports * and ? glob patterns."""
        hay = [
            rec.timestamp_iso(),
            str(rec.usn),
            str(rec.mft_record_number()),
            rec.file_name,
            parent_path,
            rec.reason_string(),
        ]
        if use_glob:
            return any(fnmatch.fnmatch(part.lower(), search_lower) for part in hay)
        return search_lower in " ".join(hay).lower()

    def _usn_row_cell_values(self, rec, parent_path: str) -> list[str]:
        """Return display cell values for this USN row (same order as USN_COLUMNS)."""
        return [
            rec.timestamp_iso(),
            str(rec.usn),
            str(rec.mft_record_number()),
            rec.file_name or "",
            parent_path or "\\",
            rec.reason_string(),
        ]

    def _usn_apply_search_filter(
        self,
        rows: list,
        path_table: dict,
        rec_by_num: dict,
        search: str,
        criteria: list,
    ) -> list[tuple] | None:
        """Filter rows by search and/or compound column criteria. Returns list of (rec, parent_path) or None if no filters set."""
        search = search.strip().lower()
        criteria = criteria or []
        if not search and not criteria:
            return None
        use_glob = "*" in search or "?" in search
        total = len(rows)
        progress = QProgressDialog("Applying filters...", None, 0, total, self)
        progress.setMinimumDuration(0)
        progress.setValue(0)
        matched = []
        batch_evt = 5000
        has_mft_loaded = bool(rec_by_num)
        no_path_hint = "(Load $MFT first to see path)" if not has_mft_loaded else None
        for i, rec in enumerate(rows):
            pp = parent_path_for_usn_record(rec, path_table, rec_by_num) if has_mft_loaded else no_path_hint
            pp = pp if pp else "\\"
            if search and not self._usn_record_matches_search(rec, pp, search, use_glob):
                continue
            if criteria:
                cells = self._usn_row_cell_values(rec, pp)
                if not all(
                    criterion_matches(cells[c.col_index], c.operator, c.value, c.col_type)
                    for c in criteria
                    if 0 <= c.col_index < len(cells)
                ):
                    continue
            matched.append((rec, pp))
            if (i + 1) % batch_evt == 0:
                progress.setValue(i + 1)
                QApplication.processEvents()
        progress.setValue(total)
        progress.close()
        return matched

    def _on_usn_tab_filter(self):
        if not self._usn_records:
            self._usn_lazy_showing = []
            self._usn_lazy_parent_paths = []
            self._usn_lazy_total_filtered = 0
            return
        rows = list(self._usn_records)
        rows.sort(key=lambda r: -r.timestamp)
        # Time anchor: show only USN activities within ± N seconds of the set anchor time
        if self._usn_anchor_ticks is not None:
            delta_100ns = self._usn_anchor_seconds * 10 * 1_000_000  # seconds -> 100ns
            low = self._usn_anchor_ticks - delta_100ns
            high = self._usn_anchor_ticks + delta_100ns
            rows = [r for r in rows if low <= r.timestamp <= high]
        path_table = self._path_table or {}
        rec_by_num = {r.record_number: r for r in self._records} if self._records else {}
        # Show hint only when MFT was never loaded (no records); if MFT is loaded we always resolve paths
        has_mft_loaded = bool(self._records)
        search = ""
        criteria = self._usn_filter_panel.get_filters() if hasattr(self, "_usn_filter_panel") else []
        matched = self._usn_apply_search_filter(rows, path_table, rec_by_num, search, criteria)
        if matched is not None:
            showing = [r for r, _ in matched[:50_000]]
            parent_paths = [pp for _, pp in matched[:50_000]]
            total_filtered = len(matched)
        else:
            display_limit = 50_000
            showing = rows[:display_limit]
            parent_paths = []
            no_path_hint = "(Load $MFT first to see path)" if not has_mft_loaded else None
            for i, rec in enumerate(showing):
                pp = parent_path_for_usn_record(rec, path_table, rec_by_num) if has_mft_loaded else no_path_hint
                parent_paths.append(pp if pp else "\\")
                if (i + 1) % 5000 == 0:
                    QApplication.processEvents()
            total_filtered = len(rows)

        self._usn_lazy_showing = showing
        self._usn_lazy_parent_paths = parent_paths
        self._usn_lazy_total_filtered = total_filtered
        self._sort_usn_backing_rows(self._usn_sort_column, self._usn_sort_order)
        initial_count = min(INITIAL_USN_ROWS, len(showing))
        self._usn_table.setSortingEnabled(False)
        self._usn_table.setRowCount(initial_count)
        self._usn_refresh_id += 1
        refresh_id = self._usn_refresh_id
        thread = UsnTableRefreshThread(
            self._usn_lazy_showing[:initial_count],
            self._usn_lazy_parent_paths[:initial_count],
            "",
            total_filtered,
        )
        thread.batch_ready.connect(lambda start, b: self._on_usn_batch(start, b, refresh_id))
        thread.finished_refresh.connect(lambda sc, note, tr: self._on_usn_refresh_finished(sc, note, tr, refresh_id))
        self._usn_refresh_thread = thread
        thread.start()

    def _usn_sort_key(self, rec: UsnRecord, parent_path: str, column: int):
        if column == 0:
            return int(rec.timestamp)
        if column == 1:
            return int(rec.usn)
        if column == 2:
            return int(rec.mft_record_number())
        if column == 3:
            return (rec.file_name or "").lower()
        if column == 4:
            return (parent_path or "\\").lower()
        if column == 5:
            return rec.reason_string().lower()
        return int(rec.timestamp)

    def _sort_usn_backing_rows(self, column: int, order: Qt.SortOrder):
        if not self._usn_lazy_showing:
            return
        reverse = order == Qt.SortOrder.DescendingOrder
        pairs = list(zip(self._usn_lazy_showing, self._usn_lazy_parent_paths))
        pairs.sort(key=lambda rp: self._usn_sort_key(rp[0], rp[1], column), reverse=reverse)
        self._usn_lazy_showing = [rec for rec, _ in pairs]
        self._usn_lazy_parent_paths = [pp for _, pp in pairs]

    def _rerender_usn_lazy_from_start(self):
        if not self._usn_lazy_showing:
            self._usn_table.setRowCount(0)
            self._usn_lazy_loaded_count = 0
            self._usn_count_label.setText("0 events")
            return
        initial_count = min(INITIAL_USN_ROWS, len(self._usn_lazy_showing))
        self._usn_table.setRowCount(initial_count)
        anchor = getattr(self, "_usn_anchor_ticks", None)
        for row in range(initial_count):
            rec = self._usn_lazy_showing[row]
            parent_path = self._usn_lazy_parent_paths[row]
            row_items = _build_usn_row_items(rec, parent_path, anchor)
            _apply_row_risk_colors(row_items, _usn_row_risk_level(rec, parent_path))
            for col_idx, item in enumerate(row_items):
                self._usn_table.setItem(row, col_idx, item)
            if (row + 1) % 500 == 0:
                QApplication.processEvents()
        self._usn_lazy_loaded_count = initial_count
        all_loaded = self._usn_lazy_loaded_count >= len(self._usn_lazy_showing)
        if all_loaded and initial_count <= 10000:
            self._usn_table.resizeRowsToContents()
        else:
            self._usn_table.verticalHeader().setDefaultSectionSize(24)
        display_limit = 50_000
        if self._usn_lazy_total_filtered > display_limit:
            self._usn_count_label_base = f"Showing first {display_limit:,} of {self._usn_lazy_total_filtered:,}"
        else:
            self._usn_count_label_base = f"{self._usn_lazy_total_filtered:,} events"
        self._usn_count_label.setText(
            self._usn_count_label_base
            if all_loaded
            else f"{self._usn_lazy_loaded_count:,} of {len(self._usn_lazy_showing):,} loaded — scroll for more"
        )
        try:
            self._usn_table.verticalScrollBar().valueChanged.disconnect(self._on_usn_scroll)
        except (TypeError, RuntimeError):
            pass
        if not all_loaded and len(self._usn_lazy_showing) > self._usn_lazy_loaded_count:
            self._usn_table.verticalScrollBar().valueChanged.connect(self._on_usn_scroll)

    def _on_usn_header_clicked(self, logical_index: int):
        if logical_index < 0 or logical_index >= 6:
            return
        if self._usn_refresh_thread is not None:
            self._status.showMessage("USN rows are still loading. Please try sorting again in a moment.")
            return
        if logical_index == self._usn_sort_column:
            self._usn_sort_order = (
                Qt.SortOrder.DescendingOrder
                if self._usn_sort_order == Qt.SortOrder.AscendingOrder
                else Qt.SortOrder.AscendingOrder
            )
        else:
            self._usn_sort_column = logical_index
            self._usn_sort_order = Qt.SortOrder.AscendingOrder
        self._sort_usn_backing_rows(self._usn_sort_column, self._usn_sort_order)
        self._usn_table.horizontalHeader().setSortIndicator(self._usn_sort_column, self._usn_sort_order)
        self._rerender_usn_lazy_from_start()

    def _on_usn_batch(self, start_row: int, batch: list, refresh_id: int):
        if refresh_id != self._usn_refresh_id:
            return
        anchor = getattr(self, "_usn_anchor_ticks", None)
        for i, row_data in enumerate(batch):
            row = start_row + i
            ts, usn_str, mft_str, file_name, parent_path, reason_str = row_data
            rec_for_row = self._usn_lazy_showing[row] if row < len(self._usn_lazy_showing) else None
            if rec_for_row is not None:
                row_items = _build_usn_row_items(rec_for_row, parent_path, anchor)
                _apply_row_risk_colors(row_items, _usn_row_risk_level(rec_for_row, parent_path))
            else:
                row_items = [
                    SortableTableWidgetItem(ts),
                    SortableTableWidgetItem(usn_str),
                    SortableTableWidgetItem(mft_str),
                    SortableTableWidgetItem(file_name),
                    SortableTableWidgetItem(parent_path),
                    SortableTableWidgetItem(reason_str),
                ]
            for col_idx, item in enumerate(row_items):
                self._usn_table.setItem(row, col_idx, item)

    def _on_usn_refresh_finished(self, showing_count: int, mft_note: str, total_rows_filtered: int, refresh_id: int):
        if refresh_id != self._usn_refresh_id:
            return
        self._usn_refresh_thread = None
        self._usn_lazy_loaded_count = showing_count
        all_loaded = showing_count >= len(self._usn_lazy_showing)
        self._usn_table.horizontalHeader().setSortIndicator(self._usn_sort_column, self._usn_sort_order)
        if all_loaded:
            if showing_count <= 10000:
                self._usn_table.resizeRowsToContents()
            else:
                self._usn_table.verticalHeader().setDefaultSectionSize(24)
        else:
            self._usn_table.verticalHeader().setDefaultSectionSize(24)
        display_limit = 50_000
        if total_rows_filtered > display_limit:
            self._usn_count_label_base = f"Showing first {display_limit:,} of {total_rows_filtered:,}"
        else:
            self._usn_count_label_base = f"{total_rows_filtered:,} events"
        self._usn_count_label.setText(f"{self._usn_lazy_loaded_count:,} of {len(self._usn_lazy_showing):,} loaded — scroll for more" if not all_loaded else self._usn_count_label_base)
        try:
            self._usn_table.verticalScrollBar().valueChanged.disconnect(self._on_usn_scroll)
        except (TypeError, RuntimeError):
            pass
        if not all_loaded and len(self._usn_lazy_showing) > self._usn_lazy_loaded_count:
            self._usn_table.verticalScrollBar().valueChanged.connect(self._on_usn_scroll)

    def _on_usn_scroll(self):
        """Load more USN rows when user scrolls near the bottom (lazy loading)."""
        if self._usn_lazy_loading or self._usn_lazy_loaded_count >= len(self._usn_lazy_showing):
            return
        sb = self._usn_table.verticalScrollBar()
        if sb.maximum() <= 0:
            return
        threshold = 400
        if sb.value() + sb.pageStep() < sb.maximum() - threshold:
            return
        self._usn_lazy_loading = True
        start = self._usn_lazy_loaded_count
        batch = min(LOAD_MORE_USN_BATCH, len(self._usn_lazy_showing) - start)
        if batch <= 0:
            self._usn_lazy_loading = False
            return
        self._usn_table.setRowCount(start + batch)
        anchor = getattr(self, "_usn_anchor_ticks", None)
        for i in range(batch):
            row = start + i
            rec = self._usn_lazy_showing[row]
            parent_path = self._usn_lazy_parent_paths[row]
            row_items = _build_usn_row_items(rec, parent_path, anchor)
            _apply_row_risk_colors(row_items, _usn_row_risk_level(rec, parent_path))
            for col_idx, item in enumerate(row_items):
                self._usn_table.setItem(row, col_idx, item)
            if (i + 1) % 500 == 0:
                QApplication.processEvents()
        self._usn_lazy_loaded_count = start + batch
        all_loaded = self._usn_lazy_loaded_count >= len(self._usn_lazy_showing)
        if all_loaded:
            try:
                self._usn_table.verticalScrollBar().valueChanged.disconnect(self._on_usn_scroll)
            except (TypeError, RuntimeError):
                pass
            self._usn_count_label.setText(self._usn_count_label_base)
        else:
            self._usn_count_label.setText(f"{self._usn_lazy_loaded_count:,} of {len(self._usn_lazy_showing):,} loaded — scroll for more")
        self._usn_lazy_loading = False

    def _filtered_rows(self) -> list[int]:
        """Return list of view (proxy) row indices currently shown (for export/copy)."""
        return list(range(self._mft_model.rowCount()))

    def _search_matches(self, search: str, rec: MFTRecord) -> bool:
        """Return True if the search pattern matches this record. Supports * and ? glob patterns."""
        search = search.strip().lower()
        if not search:
            return True
        display_name = (rec.primary_name() or "").lower()
        all_names = [f.name for f in rec.file_names if f.name]
        mft_str = str(rec.record_number)
        if "*" in search or "?" in search:
            # Glob: match only the display name (what you see in the table)
            if display_name:
                # Strict: *.ext must match only names ending with .ext (e.g. *.csv ≠ .js.gz)
                if search.startswith("*") and "." in search and search.rfind("*") == 0 and "?" not in search[1:]:
                    suffix = search[1:]
                    if display_name.endswith(suffix):
                        return True
                elif fnmatch.fnmatch(display_name, search):
                    return True
            if fnmatch.fnmatch(mft_str, search):
                return True
            return False
        # Plain substring
        hay = " ".join([mft_str, display_name] + all_names).lower()
        return search in hay

    def _record_for_table_row(self, view_row: int) -> MFTRecord | None:
        """Get the record displayed in this table row (view row = proxy row)."""
        return self._mft_model.record_at(view_row)

    def _mft_record_by_number(self, mft_num: int) -> MFTRecord | None:
        """Resolve MFT record number to MFTRecord; returns None if not in loaded data."""
        if not self._records:
            return None
        rec_by_num = {r.record_number: r for r in self._records}
        return rec_by_num.get(mft_num)

    def _add_file_to_kill_chain_phase(self, mft_record_number: int, phase: str) -> None:
        """Add a file (by MFT #) to a kill chain phase, refresh the tab, and switch to it."""
        if phase not in self._kill_chain_entries:
            self._kill_chain_entries[phase] = []
        self._kill_chain_entries[phase].append(mft_record_number)
        if hasattr(self, "_kill_chain_tables") and self._kill_chain_tab_index >= 0:
            self._refresh_kill_chain_tab()
        self._main_tabs.setCurrentIndex(self._kill_chain_tab_index)
        self._status.showMessage(f"Added MFT #{mft_record_number} to phase: {phase}.")

    def _add_to_kill_chain_from_mft_selection(self, phase: str) -> None:
        """Get current MFT table selection and add that record to the given phase."""
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        rec = self._record_for_table_row(rows[0].row())
        if rec:
            self._add_file_to_kill_chain_phase(rec.record_number, phase)

    def _refresh_kill_chain_tab(self) -> None:
        """Repopulate all Kill Chain phase tables from _kill_chain_entries."""
        if not hasattr(self, "_kill_chain_tables"):
            return
        for phase in KILL_CHAIN_PHASES:
            tbl = self._kill_chain_tables.get(phase)
            if not tbl:
                continue
            tbl.setRowCount(0)
            mft_nums = self._kill_chain_entries.get(phase, [])
            for mft_num in mft_nums:
                rec = self._mft_record_by_number(mft_num)
                if not rec:
                    continue
                row = tbl.rowCount()
                tbl.insertRow(row)
                name_item = QTableWidgetItem(rec.primary_name() or "")
                # Store MFT # in metadata on the filename cell.
                name_item.setData(Qt.ItemDataRole.UserRole, mft_num)
                tbl.setItem(row, 0, name_item)

    def _on_kill_chain_table_context_menu(self, pos, table: QTableWidget, phase: str) -> None:
        """Context menu on a Kill Chain phase table: Remove, Move to phase, Jump to MFT row."""
        row = table.rowAt(pos.y())
        if row < 0:
            return
        name_item = table.item(row, 0)
        if not name_item:
            return
        mft_num = name_item.data(Qt.ItemDataRole.UserRole)
        if mft_num is None:
            return
        menu = QMenu(self)
        remove_act = QAction("Remove from phase", self)
        remove_act.triggered.connect(lambda: self._kill_chain_remove_from_phase(phase, mft_num))
        menu.addAction(remove_act)
        move_menu = QMenu("Move to phase...", self)
        for other_phase in KILL_CHAIN_PHASES:
            if other_phase == phase:
                continue
            act = QAction(other_phase, self)
            act.triggered.connect(lambda checked=False, p=other_phase: self._kill_chain_move_entry(phase, mft_num, p))
            move_menu.addAction(act)
        menu.addMenu(move_menu)
        jump_act = QAction("Jump to MFT row", self)
        jump_act.triggered.connect(lambda: self._kill_chain_jump_to_mft(mft_num))
        menu.addAction(jump_act)
        menu.exec(table.viewport().mapToGlobal(pos))

    def _kill_chain_remove_from_phase(self, phase: str, mft_num: int) -> None:
        """Remove the first occurrence of this MFT # from the phase."""
        if phase not in self._kill_chain_entries:
            return
        try:
            self._kill_chain_entries[phase].remove(mft_num)
        except ValueError:
            pass
        self._refresh_kill_chain_tab()
        self._status.showMessage(f"Removed MFT #{mft_num} from {phase}.")

    def _kill_chain_move_entry(self, from_phase: str, mft_num: int, to_phase: str) -> None:
        """Move one occurrence of this MFT # from from_phase to to_phase."""
        if from_phase in self._kill_chain_entries:
            try:
                self._kill_chain_entries[from_phase].remove(mft_num)
            except ValueError:
                pass
        if to_phase not in self._kill_chain_entries:
            self._kill_chain_entries[to_phase] = []
        self._kill_chain_entries[to_phase].append(mft_num)
        self._refresh_kill_chain_tab()
        self._status.showMessage(f"Moved MFT #{mft_num} to {to_phase}.")

    def _kill_chain_jump_to_mft(self, mft_num: int) -> None:
        """Switch to MFT tab and select the row for this record number."""
        rec = self._mft_record_by_number(mft_num)
        if not rec:
            self._status.showMessage("MFT record not found.")
            return
        self._main_tabs.setCurrentIndex(0)
        model = self._mft_model
        for r in range(model.rowCount()):
            if model.record_at(r) is rec:
                self._table.selectionModel().clearSelection()
                self._table.selectRow(r)
                self._table.scrollTo(model.index(r, 0))
                break

    def _kill_chain_set_kv_table(self, table: QTableWidget, rows: list[tuple[str, str]]) -> None:
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            k_item = QTableWidgetItem(k)
            v_item = QTableWidgetItem(v)
            v_item.setToolTip(v if v else "")
            table.setItem(i, 0, k_item)
            table.setItem(i, 1, v_item)
        table.resizeColumnsToContents()
        table.setSortingEnabled(True)

    def _on_kill_chain_selection_changed(self) -> None:
        """Update Kill Chain detail panel when a row is selected in any phase table."""
        self._kill_chain_detail_summary.setRowCount(0)
        self._kill_chain_detail_attrs.setRowCount(0)
        self._kill_chain_detail_hex.clear()
        for tbl in self._kill_chain_tables.values():
            rows = tbl.selectionModel().selectedRows()
            if not rows:
                continue
            row = rows[0].row()
            name_item = tbl.item(row, 0)
            if not name_item:
                continue
            mft_num = name_item.data(Qt.ItemDataRole.UserRole)
            if mft_num is None:
                continue
            rec = self._mft_record_by_number(mft_num)
            if not rec:
                continue
            path = parent_path_for_record(rec, self._path_table or {})
            all_names = []
            for fn in rec.file_names:
                ns = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32+DOS"}.get(fn.namespace, str(fn.namespace))
                all_names.append(f"{fn.name} ({ns})")
            anomaly = detect_timestomping_anomaly(rec)
            usn_preview = ""
            if self._usn_by_mft and rec.record_number in self._usn_by_mft:
                usn_list = sorted(self._usn_by_mft[rec.record_number], key=lambda r: -r.timestamp)
                usn_preview = "\n".join([f"{u.timestamp_iso()}  {u.reason_string()}" for u in usn_list[:20]])
                if len(usn_list) > 20:
                    usn_preview += f"\n... and {len(usn_list) - 20} more"
            summary_rows: list[tuple[str, str]] = [
                ("MFT #", str(rec.record_number)),
                ("Parent path", path),
                ("Primary name", rec.primary_name() or ""),
                ("All names", "\n".join(all_names)),
                ("Offset in file", f"0x{rec.offset_in_file:X}"),
                ("Signature", str(rec.signature)),
                ("Sequence", str(rec.sequence)),
                ("In use", str(bool(rec.in_use))),
                ("Directory", str(bool(rec.is_directory))),
                ("Size", str(rec.size())),
            ]
            if rec.standard_info:
                summary_rows.extend([
                    ("SI Created", rec.standard_info.created_iso()),
                    ("SI Modified", rec.standard_info.modified_iso()),
                    ("SI MFT Modified", rec.standard_info.mft_modified_iso()),
                    ("SI Accessed", rec.standard_info.accessed_iso()),
                ])
            if rec.primary_file_name():
                fn = rec.primary_file_name()
                if fn:
                    summary_rows.extend([
                        ("FN Created", _win_timestamp_to_iso(fn.created)),
                        ("FN Modified", _win_timestamp_to_iso(fn.modified)),
                        ("FN MFT Modified", _win_timestamp_to_iso(fn.mft_modified)),
                        ("FN Accessed", _win_timestamp_to_iso(fn.accessed)),
                    ])
            if rec.data_attr:
                summary_rows.extend([
                    ("DATA Allocated size", str(rec.data_attr.allocated_size)),
                    ("DATA Resident", str(bool(rec.data_attr.resident))),
                ])
            summary_rows.extend([
                ("Timestomping anomaly", anomaly.flag_message() if anomaly else ""),
                ("High sequence", "Yes" if is_high_sequence(rec, DEFAULT_SEQUENCE_GAP_THRESHOLD) else "No"),
                ("USN (preview)", usn_preview),
                ("Parse note", rec.parse_error or ""),
            ])
            self._kill_chain_set_kv_table(self._kill_chain_detail_summary, summary_rows)
            # Attributes
            self._kill_chain_detail_attrs.setSortingEnabled(False)
            self._kill_chain_detail_attrs.setRowCount(len(rec.all_attributes or []))
            for i, a in enumerate(rec.all_attributes or []):
                self._kill_chain_detail_attrs.setItem(i, 0, QTableWidgetItem(str(a.type_name)))
                # Most NTFS attributes are unnamed; the Name field is mainly used for named streams and similar cases.
                name_display = str(a.name) if (a.name is not None and str(a.name).strip() != "") else "(none)"
                name_item = QTableWidgetItem(name_display)
                if name_display == "(none)":
                    name_item.setToolTip("Unnamed attribute (common). Named attributes appear here (e.g., alternate data streams).")
                self._kill_chain_detail_attrs.setItem(i, 1, name_item)
                self._kill_chain_detail_attrs.setItem(i, 2, QTableWidgetItem("Yes" if a.resident else "No"))
                self._kill_chain_detail_attrs.setItem(i, 3, QTableWidgetItem(str(a.length)))
            self._kill_chain_detail_attrs.resizeColumnsToContents()
            self._kill_chain_detail_attrs.setSortingEnabled(True)
            # Raw record hex summary
            hex_parts = [f"Header: {rec.raw_header_hex}"]
            for a in rec.all_attributes:
                hex_parts.append(f"{a.type_name}: {a.raw_hex[:80]}...")
            self._kill_chain_detail_hex.setText("\n\n".join(hex_parts))
            break

    def _on_filter_changed(self):
        criteria = self._mft_filter_panel.get_filters() if hasattr(self, "_mft_filter_panel") else []
        time_anchor_ticks = getattr(self, "_usn_anchor_ticks", None)
        time_anchor_mft_col: int | None = None
        if time_anchor_ticks is not None and hasattr(self, "_usn_time_column_combo"):
            data = self._usn_time_column_combo.currentData()
            if data and isinstance(data, (list, tuple)) and len(data) >= 2 and data[0] == "mft":
                time_anchor_mft_col = int(data[1])
        self._mft_model.set_filter(
            "",
            "All",
            criteria=criteria,
            time_anchor_ticks=time_anchor_ticks,
            time_anchor_seconds=getattr(self, "_usn_anchor_seconds", 30),
            time_anchor_mft_col=time_anchor_mft_col,
        )
        # Reapply current header sort over the full filtered index set.
        mft_header = self._table.horizontalHeader()
        mft_sort_col = mft_header.sortIndicatorSection()
        if mft_sort_col < 0 or mft_sort_col >= len(MFTTableModel.COLUMNS):
            mft_sort_col = 0
            mft_header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        self._mft_model.sort(mft_sort_col, mft_header.sortIndicatorOrder())
        visible = self._mft_model.total_filtered()
        self._status.showMessage(f"Showing {visible:,} of {len(self._records):,} records.")

    # MFT col_index -> USN col_index for compatible columns: MFT#, Name, Parent path
    _MFT_TO_USN_COL_MAP = {0: 2, 1: 3, 2: 4}

    # USN col_index -> MFT col_index for compatible columns: MFT#, Filename, Parent path
    _USN_TO_MFT_COL_MAP = {2: 0, 3: 1, 4: 2}

    def _copy_mft_search_to_usn(self):
        """Copy compatible MFT filters to USN Journal panel, switch tab, and apply."""
        criteria = self._mft_filter_panel.get_filters() if hasattr(self, "_mft_filter_panel") else []
        mapped = []
        for c in criteria:
            if c.col_index in self._MFT_TO_USN_COL_MAP:
                usn_idx = self._MFT_TO_USN_COL_MAP[c.col_index]
                col_name = next(n for i, n, _ in USN_COLUMNS if i == usn_idx)
                col_type = next(t for i, _, t in USN_COLUMNS if i == usn_idx)
                mapped.append(FilterCriterion(usn_idx, col_name, col_type, c.operator, c.value))
        if not mapped:
            self._status.showMessage("No compatible filters to copy (MFT #, Name, Parent path).")
            return
        self._usn_filter_panel.set_filters(mapped)
        self._main_tabs.setCurrentIndex(self._usn_tab_index)
        self._on_usn_tab_filter()
        self._status.showMessage(f"Copied {len(mapped)} filter(s) to USN Journal.")

    def _copy_usn_search_to_mft(self):
        """Copy compatible USN filters to MFT panel, switch tab, and apply."""
        criteria = self._usn_filter_panel.get_filters() if hasattr(self, "_usn_filter_panel") else []
        mapped = []
        for c in criteria:
            if c.col_index in self._USN_TO_MFT_COL_MAP:
                mft_idx = self._USN_TO_MFT_COL_MAP[c.col_index]
                col_name = next(n for i, n, _ in MFT_COLUMNS if i == mft_idx)
                col_type = next(t for i, _, t in MFT_COLUMNS if i == mft_idx)
                mapped.append(FilterCriterion(mft_idx, col_name, col_type, c.operator, c.value))
        if not mapped:
            self._status.showMessage("No compatible filters to copy (MFT #, Filename, Parent path).")
            return
        self._mft_filter_panel.set_filters(mapped)
        self._main_tabs.setCurrentIndex(0)
        self._on_filter_changed()
        self._status.showMessage(f"Copied {len(mapped)} filter(s) to MFT.")

    def _on_selection_changed(self):
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            self._detail_summary.clear()
            self._detail_attrs.clear()
            self._detail_hex.clear()
            return
        view_row = rows[0].row()
        rec = self._mft_model.record_at(view_row)
        if not rec:
            return
        # Summary
        lines = [
            f"MFT Record #: {rec.record_number}",
            f"Offset in file: 0x{rec.offset_in_file:X}",
            f"Signature: {rec.signature}  Sequence: {rec.sequence}",
            f"In use: {rec.in_use}  Directory: {rec.is_directory}",
            f"Primary name: {rec.primary_name()}",
            "",
            "All names:",
        ]
        for fn in rec.file_names:
            ns = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32+DOS"}.get(fn.namespace, str(fn.namespace))
            lines.append(f"  - {fn.name!r} (namespace: {ns})")
        if rec.standard_info:
            lines.extend([
                "",
                "Timestamps (from $STANDARD_INFORMATION):",
                f"  Created:    {rec.standard_info.created_iso()}",
                f"  Modified:   {rec.standard_info.modified_iso()}",
                f"  MFT mod:    {rec.standard_info.mft_modified_iso()}",
                f"  Accessed:   {rec.standard_info.accessed_iso()}",
            ])
        if rec.data_attr:
            lines.extend([
                "",
                "$DATA:",
                f"  Size: {rec.data_attr.size:,}  Allocated: {rec.data_attr.allocated_size:,}  Resident: {rec.data_attr.resident}",
            ])
        anomaly = detect_timestomping_anomaly(rec)
        if anomaly:
            lines.extend([
                "",
                "⚠ TIMESTOMPING ANOMALY (SI vs FN):",
                f"  {anomaly.flag_message()}",
                f"  {anomaly.detail_message()}",
            ])
        if is_high_sequence(rec, DEFAULT_SEQUENCE_GAP_THRESHOLD):
            lines.extend([
                "",
                "⚠ HIGH SEQUENCE (graveyard slot):",
                f"  Sequence {rec.sequence} — this MFT slot has been reused {rec.sequence} times.",
                "  Consider carving unallocated space in this directory for deleted file remnants.",
            ])
        if self._usn_by_mft and rec.record_number in self._usn_by_mft:
            usn_list = sorted(self._usn_by_mft[rec.record_number], key=lambda r: -r.timestamp)
            lines.append("")
            lines.append("USN Journal (all update reasons):")
            for u in usn_list[:20]:
                lines.append(f"  {u.timestamp_iso()}  {u.reason_string()}")
            if len(usn_list) > 20:
                lines.append(f"  ... and {len(usn_list) - 20} more")
        if rec.parse_error:
            lines.append(f"\nParse note: {rec.parse_error}")
        self._detail_summary.setText("\n".join(lines))
        # Attributes
        attr_lines = []
        for a in rec.all_attributes:
            attr_lines.append(f"[{a.type_name}] name={a.name!r} resident={a.resident} len={a.length}")
            attr_lines.append(f"  Hex: {a.raw_hex[:120]}{'...' if len(a.raw_hex) > 120 else ''}")
        self._detail_attrs.setText("\n".join(attr_lines) if attr_lines else "(no attributes)")
        # Full record hex (we don't store full raw in MFTRecord; show header + attrs summary)
        hex_parts = [f"Header: {rec.raw_header_hex}"]
        for a in rec.all_attributes:
            hex_parts.append(f"{a.type_name}: {a.raw_hex[:80]}...")
        self._detail_hex.setText("\n\n".join(hex_parts))

    def _on_mft_header_context_menu(self, pos):
        menu = QMenu(self)
        menu.setTitle("Toggle columns")
        for col, name in enumerate(MFTTableModel.COLUMNS):
            action = QAction(name, self)
            action.setCheckable(True)
            action.setChecked(not self._table.isColumnHidden(col))
            action.toggled.connect(lambda checked, c=col: self._table.setColumnHidden(c, not checked))
            menu.addAction(action)
        menu.addSeparator()
        show_all = QAction("Show all columns", self)
        show_all.triggered.connect(lambda: [self._table.setColumnHidden(c, False) for c in range(len(MFTTableModel.COLUMNS))])
        menu.addAction(show_all)
        reset_act = QAction("Reset to default", self)
        reset_act.triggered.connect(lambda: [
            self._table.setColumnHidden(c, c in MFTTableModel.DEFAULT_HIDDEN)
            for c in range(len(MFTTableModel.COLUMNS))
        ])
        menu.addAction(reset_act)
        menu.exec(self._table.horizontalHeader().mapToGlobal(pos))

    def _on_table_context_menu(self, pos):
        menu = QMenu(self)
        copy_act = QAction("Copy selected row(s) as CSV", self)
        copy_act.triggered.connect(self._copy_selection_csv)
        menu.addAction(copy_act)
        rows = self._table.selectionModel().selectedRows()
        if rows and self._records:
            kill_sub = QMenu("Add to Kill Chain Phase", self)
            for phase in KILL_CHAIN_PHASES:
                act = QAction(phase, self)
                act.triggered.connect(lambda checked=False, p=phase: self._add_to_kill_chain_from_mft_selection(p))
                kill_sub.addAction(act)
            menu.addMenu(kill_sub)
        menu.exec(self._table.mapToGlobal(pos))

    def _on_usn_table_context_menu(self, pos) -> None:
        """Context menu on USN table: Add to Kill Chain Phase (submenu) when row has resolvable MFT #."""
        row = self._usn_table.rowAt(pos.y())
        if row < 0:
            return
        mft_item = self._usn_table.item(row, 2)  # MFT # column
        if not mft_item:
            return
        try:
            mft_num = int(mft_item.text())
        except (TypeError, ValueError):
            return
        if not self._mft_record_by_number(mft_num):
            return
        menu = QMenu(self)
        kill_sub = QMenu("Add to Kill Chain Phase", self)
        for phase in KILL_CHAIN_PHASES:
            act = QAction(phase, self)
            act.triggered.connect(lambda checked=False, m=mft_num, p=phase: self._add_file_to_kill_chain_phase(m, p))
            kill_sub.addAction(act)
        menu.addMenu(kill_sub)
        menu.exec(self._usn_table.viewport().mapToGlobal(pos))

    def _on_analysis_table_kill_chain_menu(self, pos, table: QTableWidget, mft_column: int) -> None:
        """Context menu on Analysis tables (extension change, filename entropy, survival): Add to Kill Chain Phase."""
        row = table.rowAt(pos.y())
        if row < 0:
            return
        mft_item = table.item(row, mft_column)
        if not mft_item:
            return
        try:
            mft_num = int(mft_item.text())
        except (TypeError, ValueError):
            return
        if not self._mft_record_by_number(mft_num):
            self._status.showMessage("MFT record not found.")
            return
        menu = QMenu(self)
        kill_sub = QMenu("Add to Kill Chain Phase", self)
        for phase in KILL_CHAIN_PHASES:
            act = QAction(phase, self)
            act.triggered.connect(lambda checked=False, m=mft_num, p=phase: self._add_file_to_kill_chain_phase(m, p))
            kill_sub.addAction(act)
        menu.addMenu(kill_sub)
        menu.exec(table.viewport().mapToGlobal(pos))

    def _copy_selection_csv(self):
        rows = sorted(set(idx.row() for idx in self._table.selectionModel().selectedRows()))
        if not rows:
            return
        lines = []
        delete_ticks_by_file_ref = self._build_usn_delete_ticks_by_file_ref()
        for row in rows:
            rec = self._record_for_table_row(row)
            if rec is None:
                continue
            parent_path = parent_path_for_record(rec, self._path_table)
            d_create_mod, d_create_mftchg, d_mod_del = _record_timeline_delta_fields(rec, delete_ticks_by_file_ref)
            line = "\t".join([
                str(rec.record_number),
                rec.primary_name().replace("\t", " "),
                parent_path.replace("\t", " "),
                "Dir" if rec.is_directory else "File",
                str(rec.size()),
                rec.created_iso(),
                rec.modified_iso(),
                rec.standard_info.mft_modified_iso() if rec.standard_info else "",
                rec.standard_info.accessed_iso() if rec.standard_info else "",
                d_create_mod,
                d_create_mftchg,
                d_mod_del,
            ])
            lines.append(line)
        if lines:
            QApplication.clipboard().setText("\n".join(lines))
            self._status.showMessage("Copied to clipboard.")

    def _on_sequence_gap_report(self):
        """Open dialog listing records with high sequence numbers (graveyard slots)."""
        if not self._records:
            return
        report = build_sequence_gap_report(
            self._records,
            self._path_table,
            min_sequence=DEFAULT_SEQUENCE_GAP_THRESHOLD,
        )
        dlg = SequenceGapReportDialog(report, self)
        dlg.exec()

    def _on_open_usn(self):
        """Load USN Journal ($J) to correlate when files were opened/closed."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select USN Journal ($J) file",
            str(self._current_path or Path.home()),
            "All files (*);;USN Journal ($J) (*)",
        )
        if not path:
            return
        self._status.showMessage("Loading USN Journal...")
        self._progress = QProgressDialog("Loading USN Journal ($J)...", None, 0, 0, self)
        self._progress.setWindowTitle("MFT Reader")
        self._progress.setMinimumDuration(0)
        self._progress.setWindowModality(Qt.WindowModality.WindowModal)
        self._load_usn_thread = LoadUsnThread(Path(path), max_records=500_000, close_only=False)
        self._load_usn_thread.progress_phase.connect(self._on_load_phase)
        self._load_usn_thread.finished_load.connect(self._on_usn_load_finished)
        self._load_usn_thread.error.connect(self._on_usn_load_error)
        self._load_usn_thread.start()

    def _on_usn_load_finished(self, records: list, by_mft: dict):
        self._usn_records = records
        self._usn_by_mft = by_mft
        self._mft_model.set_usn_delete_ticks_map(self._build_usn_delete_ticks_by_file_ref())
        self._usn_path = getattr(self._load_usn_thread, "path", None) if self._load_usn_thread else None
        self._btn_usn_report.setEnabled(True)
        if self._progress:
            self._progress.close()
            self._progress = None
        self._rebuild_full_usn_parent_paths()
        self._on_filter_changed()
        self._on_usn_tab_filter()
        self._status.showMessage(f"Loaded {len(records):,} USN events (all reasons). Use USN Journal tab or dialog to filter.")
        self._refresh_statistics_tab()
        self._on_selection_changed()

    def _on_usn_load_error(self, msg: str):
        if self._progress:
            self._progress.close()
            self._progress = None
        QMessageBox.critical(self, "MFT Reader", msg)
        self._status.showMessage("USN load failed.")

    def _on_usn_report(self):
        """Open dialog with all USN Journal events and reason filter."""
        if not self._usn_records:
            return
        path_table = self._path_table or {}
        rec_by_num = {r.record_number: r for r in self._records} if self._records else {}
        dlg = UsnJournalDialog(self._usn_records, path_table, self, rec_by_num=rec_by_num)
        dlg.exec()

    def _on_export_csv(self):
        if not self._records:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", str(Path.home() / "mft_export.csv"), "CSV (*.csv);;All (*)"
        )
        if not path:
            return
        try:
            delete_ticks_by_file_ref = self._build_usn_delete_ticks_by_file_ref()
            with open(path, "w", encoding="utf-8") as f:
                f.write(
                    "MFT#,Name,Parent path,Type,Size,Created,Modified,MFT_Modified,Accessed,Sequence,"
                    "Delta_create_to_modify_s,Delta_create_to_mftchange_s,Delta_modify_to_delete_s\n"
                )
                for rec in self._records:
                    name = rec.primary_name().replace('"', '""')
                    parent_path = parent_path_for_record(rec, self._path_table).replace('"', '""')
                    typ = "Directory" if rec.is_directory else "File"
                    if not rec.in_use:
                        typ += " (deleted)"
                    d_create_mod, d_create_mftchg, d_mod_del = _record_timeline_delta_fields(rec, delete_ticks_by_file_ref)
                    f.write(f'{rec.record_number},"{name}","{parent_path}",{typ},{rec.size()},{rec.created_iso()},{rec.modified_iso()},')
                    f.write(
                        f'{rec.standard_info.mft_modified_iso() if rec.standard_info else ""},'
                        f'{rec.standard_info.accessed_iso() if rec.standard_info else ""},'
                        f'{rec.sequence},{d_create_mod},{d_create_mftchg},{d_mod_del}\n'
                    )
            self._status.showMessage(f"Exported to {path}")
            QMessageBox.information(self, "MFT Reader", f"Exported {len(self._records):,} records to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "MFT Reader", f"Export failed: {e}")
