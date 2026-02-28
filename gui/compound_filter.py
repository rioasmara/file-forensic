"""
Compound filter panel with drag-and-drop: drag column headers onto the panel to add
filters; reorder filter rows by dragging. All criteria are ANDed.
"""

import fnmatch
import json
from dataclasses import dataclass

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QFrame,
    QSizePolicy,
    QMenu,
    QHeaderView,
    QApplication,
    QStyle,
)
from PySide6.QtCore import Qt, Signal, QMimeData, QByteArray, QObject, QEvent, QPoint
from PySide6.QtGui import QDrag, QFont, QPixmap, QPainter, QColor

# Mime type for dragging a column header into the filter panel
COLUMN_DROP_MIME = "application/x-mftreader-column"
# Mime type for dragging a table row (payload: JSON {"t": table_id, "c": col_index, "v": cell_value})
ROW_DROP_MIME = "application/x-mftreader-row"

# Column definitions: (index, display_name, type)  type = "text" | "number"
MFT_COLUMNS = [
    (0, "MFT #", "number"),
    (1, "Name", "text"),
    (2, "Parent path", "text"),
    (3, "Type", "text"),
    (4, "Size", "number"),
    (5, "Created", "text"),
    (6, "Modified", "text"),
    (7, "MFT Modified", "text"),
    (8, "Accessed", "text"),
    (9, "FN Created", "text"),
    (10, "SI vs FN", "text"),
    (11, "Seq", "text"),
    (12, "\u0394 C\u2192M (s)", "number"),
    (13, "\u0394 C\u2192MFT (s)", "number"),
    (14, "\u0394 M\u2192Del (s)", "number"),
]

USN_COLUMNS = [
    (0, "Timestamp", "text"),
    (1, "USN", "number"),
    (2, "MFT #", "number"),
    (3, "Filename", "text"),
    (4, "Parent path", "text"),
    (5, "Reason", "text"),
]

OPERATORS_TEXT = ["contains", "equals", "starts with", "ends with", "glob (* ?)"]
OPERATORS_NUMBER = ["equals", "not equals", "<", ">", "<=", ">="]


@dataclass
class FilterCriterion:
    """Single filter: column index, operator, value."""
    col_index: int
    col_name: str
    col_type: str
    operator: str
    value: str


def criterion_matches(cell_value: str, operator: str, value: str, col_type: str) -> bool:
    """Return True if the cell value satisfies the criterion. Empty value means no filter (match all)."""
    value = (value or "").strip()
    if not value:
        return True
    cell = (cell_value or "").strip()
    cell_lower = cell.lower()
    val_lower = value.lower()

    if col_type == "number":
        try:
            cell_num = float(cell.replace(",", ""))
        except ValueError:
            cell_num = 0.0
        try:
            val_num = float(value.replace(",", ""))
        except ValueError:
            return False
        if operator == "equals":
            return cell_num == val_num
        if operator == "not equals":
            return cell_num != val_num
        if operator == "<":
            return cell_num < val_num
        if operator == ">":
            return cell_num > val_num
        if operator == "<=":
            return cell_num <= val_num
        if operator == ">=":
            return cell_num >= val_num
        return False

    # Text
    if operator == "contains":
        return val_lower in cell_lower
    if operator == "equals":
        return cell_lower == val_lower
    if operator == "starts with":
        return cell_lower.startswith(val_lower)
    if operator == "ends with":
        return cell_lower.endswith(val_lower)
    if operator == "glob (* ?)":
        return fnmatch.fnmatch(cell_lower, val_lower)
    return False


class DraggableColumnHeader(QHeaderView):
    """
    Header view that starts a drag when the user drags a section (beyond startDragDistance).
    Disables built-in section moving so our drag can receive mouse move events.
    """
    def __init__(self, table_id: str, column_names: list[str], parent=None):
        super().__init__(Qt.Orientation.Horizontal, parent)
        self._table_id = table_id
        self._column_names = column_names
        self._press_section = -1
        self._press_pos = None
        # Disable section reorder so mouse move is delivered to us for drag
        self.setSectionsMovable(False)
        self.setSectionsClickable(True)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._press_section = self.logicalIndexAt(event.position().toPoint().x() if hasattr(event, "position") else event.x())
            self._press_pos = event.globalPosition().toPoint() if hasattr(event, "globalPosition") else event.globalPos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._press_section >= 0 and self._press_section < len(self._column_names):
            pos = event.globalPosition().toPoint() if hasattr(event, "globalPosition") else event.globalPos()
            dist = (pos - self._press_pos).manhattanLength()
            if dist >= QApplication.startDragDistance():
                idx = self._press_section
                self._press_section = -1
                drag = QDrag(self.parent() or self)
                mime = QMimeData()
                payload = f"{self._table_id}:{idx}"
                mime.setText(payload)
                mime.setData(COLUMN_DROP_MIME, QByteArray(payload.encode("utf-8")))
                drag.setMimeData(mime)
                # Optional: small pixmap so user sees drag feedback
                pix = QPixmap(120, 24)
                pix.fill(QColor(60, 60, 80, 220))
                painter = QPainter(pix)
                painter.setPen(QColor(200, 200, 220))
                painter.drawText(pix.rect().adjusted(4, 0, -4, 0), Qt.AlignmentFlag.AlignCenter, self._column_names[idx][:20])
                painter.end()
                drag.setPixmap(pix)
                drag.exec(Qt.DropAction.CopyAction)
                event.accept()
                return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._press_section = -1
        self._press_pos = None
        super().mouseReleaseEvent(event)


def make_header_draggable(table, table_id: str, column_names: list[str]):
    """Replace the table's horizontal header with DraggableColumnHeader. Call after setModel()."""
    header = DraggableColumnHeader(table_id, column_names)
    table.setHorizontalHeader(header)
    return header


# --- Drop target list (accept drops from header) ---


class FilterListWidget(QListWidget):
    """List that accepts column-header drops (add filter) and internal moves (reorder)."""
    def __init__(self, panel: "CompoundFilterPanel", parent=None):
        super().__init__(parent)
        self._panel = panel
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(COLUMN_DROP_MIME) or event.mimeData().hasFormat(ROW_DROP_MIME) or event.mimeData().hasText():
            self._panel._check_accept_drag(event)
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasFormat(COLUMN_DROP_MIME) or event.mimeData().hasFormat(ROW_DROP_MIME) or event.mimeData().hasText():
            self._panel._check_accept_drag(event)
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasFormat(COLUMN_DROP_MIME) or event.mimeData().hasFormat(ROW_DROP_MIME) or (event.mimeData().hasText() and (":" in event.mimeData().text() or event.mimeData().text().strip().startswith("{"))):
            self._panel._handle_drop(event)
        else:
            super().dropEvent(event)


# --- Filter row and panel (drop target, reorderable list) ---


class FilterRowWidget(QWidget):
    """One row: column name (label), operator combo, value edit, remove button."""
    remove_clicked = Signal()

    def __init__(self, col_index: int, col_name: str, col_type: str, parent=None):
        super().__init__(parent)
        self.setObjectName("filterRow")
        self.col_index = col_index
        self.col_name = col_name
        self.col_type = col_type
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(6)
        name_label = QLabel(col_name + ":")
        name_label.setObjectName("filterColumnLabel")
        name_label.setFixedWidth(150)
        name_label.setToolTip(col_name)
        layout.addWidget(name_label)
        self._op_combo = QComboBox()
        self._op_combo.addItems(OPERATORS_NUMBER if col_type == "number" else OPERATORS_TEXT)
        self._op_combo.setFixedWidth(128)
        layout.addWidget(self._op_combo)
        self._value_edit = QLineEdit()
        self._value_edit.setPlaceholderText("Value…")
        self._value_edit.setClearButtonEnabled(True)
        self._value_edit.setMinimumWidth(160)
        self._value_edit.setMaximumWidth(320)
        self._value_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self._value_edit, 1)
        btn = QPushButton()
        btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TabCloseButton))
        btn.setFixedWidth(30)
        btn.setToolTip("Remove this filter")
        btn.clicked.connect(self.remove_clicked.emit)
        layout.addWidget(btn)

    def get_criterion(self) -> FilterCriterion:
        return FilterCriterion(
            self.col_index, self.col_name, self.col_type,
            self._op_combo.currentText(), self._value_edit.text().strip(),
        )

    def set_initial_value(self, value: str):
        """Set the filter value (e.g. when dropped from a table row)."""
        self._value_edit.setText(value or "")


class CompoundFilterPanel(QFrame):
    """
    Panel showing active filter criteria. Drag column headers here to add a filter;
    or use 'Add filter' menu. Drag rows to reorder. All criteria ANDed.
    Collapsible: click the header to expand/collapse (like Statistics filters).
    """
    filters_changed = Signal()
    copy_requested = Signal()  # Emitted when "Copy to X" is clicked; parent handles mapping

    def __init__(self, table_id: str, column_defs: list, parent=None, *, copy_to_target: str | None = None):
        super().__init__(parent)
        self.setObjectName("compoundFilterPanel")
        self._table_id = table_id
        self._column_defs = column_defs  # list of (index, name, type)
        self._copy_to_target = copy_to_target
        self._expanded = True
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 6, 8, 6)
        root.setSpacing(4)

        # --- Collapsible header row (same layout as Statistics: toggle, + Add, Apply, Clear all, Copy to X) ---
        hdr = QHBoxLayout()
        hdr.setSpacing(6)
        self._toggle_btn = QPushButton("\u25bc  Filters")
        self._toggle_btn.setObjectName("compoundFilterToggle")
        self._toggle_btn.setFlat(True)
        self._toggle_btn.setFixedHeight(22)
        self._toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle_btn.clicked.connect(self._toggle)
        hdr.addWidget(self._toggle_btn)
        hdr.addStretch()

        self._add_btn = QPushButton("+ Add")
        self._add_btn.setObjectName("compoundFilterBtn")
        self._add_btn.setFixedHeight(22)
        self._add_btn.setToolTip("Add a filter for any column")
        self._add_btn.clicked.connect(self._on_add_filter)
        hdr.addWidget(self._add_btn)

        self._apply_btn = QPushButton("Apply")
        self._apply_btn.setObjectName("compoundFilterBtn")
        self._apply_btn.setFixedHeight(22)
        self._apply_btn.setToolTip("Apply the current filter criteria to the table")
        self._apply_btn.clicked.connect(self.filters_changed.emit)
        hdr.addWidget(self._apply_btn)

        self._clear_btn = QPushButton("Clear all")
        self._clear_btn.setObjectName("compoundFilterBtn")
        self._clear_btn.setFixedHeight(22)
        self._clear_btn.setToolTip("Remove all filters")
        self._clear_btn.clicked.connect(self._clear_all)
        hdr.addWidget(self._clear_btn)

        if copy_to_target:
            self._copy_btn = QPushButton(f"Copy to {copy_to_target}…")
            self._copy_btn.setObjectName("compoundFilterBtn")
            self._copy_btn.setFixedHeight(22)
            self._copy_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowForward))
            self._copy_btn.setToolTip(f"Copy compatible filters to {copy_to_target} tab")
            self._copy_btn.clicked.connect(self.copy_requested.emit)
            hdr.addWidget(self._copy_btn)

        root.addLayout(hdr)

        # --- Content (hidden when collapsed): drop hint + filter list only ---
        self._content_widget = QWidget()
        content_layout = QVBoxLayout(self._content_widget)
        content_layout.setContentsMargins(0, 2, 0, 0)
        content_layout.setSpacing(4)
        self._drop_hint = QLabel("Drag a column header here, or use + Add.")
        self._drop_hint.setObjectName("filterDropHint")
        content_layout.addWidget(self._drop_hint)
        self._list = FilterListWidget(self)
        self._list.setObjectName("compoundFilterList")
        self._list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        self._list.setDefaultDropAction(Qt.DropAction.MoveAction)
        self._list.setMinimumHeight(48)
        self._list.setMaximumHeight(140)
        self._list.setSpacing(2)
        content_layout.addWidget(self._list)
        root.addWidget(self._content_widget)
        self._update_empty_state()

    def _toggle(self):
        self._expanded = not self._expanded
        self._content_widget.setVisible(self._expanded)
        self._add_btn.setVisible(self._expanded)
        self._apply_btn.setVisible(self._expanded)
        self._clear_btn.setVisible(self._expanded)
        if getattr(self, "_copy_btn", None) is not None:
            self._copy_btn.setVisible(self._expanded)
        self._refresh_toggle_text()

    def _refresh_toggle_text(self):
        n = self._list.count()
        arrow = "\u25bc" if self._expanded else "\u25b6"
        suffix = f"  ({n} active)" if n else ""
        self._toggle_btn.setText(f"{arrow}  Filters{suffix}")

    def _clear_all(self):
        self._list.clear()
        self._update_empty_state()
        self.filters_changed.emit()

    def _update_empty_state(self):
        self._drop_hint.setVisible(self._list.count() == 0)
        self._refresh_toggle_text()

    def _on_add_filter(self):
        menu = QMenu(self)
        for idx, name, _ in self._column_defs:
            action = menu.addAction(name)
            action.setData(idx)
        pos = self._add_btn.mapToGlobal(self._add_btn.rect().bottomLeft())
        action = menu.exec(pos)
        if action and action.data() is not None:
            self._add_filter_row(action.data())

    def _add_filter_row(self, col_index: int, initial_value: str | None = None, operator: str | None = None):
        for idx, name, ctype in self._column_defs:
            if idx == col_index:
                break
        else:
            return
        row_w = FilterRowWidget(col_index, name, ctype)
        if initial_value is not None:
            row_w.set_initial_value(initial_value)
        if operator is not None:
            ops = OPERATORS_NUMBER if row_w.col_type == "number" else OPERATORS_TEXT
            if operator in ops:
                row_w._op_combo.setCurrentText(operator)
            elif initial_value is not None:
                row_w._op_combo.setCurrentText("equals")
        elif initial_value is not None:
            row_w._op_combo.setCurrentText("equals")
        row_w.remove_clicked.connect(lambda w=row_w: self._remove_row(w))
        item = QListWidgetItem(self._list)
        item.setSizeHint(row_w.sizeHint())
        self._list.addItem(item)
        self._list.setItemWidget(item, row_w)
        self._update_empty_state()

    def _remove_row(self, row_w: QWidget):
        for i in range(self._list.count()):
            if self._list.itemWidget(self._list.item(i)) == row_w:
                self._list.takeItem(i)
                self._update_empty_state()
                break

    def get_filters(self) -> list:
        result = []
        for i in range(self._list.count()):
            w = self._list.itemWidget(self._list.item(i))
            if isinstance(w, FilterRowWidget):
                result.append(w.get_criterion())
        return result

    def set_filters(self, criteria: list[FilterCriterion]):
        """Replace all filters with the given criteria. Criteria must use col_index valid for this panel."""
        self._list.clear()
        col_defs_by_idx = {idx: (name, ctype) for idx, name, ctype in self._column_defs}
        for c in criteria or []:
            if c.col_index not in col_defs_by_idx:
                continue
            name, ctype = col_defs_by_idx[c.col_index]
            row_w = FilterRowWidget(c.col_index, name, ctype)
            row_w.set_initial_value(c.value or "")
            ops = OPERATORS_NUMBER if ctype == "number" else OPERATORS_TEXT
            if c.operator in ops:
                row_w._op_combo.setCurrentText(c.operator)
            row_w.remove_clicked.connect(lambda w=row_w: self._remove_row(w))
            item = QListWidgetItem(self._list)
            item.setSizeHint(row_w.sizeHint())
            self._list.addItem(item)
            self._list.setItemWidget(item, row_w)
        self._update_empty_state()

    def _check_accept_drag(self, event):
        """Accept drag if it's our column header, row, or table_id matches."""
        md = event.mimeData()
        if md.hasFormat(ROW_DROP_MIME):
            try:
                data = json.loads(md.text())
                if data.get("t") == self._table_id and isinstance(data.get("c"), int):
                    if 0 <= data["c"] < len(self._column_defs):
                        event.acceptProposedAction()
            except (json.JSONDecodeError, TypeError):
                pass
            return
        if not md.hasFormat(COLUMN_DROP_MIME) and not md.hasText():
            return
        text = md.text()
        if ":" in text and "{" not in text:
            try:
                tid, idx = text.split(":", 1)
                if tid == self._table_id and int(idx) < len(self._column_defs):
                    event.acceptProposedAction()
            except ValueError:
                pass

    def _handle_drop(self, event):
        """Parse drop: row (JSON with t,c,v) or column header (table_id:col_index)."""
        text = event.mimeData().text()
        try:
            data = json.loads(text)
            if isinstance(data, dict) and data.get("t") == self._table_id and "c" in data:
                col_index = int(data["c"])
                if 0 <= col_index < len(self._column_defs):
                    value = data.get("v")
                    event.acceptProposedAction()
                    if not self._expanded:
                        self._toggle()
                    self._add_filter_row(col_index, initial_value=(str(value) if value is not None else ""))
                    return
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        if ":" in text and "{" not in text:
            try:
                tid, idx_str = text.split(":", 1)
                if tid != self._table_id:
                    return
                col_index = int(idx_str)
            except ValueError:
                return
            event.acceptProposedAction()
            if not self._expanded:
                self._toggle()
            self._add_filter_row(col_index)

    def dragEnterEvent(self, event):
        self._check_accept_drag(event)

    def dragMoveEvent(self, event):
        self._check_accept_drag(event)

    def dropEvent(self, event):
        self._handle_drop(event)


# ---------------------------------------------------------------------------
# Column definitions for Statistics sub-tabs
# ---------------------------------------------------------------------------

ANOMALY_SEQ_COLUMNS = [
    (0, "Score", "number"),
    (1, "Risk", "text"),
    (2, "Start", "text"),
    (3, "End", "text"),
    (4, "Path", "text"),
    (5, "Pattern", "text"),
]

EXT_CHANGE_COLUMNS = [
    (0, "MFT #", "number"),
    (1, "Old name", "text"),
    (2, "New name", "text"),
    (3, "Ext change", "text"),
    (4, "Timestamp", "text"),
    (5, "Parent path", "text"),
]

FILENAME_ENTROPY_COLUMNS = [
    (0, "Entropy", "number"),
    (1, "Filename", "text"),
    (2, "Parent path", "text"),
    (3, "MFT #", "number"),
]

EXT_ENTROPY_COLUMNS = [
    (0, "Directory", "text"),
    (1, "Ext. entropy", "number"),
    (2, "Files", "number"),
    (3, "Distinct ext.", "number"),
]

CHURN_COLUMNS = [
    (0, "Directory", "text"),
    (1, "Files", "number"),
    (2, "First file (burst)", "text"),
    (3, "Last file (burst)", "text"),
    (4, "Duration (s) ≤ window", "number"),
    (5, "Executable?", "text"),
    (6, "Persistence?", "text"),
    (7, "Files in burst", "text"),
]

SURVIVAL_COLUMNS = [
    (0, "MFT #", "number"),
    (1, "Name", "text"),
    (2, "Path", "text"),
    (3, "Created", "text"),
    (4, "Deleted", "text"),
    (5, "Time to delete", "text"),
]

TEMPORAL_BURST_POISSON_COLUMNS = [
    (0, "Burst start (UTC)", "text"),
    (1, "Burst end (UTC)", "text"),
    (2, "Files in window", "number"),
    (3, "Normal rate (per min)", "number"),
    (4, "How unusual (0 = very rare)", "number"),
    (5, "Flagged?", "text"),
]

TEMPORAL_BURST_BURSTINESS_COLUMNS = [
    (0, "Directory path", "text"),
    (1, "Burstiness score (−1 to +1)", "number"),
    (2, "Activity pattern", "text"),
    (3, "File events", "number"),
    (4, "Avg time between events (sec)", "number"),
    (5, "Time variation (sec)", "number"),
]


# ---------------------------------------------------------------------------
# Compact collapsible filter for Statistics tables
# ---------------------------------------------------------------------------


class _StatsFilterRow(QWidget):
    """Single compact filter row: column selector, operator, value, remove."""
    remove_clicked = Signal()
    apply_requested = Signal()

    def __init__(self, column_defs: list, parent=None):
        super().__init__(parent)
        self.setObjectName("statsFilterRow")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(4)

        self._col_combo = QComboBox()
        self._col_combo.setFixedWidth(140)
        for idx, name, ctype in column_defs:
            self._col_combo.addItem(name, (idx, name, ctype))
        self._col_combo.currentIndexChanged.connect(self._on_column_changed)
        layout.addWidget(self._col_combo)

        self._op_combo = QComboBox()
        self._op_combo.setFixedWidth(110)
        self._sync_operators()
        layout.addWidget(self._op_combo)

        self._value_edit = QLineEdit()
        self._value_edit.setPlaceholderText("Value\u2026")
        self._value_edit.setClearButtonEnabled(True)
        self._value_edit.setMinimumWidth(120)
        self._value_edit.returnPressed.connect(self.apply_requested.emit)
        layout.addWidget(self._value_edit, 1)

        btn = QPushButton("\u00d7")
        btn.setFixedSize(24, 24)
        btn.setToolTip("Remove this filter")
        btn.clicked.connect(self.remove_clicked.emit)
        layout.addWidget(btn)

    def _on_column_changed(self):
        self._sync_operators()

    def _sync_operators(self):
        data = self._col_combo.currentData()
        ctype = data[2] if data else "text"
        prev = self._op_combo.currentText()
        self._op_combo.clear()
        ops = OPERATORS_NUMBER if ctype == "number" else OPERATORS_TEXT
        self._op_combo.addItems(ops)
        if prev in ops:
            self._op_combo.setCurrentText(prev)

    def get_criterion(self) -> FilterCriterion | None:
        data = self._col_combo.currentData()
        if not data:
            return None
        idx, name, ctype = data
        return FilterCriterion(idx, name, ctype, self._op_combo.currentText(), self._value_edit.text().strip())

    def set_column(self, col_index: int):
        for i in range(self._col_combo.count()):
            data = self._col_combo.itemData(i)
            if data and data[0] == col_index:
                self._col_combo.setCurrentIndex(i)
                break

    def set_value(self, value: str):
        self._value_edit.setText(value or "")

    def set_operator(self, op: str):
        for i in range(self._op_combo.count()):
            if self._op_combo.itemText(i) == op:
                self._op_combo.setCurrentText(op)
                break


class CollapsibleStatsFilter(QFrame):
    """
    Compact collapsible filter bar for statistics tables.

    Collapsed: thin single-line strip with toggle button and row count.
    Expanded: shows compound filter rows (column + operator + value) with
    Add / Apply / Clear controls.  All criteria are ANDed.

    Supports drag-and-drop: drag a column header onto this panel to add
    a filter for that column; drag a table cell to add a filter with the
    cell value pre-filled.
    """
    filters_changed = Signal()

    def __init__(self, table_id: str, column_defs: list, parent=None):
        super().__init__(parent)
        self.setObjectName("statsFilterBar")
        self._table_id = table_id
        self._column_defs = column_defs
        self._expanded = False
        self._filter_rows: list[_StatsFilterRow] = []

        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Plain)

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 3, 6, 3)
        root.setSpacing(2)

        # --- header row ---
        hdr = QHBoxLayout()
        hdr.setSpacing(6)

        self._toggle_btn = QPushButton("\u25b6  Filters")
        self._toggle_btn.setObjectName("statsFilterToggle")
        self._toggle_btn.setFlat(True)
        self._toggle_btn.setFixedHeight(22)
        self._toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle_btn.clicked.connect(self._toggle)
        hdr.addWidget(self._toggle_btn)

        self._count_label = QLabel("")
        self._count_label.setObjectName("statsFilterCount")
        self._count_label.setStyleSheet("color: #9399b2; font-size: 9pt;")
        hdr.addWidget(self._count_label)

        hdr.addStretch()

        self._add_btn = QPushButton("+ Add")
        self._add_btn.setObjectName("statsFilterBtn")
        self._add_btn.setFixedHeight(22)
        self._add_btn.setVisible(False)
        self._add_btn.clicked.connect(self._on_add)
        hdr.addWidget(self._add_btn)

        self._apply_btn = QPushButton("Apply")
        self._apply_btn.setObjectName("statsFilterBtn")
        self._apply_btn.setFixedHeight(22)
        self._apply_btn.setVisible(False)
        self._apply_btn.clicked.connect(self._on_apply)
        hdr.addWidget(self._apply_btn)

        self._clear_btn = QPushButton("Clear all")
        self._clear_btn.setObjectName("statsFilterBtn")
        self._clear_btn.setFixedHeight(22)
        self._clear_btn.setVisible(False)
        self._clear_btn.clicked.connect(self._clear_all)
        hdr.addWidget(self._clear_btn)

        root.addLayout(hdr)

        # --- filter rows container (hidden when collapsed) ---
        self._rows_widget = QWidget()
        self._rows_layout = QVBoxLayout(self._rows_widget)
        self._rows_layout.setContentsMargins(0, 2, 0, 0)
        self._rows_layout.setSpacing(2)
        self._rows_widget.setVisible(False)
        root.addWidget(self._rows_widget)

    # -- public API --

    def get_filters(self) -> list[FilterCriterion]:
        out: list[FilterCriterion] = []
        for row in self._filter_rows:
            c = row.get_criterion()
            if c and c.value:
                out.append(c)
        return out

    def match_row(self, values: list[str]) -> bool:
        """Return True if *values* satisfies every active filter (AND)."""
        for c in self.get_filters():
            if c.col_index < 0 or c.col_index >= len(values):
                continue
            if not criterion_matches(values[c.col_index], c.operator, c.value, c.col_type):
                return False
        return True

    def set_count_text(self, text: str):
        self._count_label.setText(text)

    def active_count(self) -> int:
        return len(self.get_filters())

    # -- internals --

    def _toggle(self):
        self._expanded = not self._expanded
        self._rows_widget.setVisible(self._expanded)
        self._add_btn.setVisible(self._expanded)
        self._apply_btn.setVisible(self._expanded)
        self._clear_btn.setVisible(self._expanded)
        self._refresh_toggle_text()

    def _refresh_toggle_text(self):
        n = self.active_count()
        arrow = "\u25bc" if self._expanded else "\u25b6"
        suffix = f"  ({n} active)" if n else ""
        self._toggle_btn.setText(f"{arrow}  Filters{suffix}")

    def _on_add(self):
        row = _StatsFilterRow(self._column_defs)
        row.remove_clicked.connect(lambda r=row: self._remove_row(r))
        row.apply_requested.connect(self._on_apply)
        self._filter_rows.append(row)
        self._rows_layout.addWidget(row)
        self._refresh_toggle_text()

    def _add_filter_for_column(self, col_index: int, initial_value: str | None = None):
        """Add a filter row pre-set to *col_index* (and optionally a value). Auto-expands."""
        if col_index < 0 or col_index >= len(self._column_defs):
            return
        row = _StatsFilterRow(self._column_defs)
        row.set_column(col_index)
        if initial_value is not None:
            row.set_value(initial_value)
            row.set_operator("equals")
        row.remove_clicked.connect(lambda r=row: self._remove_row(r))
        row.apply_requested.connect(self._on_apply)
        self._filter_rows.append(row)
        self._rows_layout.addWidget(row)
        if not self._expanded:
            self._toggle()
        self._refresh_toggle_text()

    def _remove_row(self, row: _StatsFilterRow):
        if row in self._filter_rows:
            self._filter_rows.remove(row)
            self._rows_layout.removeWidget(row)
            row.deleteLater()
            self._refresh_toggle_text()

    def _clear_all(self):
        for row in list(self._filter_rows):
            self._rows_layout.removeWidget(row)
            row.deleteLater()
        self._filter_rows.clear()
        self._refresh_toggle_text()
        self.filters_changed.emit()

    def set_filters(self, criteria: list[FilterCriterion]) -> None:
        """Replace all filter rows with the given criteria (e.g. when loading a session)."""
        for row in list(self._filter_rows):
            self._rows_layout.removeWidget(row)
            row.deleteLater()
        self._filter_rows.clear()
        for c in criteria or []:
            if c.col_index < 0 or c.col_index >= len(self._column_defs):
                continue
            row = _StatsFilterRow(self._column_defs)
            row.set_column(c.col_index)
            row.set_operator(c.operator)
            row.set_value(c.value or "")
            row.remove_clicked.connect(lambda r=row: self._remove_row(r))
            row.apply_requested.connect(self._on_apply)
            self._filter_rows.append(row)
            self._rows_layout.addWidget(row)
        self._refresh_toggle_text()

    def _on_apply(self):
        self._refresh_toggle_text()
        self.filters_changed.emit()

    # -- drag-and-drop acceptance --

    def _check_accept_drag(self, event):
        md = event.mimeData()
        if md.hasFormat(ROW_DROP_MIME):
            try:
                data = json.loads(md.text())
                if data.get("t") == self._table_id and isinstance(data.get("c"), int):
                    if 0 <= data["c"] < len(self._column_defs):
                        event.acceptProposedAction()
            except (json.JSONDecodeError, TypeError):
                pass
            return
        if md.hasFormat(COLUMN_DROP_MIME) or md.hasText():
            text = md.text()
            if ":" in text and "{" not in text:
                try:
                    tid, idx = text.split(":", 1)
                    if tid == self._table_id and int(idx) < len(self._column_defs):
                        event.acceptProposedAction()
                except ValueError:
                    pass

    def _handle_drop(self, event):
        text = event.mimeData().text()
        try:
            data = json.loads(text)
            if isinstance(data, dict) and data.get("t") == self._table_id and "c" in data:
                col_index = int(data["c"])
                if 0 <= col_index < len(self._column_defs):
                    value = data.get("v")
                    event.acceptProposedAction()
                    self._add_filter_for_column(
                        col_index,
                        initial_value=(str(value) if value is not None else None),
                    )
                    return
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        if ":" in text and "{" not in text:
            try:
                tid, idx_str = text.split(":", 1)
                if tid != self._table_id:
                    return
                col_index = int(idx_str)
            except ValueError:
                return
            event.acceptProposedAction()
            self._add_filter_for_column(col_index)

    def dragEnterEvent(self, event):
        self._check_accept_drag(event)

    def dragMoveEvent(self, event):
        self._check_accept_drag(event)

    def dropEvent(self, event):
        self._handle_drop(event)