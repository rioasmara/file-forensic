"""
Persist MFT Reader session to SQLite: loaded MFT/USN data, path table,
all computed statistics, and filters. Load restores state without re-parsing or re-computing.
"""

import json
import pickle
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Schema version for future migrations
SCHEMA_VERSION = 1


def _default_db_path() -> Path:
    """Default path for the sessions database (user's home or cwd)."""
    base = Path.home() / ".mft_reader"
    base.mkdir(parents=True, exist_ok=True)
    return base / "sessions.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mft_path TEXT,
            usn_path TEXT,
            created_at TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS session_data (
            session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            key TEXT NOT NULL,
            value BLOB,
            value_text TEXT,
            PRIMARY KEY (session_id, key)
        );
        CREATE INDEX IF NOT EXISTS idx_session_data_session_id ON session_data(session_id);
    """)


def create_session(
    db_path: Path | None = None,
    name: str | None = None,
    mft_path: str | None = None,
    usn_path: str | None = None,
) -> int:
    """Create a new session row and return its id."""
    db_path = db_path or _default_db_path()
    conn = _connect(db_path)
    try:
        _init_schema(conn)
        now = datetime.now(timezone.utc).isoformat()
        name = name or (Path(mft_path).name if mft_path else "Session")
        cur = conn.execute(
            "INSERT INTO sessions (name, mft_path, usn_path, created_at, version) VALUES (?, ?, ?, ?, ?)",
            (name, mft_path, usn_path, now, SCHEMA_VERSION),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def save_session(
    session_id: int,
    state: dict[str, Any],
    db_path: Path | None = None,
) -> None:
    """
    Persist full session state into SQLite.
    state must contain: mft_records, path_table, usn_records (or None),
    filters (dict panel_id -> list of criterion dicts),
    stats (dict with raw data and churn_report_data),
    ui_state (dict with sort, anchor, churn params, etc.),
    and optionally kill_chain (flat list of phase/mft_record_number mappings).
    """
    db_path = db_path or _default_db_path()
    conn = _connect(db_path)
    try:
        _init_schema(conn)
        # Store large blobs with pickle; small dicts as JSON
        def put(key: str, blob: bytes | None = None, text: str | None = None) -> None:
            conn.execute(
                "INSERT OR REPLACE INTO session_data (session_id, key, value, value_text) VALUES (?, ?, ?, ?)",
                (session_id, key, blob, text),
            )

        # MFT records and path_table: pickle (can be large)
        put("mft_records", blob=pickle.dumps(state.get("mft_records"), protocol=pickle.HIGHEST_PROTOCOL))
        put("path_table", blob=pickle.dumps(state.get("path_table") or {}, protocol=pickle.HIGHEST_PROTOCOL))
        usn = state.get("usn_records")
        put("usn_records", blob=pickle.dumps(usn if usn else [], protocol=pickle.HIGHEST_PROTOCOL))

        # Filters: JSON list per panel
        filters = state.get("filters") or {}
        put("filters", text=json.dumps(filters))

        # Stats: one pickle blob for the whole stats dict (raw lists + churn_report_data + survival_histogram)
        stats = state.get("stats") or {}
        put("stats", blob=pickle.dumps(stats, protocol=pickle.HIGHEST_PROTOCOL))

        # UI state: JSON
        ui = state.get("ui_state") or {}
        put("ui_state", text=json.dumps(ui))

        # File system tree: FsTreeData + expanded node IDs (pickle)
        fs_tree = state.get("fs_tree")
        if fs_tree is not None:
            put("fs_tree", blob=pickle.dumps(fs_tree, protocol=pickle.HIGHEST_PROTOCOL))

        # Kill chain mappings: list of {"phase": str, "mft_record_number": int}
        kill_chain = state.get("kill_chain")
        if kill_chain is not None:
            put("kill_chain", blob=pickle.dumps(kill_chain, protocol=pickle.HIGHEST_PROTOCOL))

        # Forensic analysis report text (Analysis Report tab)
        report_text = state.get("forensic_report_text")
        if report_text is not None:
            put("forensic_report_text", text=report_text)

        conn.commit()
    finally:
        conn.close()


def load_session(session_id: int, db_path: Path | None = None) -> dict[str, Any]:
    """Load full session state from SQLite. Returns state dict for main window to apply."""
    db_path = db_path or _default_db_path()
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT name, mft_path, usn_path FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row:
            raise FileNotFoundError(f"Session id {session_id} not found")

        rows = conn.execute("SELECT key, value, value_text FROM session_data WHERE session_id = ?", (session_id,)).fetchall()
        data = {r["key"]: (r["value"], r["value_text"]) for r in rows}

        def get_blob(key: str) -> Any:
            blob, _ = data.get(key, (None, None))
            if blob is None:
                return None
            return pickle.loads(blob)

        def get_text(key: str) -> str | None:
            _, text = data.get(key, (None, None))
            return text

        state = {
            "mft_records": get_blob("mft_records") or [],
            "path_table": get_blob("path_table") or {},
            "usn_records": get_blob("usn_records") or [],
            "session_name": row["name"],
            "mft_path": row["mft_path"],
            "usn_path": row["usn_path"],
        }
        raw_filters = get_text("filters")
        state["filters"] = json.loads(raw_filters) if raw_filters else {}
        state["stats"] = get_blob("stats") or {}
        raw_ui = get_text("ui_state")
        state["ui_state"] = json.loads(raw_ui) if raw_ui else {}
        state["fs_tree"] = get_blob("fs_tree")
        # Kill chain is optional for backward compatibility with older session files.
        state["kill_chain"] = get_blob("kill_chain") or []
        # Forensic report text (optional; regenerate if missing for old sessions)
        state["forensic_report_text"] = get_text("forensic_report_text") or ""
        return state
    finally:
        conn.close()


def list_sessions(db_path: Path | None = None) -> list[tuple[int, str, str | None, str | None, str]]:
    """Return list of (id, name, mft_path, usn_path, created_at)."""
    db_path = db_path or _default_db_path()
    if not db_path.is_file():
        return []
    conn = _connect(db_path)
    try:
        _init_schema(conn)
        rows = conn.execute(
            "SELECT id, name, mft_path, usn_path, created_at FROM sessions ORDER BY created_at DESC"
        ).fetchall()
        return [(r["id"], r["name"], r["mft_path"], r["usn_path"], r["created_at"]) for r in rows]
    finally:
        conn.close()


def delete_session(session_id: int, db_path: Path | None = None) -> None:
    """Remove a session and its data."""
    db_path = db_path or _default_db_path()
    conn = _connect(db_path)
    try:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
    finally:
        conn.close()


# --- Single-file session: user chooses save/load path ---

SESSION_FILE_FILTER = "MFT Reader session (*.mftsession);;All files (*)"


def save_session_to_file(
    file_path: Path | str,
    state: dict[str, Any],
    name: str | None = None,
    mft_path: str | None = None,
    usn_path: str | None = None,
) -> None:
    """
    Save full session state to a single file (user-chosen path).
    Creates the SQLite file at file_path with one session. Overwrites if exists.
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    session_id = create_session(db_path=file_path, name=name, mft_path=mft_path, usn_path=usn_path)
    save_session(session_id, state, db_path=file_path)


def load_session_from_file(file_path: Path | str) -> dict[str, Any]:
    """
    Load session state from a session file (user-chosen path).
    If the file contains multiple sessions, loads the most recent one.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Session file not found: {file_path}")
    conn = _connect(file_path)
    try:
        row = conn.execute(
            "SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if not row:
            raise ValueError(f"No session found in {file_path}")
        return load_session(row["id"], db_path=file_path)
    finally:
        conn.close()


def criterion_to_dict(criterion: Any) -> dict:
    """Serialize FilterCriterion to a JSON-serializable dict."""
    return {
        "col_index": criterion.col_index,
        "col_name": criterion.col_name,
        "col_type": criterion.col_type,
        "operator": criterion.operator,
        "value": criterion.value or "",
    }


def dict_to_criterion(d: dict, criterion_class: type) -> Any:
    """Deserialize dict back to FilterCriterion (pass the FilterCriterion class)."""
    return criterion_class(
        col_index=int(d["col_index"]),
        col_name=str(d["col_name"]),
        col_type=str(d["col_type"]),
        operator=str(d["operator"]),
        value=str(d.get("value", "")),
    )
