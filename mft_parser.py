"""
MFT (Master File Table) parser for NTFS forensic analysis.
Reads $MFT file and extracts file record metadata: timestamps, names, flags, attributes.
"""

import math
import re
import statistics
import struct
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Iterator


# NTFS attribute type codes
ATTR_STANDARD_INFO = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFO = 0x70
ATTR_EA = 0x90
ATTR_EA_INFO = 0xA0
ATTR_LOGGED_UTILITY_STREAM = 0x100

ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    0x80: "$DATA",
    0x90: "$EA",
    0xA0: "$EA_INFORMATION",
    0x100: "$LOGGED_UTILITY_STREAM",
}

# File record flags
FR_IN_USE = 0x01
FR_IS_DIRECTORY = 0x02

# File name namespace
FILE_NAMESPACE_POSIX = 0
FILE_NAMESPACE_WIN32 = 1
FILE_NAMESPACE_DOS = 2
FILE_NAMESPACE_WIN32_AND_DOS = 3


def _win_timestamp_to_iso(ticks: int) -> str:
    """Convert Windows FILETIME (100ns since 1601-01-01) to ISO string, or empty if invalid."""
    if ticks is None or ticks == 0 or ticks == 0x7FFFFFFFFFFFFFFF:
        return ""
    try:
        from datetime import datetime, timezone
        # Windows epoch: 1601-01-01 00:00:00 UTC
        EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
        us = ticks / 10  # 100ns -> microseconds
        dt = EPOCH_1601 + __import__("datetime").timedelta(microseconds=us)
        return dt.isoformat(sep=" ")[:26]
    except (OverflowError, OSError, ValueError):
        return f"(invalid: {ticks})"


def iso_to_win_timestamp(iso_str: str) -> int | None:
    """Parse ISO datetime string (as produced by _win_timestamp_to_iso) to Windows FILETIME (100ns since 1601-01-01 UTC). Returns None if invalid."""
    from datetime import datetime, timezone
    iso_str = (iso_str or "").strip()
    if not iso_str:
        return None
    try:
        # Accept "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD HH:MM:SS.ffffff"; assume UTC
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
        delta = dt - EPOCH_1601
        us = delta.total_seconds() * 1_000_000
        ticks = int(us * 10)  # microseconds -> 100ns
        return ticks if 0 <= ticks <= 0x7FFFFFFFFFFFFFFF else None
    except (ValueError, OverflowError, OSError):
        return None


@dataclass
class StandardInfo:
    """$STANDARD_INFORMATION attribute (timestamps, flags)."""
    created: int = 0
    modified: int = 0
    mft_modified: int = 0
    accessed: int = 0
    file_attributes: int = 0

    def created_iso(self) -> str:
        return _win_timestamp_to_iso(self.created)

    def modified_iso(self) -> str:
        return _win_timestamp_to_iso(self.modified)

    def mft_modified_iso(self) -> str:
        return _win_timestamp_to_iso(self.mft_modified)

    def accessed_iso(self) -> str:
        return _win_timestamp_to_iso(self.accessed)


@dataclass
class FileNameAttr:
    """$FILE_NAME attribute."""
    parent_ref: int = 0
    parent_seq: int = 0
    created: int = 0
    modified: int = 0
    mft_modified: int = 0
    accessed: int = 0
    allocated_size: int = 0
    real_size: int = 0
    flags: int = 0
    namespace: int = 0
    name: str = ""

    def created_iso(self) -> str:
        return _win_timestamp_to_iso(self.created)

    def modified_iso(self) -> str:
        return _win_timestamp_to_iso(self.modified)

    def mft_modified_iso(self) -> str:
        return _win_timestamp_to_iso(self.mft_modified)

    def accessed_iso(self) -> str:
        return _win_timestamp_to_iso(self.accessed)

    def is_directory(self) -> bool:
        return bool(self.flags & 0x10000000)  # FILE_ATTR_DIRECTORY


@dataclass
class DataAttr:
    """$DATA attribute (size, resident/non-resident)."""
    size: int = 0
    allocated_size: int = 0
    resident: bool = True


@dataclass
class ParsedAttribute:
    """Generic parsed attribute for display."""
    type_code: int
    type_name: str
    name: str
    resident: bool
    length: int
    raw_hex: str = ""


@dataclass
class MFTRecord:
    """Single MFT file record with key attributes parsed."""
    record_number: int = 0
    offset_in_file: int = 0
    signature: str = ""
    sequence: int = 0
    flags: int = 0
    in_use: bool = True
    is_directory: bool = False
    standard_info: StandardInfo | None = None
    file_names: list[FileNameAttr] = field(default_factory=list)
    data_attr: DataAttr | None = None
    all_attributes: list[ParsedAttribute] = field(default_factory=list)
    raw_header_hex: str = ""
    parse_error: str = ""

    def primary_name(self) -> str:
        """Preferred display name (long name over DOS)."""
        long_name = None
        short_name = None
        for fn in self.file_names:
            if fn.namespace == FILE_NAMESPACE_WIN32 or fn.namespace == FILE_NAMESPACE_POSIX:
                long_name = fn.name
            elif fn.namespace == FILE_NAMESPACE_DOS or fn.namespace == FILE_NAMESPACE_WIN32_AND_DOS:
                short_name = fn.name
        return long_name or short_name or "(no name)"

    def primary_file_name(self) -> FileNameAttr | None:
        """$FILE_NAME to use for timestamps (long name when present); avoids DOS 8.3 which can share one creation time."""
        if not self.file_names:
            return None
        for fn in self.file_names:
            if fn.namespace == FILE_NAMESPACE_WIN32 or fn.namespace == FILE_NAMESPACE_POSIX:
                return fn
        return self.file_names[0]

    def created_iso(self) -> str:
        if self.standard_info:
            return self.standard_info.created_iso()
        fn = self.primary_file_name()
        if fn:
            return fn.created_iso()
        return ""

    def modified_iso(self) -> str:
        if self.standard_info:
            return self.standard_info.modified_iso()
        fn = self.primary_file_name()
        if fn:
            return fn.modified_iso()
        return ""

    def size(self) -> int:
        if self.data_attr:
            return self.data_attr.size
        return 0

    def timestomping_anomaly(self) -> "TimestompingAnomaly | None":
        """Anomaly if $STANDARD_INFORMATION created is earlier than $FILE_NAME created (timestomping indicator)."""
        return detect_timestomping_anomaly(self)


def _read_attr_header(data: bytes, off: int) -> tuple[int, int, int, bool, int, str]:
    """
    Returns (type_code, length, name_len, non_resident, name_offset, name).
    """
    if off + 4 > len(data):
        return 0, 0, 0, False, 0, ""
    type_code = struct.unpack_from("<I", data, off)[0]
    length = struct.unpack_from("<I", data, off + 4)[0]
    if length == 0 or off + length > len(data):
        return type_code, 0, 0, False, 0, ""
    non_resident = data[off + 8] != 0
    name_len = data[off + 9]
    name_offset = struct.unpack_from("<H", data, off + 10)[0]
    name = ""
    if name_len and name_offset and off + name_offset + name_len * 2 <= len(data):
        try:
            name = data[off + name_offset : off + name_offset + name_len * 2].decode("utf-16-le", errors="replace")
        except Exception:
            pass
    return type_code, length, name_len, non_resident, name_offset, name


def _resident_content_offset(data: bytes, attr_off: int) -> int:
    """Return offset (from record start) of resident attribute content. Attribute header has it at +0x14."""
    if attr_off + 0x16 > len(data):
        return attr_off + 0x18
    return attr_off + struct.unpack_from("<H", data, attr_off + 0x14)[0]


def _parse_standard_info(data: bytes, off: int, attr_len: int) -> StandardInfo | None:
    """Parse $STANDARD_INFORMATION from resident attribute content."""
    content_off = _resident_content_offset(data, off)
    if content_off + 0x24 > off + attr_len:
        return None
    try:
        created = struct.unpack_from("<Q", data, content_off)[0]
        modified = struct.unpack_from("<Q", data, content_off + 8)[0]
        mft_modified = struct.unpack_from("<Q", data, content_off + 16)[0]
        accessed = struct.unpack_from("<Q", data, content_off + 24)[0]
        file_attr = struct.unpack_from("<I", data, content_off + 32)[0] if content_off + 36 <= off + attr_len else 0
        return StandardInfo(
            created=created, modified=modified, mft_modified=mft_modified,
            accessed=accessed, file_attributes=file_attr
        )
    except struct.error:
        return None


def _parse_file_name(data: bytes, off: int, attr_len: int) -> FileNameAttr | None:
    """Parse $FILE_NAME from resident attribute."""
    content_off = _resident_content_offset(data, off)
    if content_off + 0x42 > off + attr_len:  # min for parent ref + name
        return None
    try:
        parent_ref = struct.unpack_from("<Q", data, content_off)[0] & 0xFFFFFFFFFFFF
        parent_seq = struct.unpack_from("<H", data, content_off + 6)[0]
        created = struct.unpack_from("<Q", data, content_off + 8)[0]
        modified = struct.unpack_from("<Q", data, content_off + 16)[0]
        mft_modified = struct.unpack_from("<Q", data, content_off + 24)[0]
        accessed = struct.unpack_from("<Q", data, content_off + 32)[0]
        allocated_size = struct.unpack_from("<Q", data, content_off + 40)[0]
        real_size = struct.unpack_from("<Q", data, content_off + 48)[0]
        flags = struct.unpack_from("<I", data, content_off + 56)[0]
        name_len = data[content_off + 64]
        namespace = data[content_off + 65]
        name = ""
        if name_len and content_off + 66 + name_len * 2 <= off + attr_len:
            name = data[content_off + 66 : content_off + 66 + name_len * 2].decode("utf-16-le", errors="replace")
        return FileNameAttr(
            parent_ref=parent_ref, parent_seq=parent_seq,
            created=created, modified=modified, mft_modified=mft_modified, accessed=accessed,
            allocated_size=allocated_size, real_size=real_size, flags=flags, namespace=namespace, name=name
        )
    except struct.error:
        return None


def _parse_data_attr(data: bytes, off: int, attr_len: int, non_resident: bool) -> DataAttr | None:
    if non_resident:
        # Non-resident: Real size at 0x30, Allocated at 0x28 (per NTFS attribute header)
        if off + 0x38 <= len(data):
            try:
                allocated = struct.unpack_from("<Q", data, off + 0x28)[0]
                size = struct.unpack_from("<Q", data, off + 0x30)[0]
                return DataAttr(size=size, allocated_size=allocated, resident=False)
            except struct.error:
                pass
        return DataAttr(size=0, allocated_size=0, resident=False)
    else:
        # Resident: content length at offset 0x10 (relative to attr start)
        try:
            content_len = struct.unpack_from("<I", data, off + 0x10)[0]
            return DataAttr(size=content_len, allocated_size=content_len, resident=True)
        except struct.error:
            return None


def _apply_usa_fixup(data: bytearray) -> None:
    """
    Apply NTFS update sequence array (USA) fixup to the record in place.
    The last 2 bytes of each 512-byte block (except block 0) are replaced
    by the corresponding USA entry so the record can be parsed correctly.
    """
    if len(data) < 0x38:
        return
    usa_offset = struct.unpack_from("<H", data, 0x04)[0]
    usa_count = struct.unpack_from("<H", data, 0x06)[0]
    if usa_offset + 2 * usa_count > len(data) or usa_count < 1:
        return
    for i in range(1, usa_count):
        pos = i * 512 - 2
        if pos + 2 > len(data):
            break
        repl_off = usa_offset + 2 * i
        if repl_off + 2 > len(data):
            break
        replacement = struct.unpack_from("<H", data, repl_off)[0]
        data[pos] = replacement & 0xFF
        data[pos + 1] = (replacement >> 8) & 0xFF


def _parse_record(data: bytes, record_number: int, offset_in_file: int, record_size: int) -> MFTRecord:
    """Parse one MFT record (1024 or 4096 bytes). Applies USA fixup before parsing."""
    rec = MFTRecord(record_number=record_number, offset_in_file=offset_in_file)
    if len(data) < 0x38:
        rec.parse_error = "Record too short"
        return rec
    data = bytearray(data)
    _apply_usa_fixup(data)
    data = bytes(data)
    sig_bytes = data[0:4]
    rec.signature = (sig_bytes + data[4:5]).decode("ascii", errors="replace") if len(data) > 4 else sig_bytes.decode("ascii", errors="replace")
    if sig_bytes != b"FILE" and sig_bytes != b"BAAD":
        rec.parse_error = f"Invalid signature: {sig_bytes!r}"
        return rec
    rec.raw_header_hex = data[:0x38].hex(" ", 1)
    rec.sequence = struct.unpack_from("<H", data, 0x10)[0]
    rec.flags = struct.unpack_from("<H", data, 0x16)[0]
    rec.in_use = bool(rec.flags & FR_IN_USE)
    rec.is_directory = bool(rec.flags & FR_IS_DIRECTORY)
    # NTFS 3.1+ stores the real MFT record number at 0x2C (4 bytes)
    attr_off = struct.unpack_from("<H", data, 0x14)[0]
    usa_offset = struct.unpack_from("<H", data, 0x04)[0]
    if attr_off >= 0x30 and len(data) >= 0x30:
        internal_num = struct.unpack_from("<I", data, 0x2C)[0]
        if internal_num != 0 or record_number == 0:
            rec.record_number = internal_num
    if attr_off < 0x2A or attr_off >= len(data):
        return rec
    # Walk attributes
    while attr_off + 4 <= len(data):
        type_code = struct.unpack_from("<I", data, attr_off)[0]
        if type_code == 0xFFFFFFFF:
            break
        attr_len = struct.unpack_from("<I", data, attr_off + 4)[0]
        if attr_len < 0x18:
            break
        end_off = attr_off + attr_len
        if end_off > len(data):
            break
        non_resident = data[attr_off + 8] != 0
        type_name = ATTR_NAMES.get(type_code, f"0x{type_code:X}")
        name_len = data[attr_off + 9]
        name_offset = struct.unpack_from("<H", data, attr_off + 10)[0]
        attr_name = ""
        if name_len and name_offset and attr_off + name_offset + name_len * 2 <= len(data):
            try:
                attr_name = data[attr_off + name_offset : attr_off + name_offset + name_len * 2].decode("utf-16-le", errors="replace")
            except Exception:
                pass
        raw_slice = data[attr_off:end_off]
        rec.all_attributes.append(ParsedAttribute(
            type_code=type_code, type_name=type_name, name=attr_name,
            resident=not non_resident, length=len(raw_slice),
            raw_hex=raw_slice[:256].hex(" ", 1) + ("..." if len(raw_slice) > 256 else "")
        ))
        if type_code == ATTR_STANDARD_INFO and not non_resident:
            rec.standard_info = _parse_standard_info(data, attr_off, attr_len)
        elif type_code == ATTR_FILE_NAME and not non_resident:
            fn = _parse_file_name(data, attr_off, attr_len)
            if fn:
                rec.file_names.append(fn)
        elif type_code == ATTR_DATA:
            rec.data_attr = _parse_data_attr(data, attr_off, attr_len, non_resident)
        attr_off = end_off
    return rec


def detect_record_size(fh: BinaryIO) -> int:
    """
    Detect MFT record size from the first record's allocated-size field and
    verify by scanning for the next FILE signature.  Handles 1024, 2048, 4096,
    and other power-of-2 sizes.
    """
    fh.seek(0)
    buf = fh.read(8192)
    if len(buf) < 0x40:
        return 1024

    # If the first record doesn't start with FILE, scan forward to find it
    first_file_off = -1
    for off in range(0, min(len(buf) - 4, 8192), 512):
        if buf[off : off + 4] == b"FILE":
            first_file_off = off
            break
    if first_file_off < 0:
        return 1024

    # Primary: read the allocated size stored in the FILE record header at +0x1C
    allocated = struct.unpack_from("<I", buf, first_file_off + 0x1C)[0]
    if 512 <= allocated <= 8192 and (allocated & (allocated - 1)) == 0:
        # Verify: does a FILE signature appear at that offset?
        check_off = first_file_off + allocated
        if check_off + 4 <= len(buf) and buf[check_off : check_off + 4] == b"FILE":
            return allocated

    # Fallback: scan for the second FILE signature and compute the gap
    for candidate in (1024, 2048, 4096):
        check_off = first_file_off + candidate
        if check_off + 4 <= len(buf) and buf[check_off : check_off + 4] == b"FILE":
            return candidate

    final = allocated if (512 <= allocated <= 8192 and (allocated & (allocated - 1)) == 0) else 1024
    return final


def iter_mft_records(
    path: Path | str,
    *,
    record_size: int = 0,
    start_record: int = 0,
    max_records: int | None = None,
) -> Iterator[MFTRecord]:
    """
    Open $MFT file and yield parsed MFTRecord for each valid record.
    record_size: 1024 or 4096; 0 = auto-detect.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"$MFT file not found: {path}")
    with open(path, "rb") as f:
        if record_size <= 0:
            record_size = detect_record_size(f)
        f.seek(start_record * record_size)
        n = 0
        while True:
            raw = f.read(record_size)
            if len(raw) < 0x38:
                break
            # Only parse records that look like valid FILE records (optional: skip bad ones for speed)
            rec_num = start_record + n
            rec = _parse_record(raw, rec_num, (start_record + n) * record_size, record_size)
            yield rec
            n += 1
            if max_records is not None and n >= max_records:
                break
            if len(raw) < record_size:
                break


def build_path_table(records: list[MFTRecord]) -> dict[int, str]:
    """
    Build a mapping from MFT record_number to full path by walking parent_ref.
    Root (record 5, self-referencing) and unknown/missing parents are represented as "\\".
    Uses iterative approach to avoid recursion depth issues on deep directory trees.
    """
    rec_by_num: dict[int, MFTRecord] = {r.record_number: r for r in records}
    path_cache: dict[int, str] = {}

    def path_of(start: int) -> str:
        if start in path_cache:
            return path_cache[start]
        # Collect the chain of ancestors up to root / unknown
        chain: list[int] = []
        visited: set[int] = set()
        cur = start
        while cur not in path_cache:
            if cur in visited:
                # Cycle detected — treat as root
                for c in chain:
                    path_cache[c] = "\\"
                return "\\"
            visited.add(cur)
            rec = rec_by_num.get(cur)
            fn = rec.primary_file_name() if rec else None
            if not fn:
                path_cache[cur] = "\\"
                break
            parent_ref = fn.parent_ref
            if parent_ref == cur or parent_ref not in rec_by_num:
                path_cache[cur] = "\\"
                break
            chain.append(cur)
            cur = parent_ref

        # Walk chain in reverse (from deepest ancestor to start) to build paths
        for c in reversed(chain):
            if c in path_cache:
                continue
            rec = rec_by_num.get(c)
            fn = rec.primary_file_name() if rec else None
            if not fn:
                path_cache[c] = "\\"
                continue
            parent_ref = fn.parent_ref
            parent_path = path_cache.get(parent_ref, "\\")
            name = rec.primary_name()
            if not name or name == "(no name)":
                path_cache[c] = parent_path
                continue
            base = parent_path.rstrip("\\") if parent_path != "\\" else ""
            path_cache[c] = f"{base}\\{name}" if base else f"\\{name}"

        return path_cache.get(start, "\\")

    for r in records:
        path_of(r.record_number)
    return path_cache


def parent_path_for_record(rec: MFTRecord, path_table: dict[int, str]) -> str:
    """
    Return the parent directory path for this record by looking up the parent
    directory's MFT record number in path_table.  Uses primary_file_name() so
    the parent_ref is consistent with the name shown in the table.
    Returns \"\\\" for root-level files or when the parent cannot be resolved.
    """
    fn = rec.primary_file_name()
    if not fn:
        return "\\"
    parent_ref = fn.parent_ref
    return path_table.get(parent_ref, "\\")


# --- File system tree (MFT + USN attribution) ---


@dataclass(slots=True)
class UsnSummary:
    """Per-MFT USN Journal activity counts for forensic attribution."""
    create: int = 0
    delete: int = 0
    rename_old: int = 0
    rename_new: int = 0
    data_overwrite: int = 0
    data_extend: int = 0
    close: int = 0

    def has_activity(self) -> bool:
        return bool(self.create or self.delete or self.rename_old or self.rename_new
                   or self.data_overwrite or self.data_extend or self.close)


def _usn_summary_for_mft(usn_list: list["UsnRecord"]) -> UsnSummary:
    """Build USN reason counts for a single MFT record from its USN list."""
    s = UsnSummary()
    for rec in usn_list:
        if rec.reason & USN_REASON_FILE_CREATE:
            s.create += 1
        if rec.reason & USN_REASON_FILE_DELETE:
            s.delete += 1
        if rec.reason & USN_REASON_RENAME_OLD_NAME:
            s.rename_old += 1
        if rec.reason & USN_REASON_RENAME_NEW_NAME:
            s.rename_new += 1
        if rec.reason & USN_REASON_DATA_OVERWRITE:
            s.data_overwrite += 1
        if rec.reason & USN_REASON_DATA_EXTEND:
            s.data_extend += 1
        if rec.reason & USN_REASON_CLOSE:
            s.close += 1
    return s


@dataclass
class FsTreeNode:
    """
    One node in the rebuilt file system tree from MFT + path table.
    Optional USN summary for forensic attribution (create/delete/rename/data activity).
    Kept for backward compatibility; prefer FsTreeData for low-memory use.
    """
    rec: MFTRecord
    path: str
    children: list["FsTreeNode"] = field(default_factory=list)
    usn_summary: UsnSummary | None = None


@dataclass(slots=True)
class FsTreeData:
    """
    Lightweight file system tree: only root IDs, parent->child map, and USN summaries.
    Use with lazy UI expansion to avoid holding full tree and MFTRecord refs in memory.
    """
    root_record_numbers: list[int]
    children_map: dict[int, list[int]]  # parent record_number -> sorted list of child record_numbers
    usn_summaries: dict[int, UsnSummary]  # record_number -> USN summary (only entries with activity)


def build_fs_tree(
    records: list[MFTRecord],
    path_table: dict[int, str],
    usn_by_mft: dict[int, list["UsnRecord"]] | None = None,
) -> FsTreeData:
    """
    Rebuild file system tree from MFT records and path table (low-memory).
    Optional usn_by_mft (MFT record number -> list of UsnRecord) enriches nodes
    with USN Journal activity counts for forensic attribution.

    Returns FsTreeData: root record numbers, parent->child map (record numbers only),
    and USN summaries. No FsTreeNode tree or MFTRecord refs per node—use with
    lazy UI expansion to minimize memory.
    """
    rec_by_num: dict[int, MFTRecord] = {r.record_number: r for r in records}
    children_map: dict[int, list[MFTRecord]] = {}
    for rec in records:
        fn = rec.primary_file_name()
        if not fn:
            continue
        parent_ref = fn.parent_ref
        if parent_ref == rec.record_number:
            continue
        if parent_ref not in children_map:
            children_map[parent_ref] = []
        children_map[parent_ref].append(rec)

    roots: list[MFTRecord] = []
    for rec in records:
        fn = rec.primary_file_name()
        if not fn:
            continue
        parent_ref = fn.parent_ref
        if parent_ref == rec.record_number:
            roots.append(rec)
        elif parent_ref not in rec_by_num:
            roots.append(rec)
    roots_sorted = sorted(roots, key=lambda r: (r.primary_name().lower(), r.record_number))
    root_record_numbers = [r.record_number for r in roots_sorted]

    # Children map as record numbers only (sorted by name); no FsTreeNode or path/rec copies
    children_map_int: dict[int, list[int]] = {}
    for rec_num, child_recs in children_map.items():
        sorted_children = sorted(
            child_recs, key=lambda r: (r.primary_name().lower(), r.record_number)
        )
        children_map_int[rec_num] = [c.record_number for c in sorted_children]

    # USN summaries only for records that have USN activity (sparse dict)
    usn_summaries: dict[int, UsnSummary] = {}
    if usn_by_mft:
        for rec_num, usn_list in usn_by_mft.items():
            if usn_list:
                usn_summaries[rec_num] = _usn_summary_for_mft(usn_list)

    return FsTreeData(
        root_record_numbers=root_record_numbers,
        children_map=children_map_int,
        usn_summaries=usn_summaries,
    )


# --- Timestomping detection (SI vs FN timestamp anomaly) ---

# Windows FILETIME: 100-nanosecond intervals since 1601-01-01
_TICKS_PER_SECOND = 10_000_000


def _ticks_to_seconds_delta(ticks: int) -> float:
    """Convert a tick difference to seconds (can be negative)."""
    if ticks == 0 or ticks == 0x7FFFFFFFFFFFFFFF:
        return 0.0
    return ticks / _TICKS_PER_SECOND


@dataclass
class TimestompingAnomaly:
    """
    Result of comparing $STANDARD_INFORMATION vs $FILE_NAME timestamps.
    SI created < FN created is physically impossible in normal Windows and indicates timestomping.
    """
    record_number: int
    # Which comparison triggered the flag
    anomaly_type: str  # e.g. "SI created < FN created"
    si_created: int
    fn_created: int
    si_created_iso: str
    fn_created_iso: str
    delta_seconds: float  # negative = SI earlier than FN (impossible normally)
    primary_name: str

    def flag_message(self) -> str:
        """Short message for red-flag display."""
        return f"TIMESTOMP? SI created before FN created (Δ={self.delta_seconds:.1f}s)"

    def detail_message(self) -> str:
        """Longer message with timestamps."""
        return (
            f"SI created: {self.si_created_iso} | FN created: {self.fn_created_iso} | "
            f"Delta: {self.delta_seconds:.1f}s (SI earlier = anomaly)"
        )


def detect_timestomping_anomaly(rec: MFTRecord) -> TimestompingAnomaly | None:
    """
    Compare $STANDARD_INFORMATION and $FILE_NAME timestamps for timestomping.

    In normal Windows behavior, SI and FN are set together at file creation.
    If SI created time is earlier than FN created time, that is a physical impossibility
    and indicates the SI timestamps were modified (timestomping) while FN was left unchanged.

    Returns an anomaly object if SI created < FN created (for the primary/first filename),
    otherwise None.
    """
    if not rec.standard_info or not rec.file_names:
        return None
    si = rec.standard_info
    # Use primary $FILE_NAME (long name when present); DOS 8.3 can share one creation time
    fn = rec.primary_file_name()
    if not fn:
        return None
    si_created = si.created
    fn_created = fn.created
    # Invalid/sentinel timestamps: skip
    if si_created in (0, 0x7FFFFFFFFFFFFFFF) or fn_created in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    if si_created >= fn_created:
        return None
    delta_ticks = si_created - fn_created
    delta_seconds = _ticks_to_seconds_delta(delta_ticks)
    return TimestompingAnomaly(
        record_number=rec.record_number,
        anomaly_type="SI created < FN created",
        si_created=si_created,
        fn_created=fn_created,
        si_created_iso=si.created_iso(),
        fn_created_iso=fn.created_iso(),
        delta_seconds=delta_seconds,
        primary_name=rec.primary_name(),
    )


# --- Sequence number analysis ("ghost" files / graveyard slots) ---

# Default threshold: sequence number above this means the record slot has been reused that many times.
# High sequence = "graveyard" slot; consider carving unallocated space in that directory.
DEFAULT_SEQUENCE_GAP_THRESHOLD = 5


@dataclass
class SequenceGapEntry:
    """
    One record flagged by sequence number analysis.
    High sequence = this MFT slot has been reused many times (file birth/death cycles).
    Useful for identifying directories where deeper carving may recover deleted files.
    """
    record_number: int
    sequence: int
    full_path: str
    primary_name: str
    in_use: bool
    is_directory: bool

    def flag_message(self) -> str:
        """Short message for table/report display."""
        return f"Seq {self.sequence} (slot reused {self.sequence}×)"

    def detail_message(self) -> str:
        """Longer message for report."""
        status = "in use" if self.in_use else "deleted"
        kind = "dir" if self.is_directory else "file"
        return f"MFT #{self.record_number}  Seq {self.sequence}  {kind} ({status})  {self.full_path}"


def is_high_sequence(rec: MFTRecord, threshold: int = DEFAULT_SEQUENCE_GAP_THRESHOLD) -> bool:
    """Return True if this record's sequence number indicates the slot has been reused many times."""
    return rec.sequence >= threshold


def build_sequence_gap_report(
    records: list[MFTRecord],
    path_table: dict[int, str],
    *,
    min_sequence: int = DEFAULT_SEQUENCE_GAP_THRESHOLD,
) -> list[SequenceGapEntry]:
    """
    Build the "Sequence Gap" report: records whose sequence number is >= min_sequence.

    High sequence = this MFT slot has been a graveyard for multiple deleted files.
    Sorted by sequence descending (highest reuse first), then by record number.
    """
    out: list[SequenceGapEntry] = []
    for rec in records:
        if rec.sequence < min_sequence:
            continue
        full_path = path_table.get(rec.record_number, "\\")
        name = rec.primary_name()
        out.append(SequenceGapEntry(
            record_number=rec.record_number,
            sequence=rec.sequence,
            full_path=full_path,
            primary_name=name,
            in_use=rec.in_use,
            is_directory=rec.is_directory,
        ))
    out.sort(key=lambda e: (-e.sequence, e.record_number))
    return out


def load_mft_records(
    path: Path | str,
    *,
    record_size: int = 0,
    start_record: int = 0,
    max_records: int | None = 100_000,
) -> list[MFTRecord]:
    """Load MFT records into a list for GUI display. Caps at max_records to avoid OOM."""
    return list(iter_mft_records(path, record_size=record_size, start_record=start_record, max_records=max_records))


# --- USN Journal ($UsnJrnl / $J) — when file was opened/closed ---

# USN reason flags (from winioctl.h); CLOSE = handle closed (file was opened before that)
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
USN_REASON_NAMED_DATA_EXTEND = 0x00000020
USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_INDEXABLE_CHANGE = 0x00004000
USN_REASON_BASIC_INFO_CHANGE = 0x00008000  # e.g. timestamps (accessed when opened)
USN_REASON_HARD_LINK_CHANGE = 0x00010000
USN_REASON_COMPRESSION_CHANGE = 0x00020000
USN_REASON_ENCRYPTION_CHANGE = 0x00040000
USN_REASON_OBJECT_ID_CHANGE = 0x00080000
USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
USN_REASON_STREAM_CHANGE = 0x00200000
USN_REASON_TRANSACTED_CHANGE = 0x00400000
USN_REASON_INTEGRITY_CHANGE = 0x00800000
USN_REASON_CLOSE = 0x80000000  # File/dir handle closed — file was opened before this

USN_REASON_NAMES = {
    USN_REASON_DATA_OVERWRITE: "DATA_OVERWRITE",
    USN_REASON_DATA_EXTEND: "DATA_EXTEND",
    USN_REASON_DATA_TRUNCATION: "DATA_TRUNCATION",
    USN_REASON_NAMED_DATA_OVERWRITE: "NAMED_DATA_OVERWRITE",
    USN_REASON_NAMED_DATA_EXTEND: "NAMED_DATA_EXTEND",
    USN_REASON_NAMED_DATA_TRUNCATION: "NAMED_DATA_TRUNCATION",
    USN_REASON_FILE_CREATE: "FILE_CREATE",
    USN_REASON_FILE_DELETE: "FILE_DELETE",
    USN_REASON_EA_CHANGE: "EA_CHANGE",
    USN_REASON_SECURITY_CHANGE: "SECURITY_CHANGE",
    USN_REASON_RENAME_OLD_NAME: "RENAME_OLD_NAME",
    USN_REASON_RENAME_NEW_NAME: "RENAME_NEW_NAME",
    USN_REASON_INDEXABLE_CHANGE: "INDEXABLE_CHANGE",
    USN_REASON_BASIC_INFO_CHANGE: "BASIC_INFO_CHANGE",
    USN_REASON_HARD_LINK_CHANGE: "HARD_LINK_CHANGE",
    USN_REASON_COMPRESSION_CHANGE: "COMPRESSION_CHANGE",
    USN_REASON_ENCRYPTION_CHANGE: "ENCRYPTION_CHANGE",
    USN_REASON_OBJECT_ID_CHANGE: "OBJECT_ID_CHANGE",
    USN_REASON_REPARSE_POINT_CHANGE: "REPARSE_POINT_CHANGE",
    USN_REASON_STREAM_CHANGE: "STREAM_CHANGE",
    USN_REASON_TRANSACTED_CHANGE: "TRANSACTED_CHANGE",
    USN_REASON_INTEGRITY_CHANGE: "INTEGRITY_CHANGE",
    USN_REASON_CLOSE: "CLOSE",
}


def usn_reason_string(reason: int) -> str:
    """Human-readable list of USN reason flags (CLOSE = file was closed / had been opened)."""
    if reason == 0:
        return ""
    parts = []
    for flag, name in USN_REASON_NAMES.items():
        if reason & flag:
            parts.append(name)
    return " | ".join(parts) if parts else f"0x{reason:08X}"


@dataclass
class UsnRecord:
    """
    Single USN Journal record. CLOSE reason = file/dir handle was closed (was opened before that).
    Use mft_record_number() to correlate with MFT (low 48 bits of file_ref).
    """
    file_ref: int          # 64-bit MFT reference (low 48 bits = record number)
    parent_ref: int        # 64-bit parent directory ref
    usn: int
    timestamp: int         # FILETIME (100ns since 1601-01-01 UTC)
    reason: int
    source_info: int
    security_id: int
    file_attributes: int
    file_name: str
    record_length: int
    major_version: int
    minor_version: int

    def timestamp_iso(self) -> str:
        return _win_timestamp_to_iso(self.timestamp)

    def mft_record_number(self) -> int:
        """MFT record number (low 48 bits of file_ref)."""
        return self.file_ref & 0xFFFFFFFFFFFF

    def parent_mft_record_number(self) -> int:
        return self.parent_ref & 0xFFFFFFFFFFFF

    def reason_string(self) -> str:
        return usn_reason_string(self.reason)

    def is_close(self) -> bool:
        """True if this record is a close event (file was opened, then closed)."""
        return bool(self.reason & USN_REASON_CLOSE)


def _usn_filename_matches(name_from_mft: str, name_from_usn: str) -> bool:
    """True if the two filenames refer to the same file (case-insensitive, stripped)."""
    if not name_from_mft or not name_from_usn:
        return False
    return name_from_mft.strip().lower() == name_from_usn.strip().lower()


def parent_path_for_usn_record(
    usn_rec: UsnRecord,
    path_table: dict[int, str],
    rec_by_num: dict[int, MFTRecord],
) -> str:
    """
    Return parent directory path for a USN record, consistent with the MFT table.

    Strategy:
      1) Look up the MFT record by the USN's file reference number.
         If the filename matches, use the MFT record's parent_ref to look up
         the parent directory in path_table — identical to parent_path_for_record().
      2) Otherwise fall back to the USN record's own parent_ref looked up in path_table.
    """
    file_mft = usn_rec.mft_record_number()
    mft_rec = rec_by_num.get(file_mft)
    if mft_rec:
        fn = mft_rec.primary_file_name()
        if fn and _usn_filename_matches(fn.name, usn_rec.file_name):
            return path_table.get(fn.parent_ref, "\\")
    parent_mft = usn_rec.parent_mft_record_number()
    return path_table.get(parent_mft, "\\")


def _parse_usn_record(data: bytes, offset: int) -> UsnRecord | None:
    """
    Parse one USN_RECORD_V2 (or V3) from data at offset.
    Returns None if record is invalid or truncated.
    """
    if offset + 60 > len(data):
        return None
    try:
        rec_len = struct.unpack_from("<I", data, offset)[0]
        if rec_len < 60 or rec_len > 0x10000 or offset + rec_len > len(data):
            return None
        major = struct.unpack_from("<H", data, offset + 4)[0]
        minor = struct.unpack_from("<H", data, offset + 6)[0]
        if major not in (2, 3):
            return None
        file_ref = struct.unpack_from("<Q", data, offset + 8)[0]
        parent_ref = struct.unpack_from("<Q", data, offset + 16)[0]
        usn = struct.unpack_from("<Q", data, offset + 24)[0]
        timestamp = struct.unpack_from("<Q", data, offset + 32)[0]
        reason = struct.unpack_from("<I", data, offset + 40)[0]
        source_info = struct.unpack_from("<I", data, offset + 44)[0]
        security_id = struct.unpack_from("<I", data, offset + 48)[0]
        file_attr = struct.unpack_from("<I", data, offset + 52)[0]
        name_len = struct.unpack_from("<H", data, offset + 56)[0]
        name_offset = struct.unpack_from("<H", data, offset + 58)[0]
        file_name = ""
        if name_len and name_offset + name_len <= rec_len:
            name_start = offset + name_offset
            if name_start + name_len <= len(data):
                raw_name = data[name_start : name_start + name_len]
                file_name = raw_name.decode("utf-16-le", errors="replace")
        return UsnRecord(
            file_ref=file_ref,
            parent_ref=parent_ref,
            usn=usn,
            timestamp=timestamp,
            reason=reason,
            source_info=source_info,
            security_id=security_id,
            file_attributes=file_attr,
            file_name=file_name,
            record_length=rec_len,
            major_version=major,
            minor_version=minor,
        )
    except struct.error:
        return None


# $J stream may have a 4096-byte page header; min sane record length
_USN_MIN_RECORD_LEN = 60
_USN_PAGE_SIZE = 4096


def iter_usn_records(
    path: Path | str,
    *,
    max_records: int | None = None,
    reason_filter: int | None = None,
) -> Iterator[UsnRecord]:
    """
    Open USN Journal stream ($J) and yield parsed UsnRecord entries.

    path: Path to the $J file (e.g. copy of \\\\?\\Volume{GUID}\\$Extend\\$UsnJrnl:$J or forensic image).
    max_records: Cap number of records (None = no limit).
    reason_filter: If set, only yield records with any of these reason flags (e.g. USN_REASON_CLOSE).
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"USN Journal file not found: {path}")
    n = 0
    with open(path, "rb") as f:
        offset = 0
        # Skip optional 4096-byte journal header if first DWORD looks invalid
        first = f.read(4)
        if len(first) < 4:
            return
        first_len = struct.unpack_from("<I", first)[0]
        if first_len < _USN_MIN_RECORD_LEN or first_len > _USN_PAGE_SIZE:
            offset = _USN_PAGE_SIZE
            f.seek(offset)
        else:
            f.seek(0)
        chunk_size = _USN_PAGE_SIZE * 8
        while True:
            f.seek(offset)
            chunk = f.read(chunk_size)
            if not chunk:
                break
            pos = 0
            while pos + _USN_MIN_RECORD_LEN <= len(chunk):
                rec_len = struct.unpack_from("<I", chunk, pos)[0]
                if rec_len < _USN_MIN_RECORD_LEN or rec_len > 0x10000:
                    pos += 8
                    continue
                if pos + rec_len > len(chunk):
                    offset += pos
                    break
                rec = _parse_usn_record(chunk, pos)
                if rec is None:
                    pos += 8
                    continue
                if reason_filter is not None and not (rec.reason & reason_filter):
                    pos += rec_len
                    continue
                yield rec
                n += 1
                if max_records is not None and n >= max_records:
                    return
                pos += rec_len
            else:
                offset += len(chunk)


def load_usn_records(
    path: Path | str,
    *,
    max_records: int | None = 500_000,
    close_only: bool = False,
) -> list[UsnRecord]:
    """
    Load USN records into a list. close_only=True loads only CLOSE events (file was opened then closed).
    """
    reason_filter = USN_REASON_CLOSE if close_only else None
    return list(iter_usn_records(path, max_records=max_records, reason_filter=reason_filter))


def usn_close_events_by_mft(
    usn_records: list[UsnRecord],
) -> dict[int, list[UsnRecord]]:
    """
    Group USN records by MFT record number. Use with any reason (CLOSE, FILE_CREATE, etc.).
    Returns dict: mft_record_number -> list of UsnRecord.
    """
    by_mft: dict[int, list[UsnRecord]] = {}
    for rec in usn_records:
        mft_num = rec.mft_record_number()
        if mft_num not in by_mft:
            by_mft[mft_num] = []
        by_mft[mft_num].append(rec)
    return by_mft


# Alias for "all events" use case
usn_events_by_mft = usn_close_events_by_mft


# --- Name-change / extension-change detection (rename where extension changed) ---

@dataclass
class ExtensionChangeEntry:
    """
    A rename detected via USN where the file extension changed (e.g. .txt → .exe, .exe → .dll).
    Useful for spotting droppers or disguised executables that are renamed after creation.
    """
    mft_record_number: int
    old_name: str
    new_name: str
    old_ext: str
    new_ext: str
    timestamp_iso: str
    parent_path: str

    def flag_message(self) -> str:
        """Short message for table/report display."""
        return f"{self.old_ext or '(none)'} → {self.new_ext or '(none)'}"

    def detail_message(self) -> str:
        """Longer message for report."""
        return f"MFT #{self.mft_record_number}  {self.old_name!r} → {self.new_name!r}  ({self.old_ext or 'none'} → {self.new_ext or 'none'})  {self.parent_path}"


# --- Entropy / novelty metrics (Shannon entropy for forensic triage) ---


def shannon_entropy(s: str) -> float:
    """
    Shannon entropy (bits) of a string, using character frequencies.
    H = -sum(p(c) * log2(p(c))) over distinct characters c.
    Empty string returns 0.0. High values indicate random-looking or high-novelty strings.
    """
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    h = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            h -= p * math.log2(p)
    return h


def filename_entropy_report(
    records: list["MFTRecord"],
    path_table: dict[int, str],
    *,
    top_n: int = 200,
    min_entropy: float = 0.0,
) -> list[tuple[int, str, str, float]]:
    """
    Compute Shannon entropy of each file's primary name; return entries with highest entropy
    (random-looking names). Useful to detect generated/malicious filenames.

    Returns list of (record_number, filename, parent_path, entropy), sorted by entropy descending.
    """
    path_table = path_table or {}
    entries: list[tuple[int, str, str, float]] = []
    for rec in records:
        name = rec.primary_name()
        if not name or name == "(no name)":
            continue
        parent_path = parent_path_for_record(rec, path_table)
        h = shannon_entropy(name)
        if h >= min_entropy:
            entries.append((rec.record_number, name, parent_path, h))
    entries.sort(key=lambda x: (x[3], x[1]), reverse=True)
    return entries[:top_n]


@dataclass
class ExtensionEntropyPerDir:
    """Extension entropy for a single directory (Shannon entropy of extension distribution)."""
    directory: str
    entropy: float
    file_count: int
    distinct_extensions: int

    def ext_summary(self) -> str:
        return f"{self.distinct_extensions} distinct"


def extension_entropy_per_directory(
    records: list["MFTRecord"],
    path_table: dict[int, str],
    *,
    min_files: int = 2,
    top_n: int = 200,
) -> list[ExtensionEntropyPerDir]:
    """
    For each directory (parent path), compute Shannon entropy of the distribution of file
    extensions among its direct children. High entropy = many different extension types;
    low entropy = few types (e.g. all .txt). Sorted by entropy descending.

    Only includes directories with at least min_files direct children.
    """
    path_table = path_table or {}
    # directory -> list of extensions (one per file)
    by_dir: dict[str, list[str]] = {}
    for rec in records:
        name = rec.primary_name()
        if not name or name == "(no name)":
            continue
        parent_path = parent_path_for_record(rec, path_table)
        ext = (Path(name).suffix or "").lower()
        # Use empty string for no extension so it's counted
        by_dir.setdefault(parent_path, []).append(ext if ext else "(none)")

    result: list[ExtensionEntropyPerDir] = []
    for directory, exts in by_dir.items():
        if len(exts) < min_files:
            continue
        n = len(exts)
        counts = Counter(exts)
        h = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                h -= p * math.log2(p)
        result.append(ExtensionEntropyPerDir(
            directory=directory,
            entropy=round(h, 4),
            file_count=n,
            distinct_extensions=len(counts),
        ))
    result.sort(key=lambda e: (e.entropy, e.file_count), reverse=True)
    return result[:top_n]


# --- Directory churn analysis (dropper / staging detection) ---

_PERSISTENCE_PATH_MARKERS = (
    "\\startup\\",
    "\\windows\\system32\\tasks\\",
    "\\windows\\tasks\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
)

DEFAULT_CHURN_WINDOW_SECONDS = 120
DEFAULT_CHURN_MIN_FILES = 3


@dataclass
class DirectoryChurnEntry:
    """
    A directory where multiple new files were created within a short time window.
    High churn in a single directory can indicate dropper behaviour (archive extraction,
    payload staging) or persistence installation.
    """
    directory: str
    window_start_iso: str
    window_end_iso: str
    file_count: int
    file_names: list[str]
    extensions: list[str]
    has_executable: bool
    is_persistence_path: bool
    window_seconds: float
    risk: str  # "critical", "high", "medium"

    def flag_message(self) -> str:
        exts = ", ".join(sorted(set(self.extensions))) or "(none)"
        parts = [f"{self.file_count} files in {self.window_seconds:.0f}s"]
        if self.has_executable:
            parts.append("EXE")
        if self.is_persistence_path:
            parts.append("PERSIST")
        return f"{' | '.join(parts)}  [{exts}]"


def _is_persistence_location(normalized_path: str) -> bool:
    return any(m in normalized_path for m in _PERSISTENCE_PATH_MARKERS)


_CHURN_WRITE_REASONS = (
    USN_REASON_FILE_CREATE
    | USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND
    | USN_REASON_RENAME_NEW_NAME
)


def build_directory_churn_report(
    records: list["MFTRecord"],
    path_table: dict[int, str],
    *,
    window_seconds: int = DEFAULT_CHURN_WINDOW_SECONDS,
    min_files: int = DEFAULT_CHURN_MIN_FILES,
    top_n: int = 200,
    usn_records: list["UsnRecord"] | None = None,
) -> list[DirectoryChurnEntry]:
    """
    Detect directories where multiple files were created/written within a short
    time window — indicative of dropper extraction, payload staging, or
    persistence installation.

    Data-source strategy — both MFT and USN are merged, deduplicated by
    (parent_directory_lower, filename_lower) so the same file is never
    double-counted:

      1. MFT $FILE_NAME created timestamps — covers files currently on disk,
         including those whose USN creation events have rotated out of $J.
      2. USN Journal write events (FILE_CREATE, DATA_OVERWRITE, DATA_EXTEND,
         RENAME_NEW_NAME) — covers files that were created and then deleted
         (no longer in MFT).  USN parent paths are resolved via MFT correlation
         (same logic as parent_path_for_usn_record) so they group correctly
         with MFT entries.  When a file appears in both sources the USN
         timestamp wins (it's the real event-log time).

    Sliding-window algorithm per parent directory finds bursts of >= *min_files*
    unique filenames within *window_seconds*.  Persistence-path directories and
    those containing executables are scored higher.
    """
    path_table = path_table or {}
    ticks_per_sec = 10_000_000
    window_ticks = window_seconds * ticks_per_sec
    exec_ext = {
        ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jse", ".msi",
    }

    # Build rec_by_num for USN parent-path resolution via MFT correlation.
    rec_by_num: dict[int, MFTRecord] = {r.record_number: r for r in records}

    # Deduplicated (dir_lower, name_lower) -> (parent_display, tick, name_display)
    # USN timestamps take priority over MFT when both exist.
    merged: dict[tuple[str, str], tuple[str, int, str]] = {}

    # 1) Seed from MFT — one event per non-directory file record.
    for rec in records:
        if rec.is_directory:
            continue
        fn = rec.primary_file_name()
        if not fn or fn.created in (0, 0x7FFFFFFFFFFFFFFF):
            continue
        parent = parent_path_for_record(rec, path_table)
        name = rec.primary_name()
        key = (parent.lower(), name.lower())
        merged[key] = (parent, fn.created, name)

    # 2) Layer USN on top — overwrites MFT entries (USN timestamp is the
    #    real event time) and adds files not in MFT (deleted after creation).
    #    For each (dir, name), keep the earliest USN write timestamp.
    #    Uses parent_path_for_usn_record() for proper parent resolution
    #    (MFT correlation first, USN parent_ref fallback).
    if usn_records:
        usn_best: dict[tuple[str, str], tuple[str, int, str]] = {}
        for urec in usn_records:
            if not (urec.reason & _CHURN_WRITE_REASONS):
                continue
            if urec.timestamp in (0, 0x7FFFFFFFFFFFFFFF):
                continue
            fname = urec.file_name or ""
            if not fname:
                continue
            parent = parent_path_for_usn_record(urec, path_table, rec_by_num)
            key = (parent.lower(), fname.lower())
            prev = usn_best.get(key)
            if prev is None or urec.timestamp < prev[1]:
                usn_best[key] = (parent, urec.timestamp, fname)
        merged.update(usn_best)

    # Group by parent directory (canonical lowercase key; keep display-case path).
    by_dir: dict[str, tuple[str, list[tuple[int, str]]]] = {}
    for (_dir_lower, _name_lower), (parent, tick, name) in merged.items():
        dir_key = parent.lower()
        if dir_key not in by_dir:
            by_dir[dir_key] = (parent, [])
        by_dir[dir_key][1].append((tick, name))

    risk_rank = {"critical": 0, "high": 1, "medium": 2}

    result: list[DirectoryChurnEntry] = []
    for _dir_key, (display_dir, items) in by_dir.items():
        if len(items) < min_files:
            continue
        items.sort(key=lambda x: x[0])
        norm = ("\\" + display_dir.replace("/", "\\").strip("\\")).lower() + "\\"
        is_persist = _is_persistence_location(norm)

        # Find all bursts, keep only the most significant per directory.
        best: DirectoryChurnEntry | None = None
        i = 0
        used: set[int] = set()
        while i < len(items):
            if i in used:
                i += 1
                continue
            start_tick = items[i][0]
            j = i
            while j < len(items) and items[j][0] - start_tick <= window_ticks:
                j += 1
            # Burst is [i, j-1]. Ensure span never exceeds configured window (safety).
            last_idx = j - 1
            while last_idx > i and items[last_idx][0] - start_tick > window_ticks:
                last_idx -= 1
            burst_count = last_idx - i + 1
            if burst_count >= min_files:
                names = [items[k][1] for k in range(i, last_idx + 1)]
                ticks_range = items[last_idx][0] - items[i][0]
                extensions = [(Path(n).suffix or "").lower() for n in names]
                has_exec = any(e in exec_ext for e in extensions)
                risk = "medium"
                if has_exec and is_persist:
                    risk = "critical"
                elif has_exec or is_persist:
                    risk = "high"
                elif burst_count >= min_files * 3:
                    risk = "high"
                entry = DirectoryChurnEntry(
                    directory=display_dir,
                    window_start_iso=_win_timestamp_to_iso(items[i][0]),
                    window_end_iso=_win_timestamp_to_iso(items[last_idx][0]),
                    file_count=burst_count,
                    file_names=names,
                    extensions=extensions,
                    has_executable=has_exec,
                    is_persistence_path=is_persist,
                    window_seconds=ticks_range / ticks_per_sec,
                    risk=risk,
                )
                if best is None or (
                    risk_rank.get(entry.risk, 3), -entry.file_count
                ) < (risk_rank.get(best.risk, 3), -best.file_count):
                    best = entry
                for k in range(i, last_idx + 1):
                    used.add(k)
                i = last_idx + 1
            else:
                i += 1
        if best is not None:
            result.append(best)

    result.sort(key=lambda e: (
        {"critical": 0, "high": 1, "medium": 2}.get(e.risk, 3),
        -e.file_count,
        e.directory,
    ))
    return result[:top_n]


def build_extension_change_report(
    usn_records: list[UsnRecord],
    path_table: dict[int, str] | None = None,
) -> list[ExtensionChangeEntry]:
    """
    Detect renames where the file extension changed (e.g. filename.txt → filename.exe).

    Uses USN Journal records with RENAME_OLD_NAME and RENAME_NEW_NAME. For each file_ref,
    pairs each RENAME_OLD_NAME with the next RENAME_NEW_NAME (by timestamp); if the
    extension (suffix after last dot) differs, the rename is reported.

    path_table: optional MFT record_number -> full path; used to resolve parent path
    for the file (parent_ref from the USN record). If None, parent_path is "\\".
    """
    path_table = path_table or {}
    rename_reasons = USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME
    renames = [r for r in usn_records if r.reason & rename_reasons]
    if not renames:
        return []

    # Group by file_ref (MFT reference), then sort by timestamp and reason (OLD before NEW)
    by_ref: dict[int, list[UsnRecord]] = {}
    for rec in renames:
        ref = rec.file_ref
        if ref not in by_ref:
            by_ref[ref] = []
        by_ref[ref].append(rec)

    result: list[ExtensionChangeEntry] = []
    for _ref, recs in by_ref.items():
        recs_sorted = sorted(recs, key=lambda r: (r.timestamp, r.reason))
        i = 0
        while i < len(recs_sorted):
            old_rec = recs_sorted[i]
            if not (old_rec.reason & USN_REASON_RENAME_OLD_NAME):
                i += 1
                continue
            old_name = old_rec.file_name or ""
            # Find next record with RENAME_NEW_NAME (same file_ref)
            j = i + 1
            while j < len(recs_sorted) and not (recs_sorted[j].reason & USN_REASON_RENAME_NEW_NAME):
                j += 1
            if j >= len(recs_sorted):
                break
            new_rec = recs_sorted[j]
            new_name = new_rec.file_name or ""
            old_ext = (Path(old_name).suffix or "").lower()
            new_ext = (Path(new_name).suffix or "").lower()
            if old_ext != new_ext:
                parent_path = path_table.get(new_rec.parent_mft_record_number(), "\\")
                result.append(ExtensionChangeEntry(
                    mft_record_number=new_rec.mft_record_number(),
                    old_name=old_name,
                    new_name=new_name,
                    old_ext=old_ext,
                    new_ext=new_ext,
                    timestamp_iso=new_rec.timestamp_iso(),
                    parent_path=parent_path,
                ))
            i = j + 1

    result.sort(key=lambda e: (e.timestamp_iso, e.mft_record_number))
    return result


# --- Temporal burst detection (Poisson + burstiness for malware-like activity) ---

def poisson_survival_p_value(lam_per_min: float, k: int) -> float:
    """
    P(X ≥ k) under Poisson(λ) with λ = baseline events per minute.
    If this probability is extremely small, observed count k is an anomaly (burst).

    P(X ≥ k) = 1 - sum(i=0 to k-1) e^(-λ) * λ^i / i!
    """
    if k <= 0:
        return 1.0
    if lam_per_min <= 0:
        return 0.0 if k > 0 else 1.0
    # Cumulative P(X < k) = sum(i=0..k-1) e^(-λ) λ^i / i!
    # Recurrence: term_0 = e^(-λ), term_i = term_{i-1} * λ / i
    term = math.exp(-lam_per_min)
    cdf = term
    for i in range(1, k):
        term *= lam_per_min / i
        cdf += term
    return 1.0 - cdf


def burstiness_b(inter_arrival_times_sec: list[float]) -> float | None:
    """
    Burstiness metric B = (σ - μ) / (σ + μ), where μ = mean and σ = std of inter-arrival times.
    Requires at least 2 inter-arrival times (i.e. 3 events).

    Interpretation:
      B ≈ -1  periodic
      B ≈  0  random
      B ≈ +1  bursty (malware-like)
    """
    if len(inter_arrival_times_sec) < 2:
        return None
    mu = statistics.mean(inter_arrival_times_sec)
    sigma = statistics.stdev(inter_arrival_times_sec)
    denom = sigma + mu
    if denom == 0:
        return 0.0
    return (sigma - mu) / denom


def _burstiness_interpretation(b: float) -> str:
    if b <= -0.5:
        return "periodic"
    if b >= 0.5:
        return "bursty"
    return "random"


@dataclass
class PoissonBurstWindowEntry:
    """
    A time window where the observed event count is anomalously high under a Poisson baseline.
    Very low P(X ≥ k) indicates a temporal burst (e.g. malware mass creation).
    """
    window_start_iso: str
    window_end_iso: str
    observed_count: int
    baseline_per_min: float
    p_value: float
    directory: str | None  # None = global window
    is_anomaly: bool

    def flag_message(self) -> str:
        return f"Burst: {self.observed_count} events (P(X≥k)={self.p_value:.2e})"


@dataclass
class DirectoryBurstinessEntry:
    """
    Burstiness B = (σ-μ)/(σ+μ) for a directory's file-activity inter-arrival times.
    B ≈ +1 suggests bursty (malware-like) activity; B ≈ -1 periodic; B ≈ 0 random.
    """
    directory: str
    burstiness_b: float
    interpretation: str  # "periodic" | "random" | "bursty"
    event_count: int
    mean_inter_arrival_sec: float
    std_inter_arrival_sec: float

    def flag_message(self) -> str:
        return f"B={self.burstiness_b:.3f} ({self.interpretation})"


DEFAULT_BURST_WINDOW_SECONDS = 60
DEFAULT_POISSON_ANOMALY_P_THRESHOLD = 0.001
DEFAULT_BURSTINESS_ANOMALY_MIN_B = 0.5


def build_temporal_burst_report(
    records: list["MFTRecord"],
    path_table: dict[int, str],
    *,
    window_seconds: int = DEFAULT_BURST_WINDOW_SECONDS,
    poisson_p_threshold: float = DEFAULT_POISSON_ANOMALY_P_THRESHOLD,
    burstiness_min_b: float = DEFAULT_BURSTINESS_ANOMALY_MIN_B,
    top_n_poisson: int = 100,
    top_n_burstiness: int = 100,
    usn_records: list["UsnRecord"] | None = None,
) -> tuple[list[PoissonBurstWindowEntry], list[DirectoryBurstinessEntry]]:
    """
    Temporal burst detection: (1) Poisson burst score and (2) burstiness B per directory.

    1) Poisson: baseline λ = mean events per minute over the timeline. For each sliding
       window of *window_seconds*, compute observed count k and P(X ≥ k). If P(X ≥ k)
       < *poisson_p_threshold* → anomaly (burst).

    2) Burstiness: per directory, inter-arrival times between events → μ, σ → B = (σ-μ)/(σ+μ).
       B ≈ +1 → bursty (malware-like); B ≈ -1 → periodic; B ≈ 0 → random.

    Uses the same merged MFT + USN event stream as directory churn (one event per file
    creation/write per directory). Returns (poisson_anomaly_windows, burstiness_per_directory).
    """
    path_table = path_table or {}
    ticks_per_sec = 10_000_000
    window_ticks = window_seconds * ticks_per_sec

    # Reuse churn-style merged (dir, tick) events
    rec_by_num: dict[int, MFTRecord] = {r.record_number: r for r in records}
    merged: dict[tuple[str, str], tuple[str, int, str]] = {}
    for rec in records:
        if rec.is_directory:
            continue
        fn = rec.primary_file_name()
        if not fn or fn.created in (0, 0x7FFFFFFFFFFFFFFF):
            continue
        parent = parent_path_for_record(rec, path_table)
        name = rec.primary_name()
        key = (parent.lower(), name.lower())
        merged[key] = (parent, fn.created, name)
    if usn_records:
        usn_best: dict[tuple[str, str], tuple[str, int, str]] = {}
        for urec in usn_records:
            if not (urec.reason & _CHURN_WRITE_REASONS):
                continue
            if urec.timestamp in (0, 0x7FFFFFFFFFFFFFFF):
                continue
            fname = urec.file_name or ""
            if not fname:
                continue
            parent = parent_path_for_usn_record(urec, path_table, rec_by_num)
            key = (parent.lower(), fname.lower())
            prev = usn_best.get(key)
            if prev is None or urec.timestamp < prev[1]:
                usn_best[key] = (parent, urec.timestamp, fname)
        merged.update(usn_best)

    # (directory_display, tick) for each event; keep first display path per dir
    events_by_dir: dict[str, list[int]] = {}
    dir_display: dict[str, str] = {}
    all_ticks: list[int] = []
    for (_dl, _nl), (parent, tick, _name) in merged.items():
        all_ticks.append(tick)
        key = parent.lower()
        if key not in events_by_dir:
            events_by_dir[key] = []
            dir_display[key] = parent
        events_by_dir[key].append(tick)

    if not all_ticks:
        return [], []

    all_ticks.sort()
    span_ticks = all_ticks[-1] - all_ticks[0]
    span_minutes = (span_ticks / ticks_per_sec) / 60.0
    if span_minutes <= 0:
        span_minutes = 1.0
    total_events = len(all_ticks)
    baseline_per_min = total_events / span_minutes

    # --- Poisson: sliding windows
    poisson_entries: list[PoissonBurstWindowEntry] = []
    seen_windows: set[tuple[int, int]] = set()
    i = 0
    while i < len(all_ticks):
        start_tick = all_ticks[i]
        end_tick = start_tick + window_ticks
        j = i
        while j < len(all_ticks) and all_ticks[j] < end_tick:
            j += 1
        k = j - i
        if k > 0:
            p = poisson_survival_p_value(baseline_per_min, k)
            window_key = (start_tick, k)
            if window_key not in seen_windows and p < poisson_p_threshold:
                seen_windows.add(window_key)
                poisson_entries.append(PoissonBurstWindowEntry(
                    window_start_iso=_win_timestamp_to_iso(start_tick),
                    window_end_iso=_win_timestamp_to_iso(min(all_ticks[j - 1], start_tick + window_ticks)),
                    observed_count=k,
                    baseline_per_min=baseline_per_min,
                    p_value=p,
                    directory=None,
                    is_anomaly=True,
                ))
        i += 1

    poisson_entries.sort(key=lambda e: (e.p_value, -e.observed_count))
    poisson_entries = poisson_entries[:top_n_poisson]

    # --- Burstiness per directory
    burstiness_entries: list[DirectoryBurstinessEntry] = []
    for dir_key, ticks in events_by_dir.items():
        ticks = sorted(ticks)
        if len(ticks) < 3:
            continue
        gaps = [(ticks[i] - ticks[i - 1]) / ticks_per_sec for i in range(1, len(ticks))]
        b = burstiness_b(gaps)
        if b is None:
            continue
        mu = statistics.mean(gaps)
        sigma = statistics.stdev(gaps)
        display_dir = dir_display.get(dir_key, dir_key)
        burstiness_entries.append(DirectoryBurstinessEntry(
            directory=display_dir,
            burstiness_b=b,
            interpretation=_burstiness_interpretation(b),
            event_count=len(ticks),
            mean_inter_arrival_sec=mu,
            std_inter_arrival_sec=sigma,
        ))

    burstiness_entries.sort(key=lambda e: (-e.burstiness_b, -e.event_count))
    burstiness_anomalies = [e for e in burstiness_entries if e.burstiness_b >= burstiness_min_b]
    burstiness_anomalies = burstiness_anomalies[:top_n_burstiness]

    return poisson_entries, burstiness_anomalies


# =============================================================================
# ABNORMAL FILE ACTIVITY SEQUENCES (per abnormal_sequence_spec.txt)
# =============================================================================


class EventType(Enum):
    """Normalized event types from USN reason flags."""
    CREATE = "CREATE"
    WRITE = "WRITE"
    OVERWRITE = "OVERWRITE"
    RENAME = "RENAME"
    DELETE = "DELETE"
    METADATA = "METADATA"
    DIRECTORY = "DIRECTORY"


@dataclass
class NormalizedEvent:
    """
    Joined Journal + MFT event. Primary processing object for abnormal sequence detection.
    """
    usn: int
    timestamp: datetime
    file_ref: int
    parent_ref: int
    filename: str
    reason_flags: list[str]
    extension: str
    full_path: str
    file_size: int
    is_directory: bool
    is_deleted_record: bool
    si_created: datetime | None
    fn_created: datetime | None
    mft_record_number: int
    sequence_number: int
    event_type: EventType
    timestamp_delta_seconds: float


@dataclass
class SequenceFinding:
    """Detection result from a pattern detector."""
    pattern: str
    file_ref: int | None
    filename: str
    path: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    composite_score: float
    events: list[NormalizedEvent]
    evidence: list[str]


@dataclass
class AttackChain:
    """Linked findings representing a complete attack sequence."""
    chain_length: int
    patterns: list[str]
    chain_score: float
    start_time: datetime
    end_time: datetime
    total_duration_seconds: float
    findings: list[SequenceFinding]
    narrative: str


# --- Suspicious path patterns (case-insensitive regex) ---
_SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\\temp\\", re.I),
    re.compile(r"\\appdata\\roaming\\", re.I),
    re.compile(r"\\appdata\\local\\temp\\", re.I),
    re.compile(r"\\programdata\\", re.I),
    re.compile(r"\\users\\public\\", re.I),
    re.compile(r"\\downloads\\", re.I),
    re.compile(r"^c:\\[^\\]+\\.(exe|dll|ps1)$", re.I),
]

# --- Suspicious extensions ---
_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".sys", ".scr",
    ".com", ".hta", ".msi",
}

# --- Archive extensions (for STAGED_DROPPER) ---
_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".cab"}

# --- Script types (elevated scrutiny) ---
_SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".bat"}

# --- System binary names for MASQUERADE_RENAME ---
_SYSTEM_BINARY_NAMES = {
    "svchost", "explorer", "lsass", "csrss", "winlogon", "services",
    "spoolsv", "taskhost", "dllhost", "conhost",
}

# --- Random/temp filename patterns ---
_RANDOM_TEMP_PATTERN = re.compile(r"^([0-9a-f]{6,}|tmp\d+|temp\d+)", re.I)


def _win_ticks_to_datetime(ticks: int) -> datetime | None:
    """Convert Windows FILETIME to datetime. Returns None if invalid."""
    if ticks is None or ticks in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    try:
        EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
        us = ticks / 10
        return EPOCH_1601 + timedelta(microseconds=us)
    except (OverflowError, OSError, ValueError):
        return None


def _is_suspicious_path(path: str) -> bool:
    """True if path matches any suspicious path pattern."""
    norm = ("\\" + (path or "").replace("/", "\\").strip("\\")).lower() + "\\"
    return any(p.search(norm) for p in _SUSPICIOUS_PATH_PATTERNS)


def _is_suspicious_extension(ext: str) -> bool:
    """True if extension is in suspicious list."""
    return (ext or "").lower() in _SUSPICIOUS_EXTENSIONS


def _is_script_extension(ext: str) -> bool:
    """True if extension is a script type."""
    return (ext or "").lower() in _SCRIPT_EXTENSIONS


def _is_timestomp_suspicious(ev: NormalizedEvent) -> bool:
    """
    Timestomp detection per spec:
    - Condition 1: abs(si_created - fn_created) > 2.0 seconds
    - Condition 2: si_created.microsecond == 0 (zero sub-second precision)
    """
    if ev.si_created is None:
        return False
    if ev.fn_created is not None:
        delta = abs((ev.si_created - ev.fn_created).total_seconds())
        if delta > 2.0:
            return True
    if ev.si_created.microsecond == 0:
        return True
    return False


def _normalize_reason_to_event_type(reason: int, is_dir: bool, filename: str) -> EventType:
    """Map USN reason flags to EventType enum."""
    if reason & USN_REASON_FILE_CREATE:
        return EventType.DIRECTORY if is_dir else EventType.CREATE
    if reason & USN_REASON_DATA_EXTEND:
        return EventType.WRITE
    if reason & (USN_REASON_DATA_OVERWRITE | USN_REASON_NAMED_DATA_OVERWRITE):
        return EventType.OVERWRITE
    if reason & (USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME):
        return EventType.RENAME
    if reason & USN_REASON_FILE_DELETE:
        return EventType.DELETE
    if reason & USN_REASON_BASIC_INFO_CHANGE:
        return EventType.METADATA
    return EventType.WRITE  # fallback for other data changes


def _build_reason_flags_list(reason: int) -> list[str]:
    """Convert reason bitmask to list of flag names."""
    return [USN_REASON_NAMES[f] for f in USN_REASON_NAMES if reason & f]


def build_abnormal_sequence_event_stream(
    records: list[MFTRecord],
    usn_records: list[UsnRecord],
    path_table: dict[int, str] | None = None,
) -> tuple[
    list[NormalizedEvent],
    dict[int, list[NormalizedEvent]],
    dict[int, list[NormalizedEvent]],
    list[str],
]:
    """
    Build event stream and indexes per spec section 4.
    Returns (event_stream, events_by_ref, events_by_parent, usn_gap_alerts).
    """
    path_table = path_table or {}
    rec_by_num: dict[int, MFTRecord] = {r.record_number: r for r in records}
    ticks_per_sec = 10_000_000

    # Sort journal by USN ascending
    sorted_usn = sorted(usn_records, key=lambda r: r.usn)

    # Check for USN gaps (journal wrap-around)
    usn_gap_alerts: list[str] = []
    for i in range(1, len(sorted_usn)):
        gap = sorted_usn[i].usn - sorted_usn[i - 1].usn
        if gap > 1_000_000:  # heuristic: large gap indicates wrap
            usn_gap_alerts.append(
                f"USN gap detected: {gap} between USN {sorted_usn[i-1].usn} and {sorted_usn[i].usn}"
            )

    event_stream: list[NormalizedEvent] = []
    for urec in sorted_usn:
        file_ref = urec.file_ref
        mft_num = urec.mft_record_number()
        seq_num = (file_ref >> 48) & 0xFFFF
        mft_rec = rec_by_num.get(mft_num)

        # MFT fields (may be None if record missing/reused)
        ext = ""
        full_path = "\\"
        file_size = 0
        is_directory = False
        is_deleted_record = True
        si_created: datetime | None = None
        fn_created: datetime | None = None
        timestamp_delta_seconds = 0.0

        if mft_rec:
            fn = mft_rec.primary_file_name()
            name = urec.file_name or mft_rec.primary_name()
            ext = (Path(name).suffix or "").lower()
            full_path = path_table.get(mft_rec.record_number, "\\")
            if not full_path.endswith("\\"):
                full_path += "\\"
            full_path += name or ""
            file_size = mft_rec.size()
            is_directory = mft_rec.is_directory
            is_deleted_record = not mft_rec.in_use
            if mft_rec.standard_info:
                si_created = _win_ticks_to_datetime(mft_rec.standard_info.created)
            if fn:
                fn_created = _win_ticks_to_datetime(fn.created)
            if si_created and fn_created:
                timestamp_delta_seconds = abs((si_created - fn_created).total_seconds())

        ts_dt = _win_ticks_to_datetime(urec.timestamp) or datetime.now(timezone.utc)
        event_type = _normalize_reason_to_event_type(
            urec.reason, is_directory, urec.file_name or ""
        )
        reason_flags = _build_reason_flags_list(urec.reason)

        ev = NormalizedEvent(
            usn=urec.usn,
            timestamp=ts_dt,
            file_ref=file_ref,
            parent_ref=urec.parent_ref,
            filename=urec.file_name or "",
            reason_flags=reason_flags,
            extension=ext,
            full_path=full_path,
            file_size=file_size,
            is_directory=is_directory,
            is_deleted_record=is_deleted_record,
            si_created=si_created,
            fn_created=fn_created,
            mft_record_number=mft_num,
            sequence_number=seq_num,
            event_type=event_type,
            timestamp_delta_seconds=timestamp_delta_seconds,
        )
        event_stream.append(ev)

    events_by_ref: dict[int, list[NormalizedEvent]] = {}
    for ev in event_stream:
        ref = ev.file_ref
        if ref not in events_by_ref:
            events_by_ref[ref] = []
        events_by_ref[ref].append(ev)

    events_by_parent: dict[int, list[NormalizedEvent]] = {}
    for ev in event_stream:
        pref = ev.parent_ref & 0xFFFFFFFFFFFF
        if pref not in events_by_parent:
            events_by_parent[pref] = []
        events_by_parent[pref].append(ev)

    return event_stream, events_by_ref, events_by_parent, usn_gap_alerts


def _detect_dropper_cleanup(events_by_ref: dict[int, list[NormalizedEvent]]) -> list[SequenceFinding]:
    """DROPPER_CLEANUP: CREATE + DELETE on same file_ref within 300s, suspicious ext+path."""
    findings: list[SequenceFinding] = []
    base_score = 0.75
    for file_ref, evs in events_by_ref.items():
        evs_sorted = sorted(evs, key=lambda e: e.usn)
        create_ev = None
        delete_ev = None
        for ev in evs_sorted:
            if ev.event_type == EventType.CREATE:
                create_ev = ev
            elif ev.event_type == EventType.DELETE:
                delete_ev = ev
        if not create_ev or not delete_ev:
            continue
        if not _is_suspicious_extension(create_ev.extension):
            continue
        if not _is_suspicious_path(create_ev.full_path):
            continue
        duration = (delete_ev.timestamp - create_ev.timestamp).total_seconds()
        if duration < 0 or duration > 300:
            continue
        has_write = any(
            ev.event_type == EventType.WRITE
            for ev in evs_sorted
            if create_ev.usn < ev.usn < delete_ev.usn
        )
        score = base_score
        if duration < 30:
            score += 0.15
        elif duration < 120:
            score += 0.08
        if has_write:
            score += 0.05
        if _is_timestomp_suspicious(create_ev):
            score += 0.15
        if create_ev.is_deleted_record:
            score += 0.10
        if _is_script_extension(create_ev.extension):
            score += 0.10
        score = min(score, 1.0)
        evidence = [
            f"CREATE then DELETE within {duration:.1f}s",
            f"File deleted: {create_ev.filename or '(no name)'}",
            f"Path: {create_ev.full_path}",
        ]
        findings.append(SequenceFinding(
            pattern="DROPPER_CLEANUP",
            file_ref=file_ref,
            filename=create_ev.filename,
            path=create_ev.full_path,
            start_time=create_ev.timestamp,
            end_time=delete_ev.timestamp,
            duration_seconds=duration,
            composite_score=score,
            events=[create_ev, delete_ev],
            evidence=evidence,
        ))
    return findings


def _detect_masquerade_rename(events_by_ref: dict[int, list[NormalizedEvent]]) -> list[SequenceFinding]:
    """MASQUERADE_RENAME: RENAME_OLD_NAME then RENAME_NEW_NAME to system binary name from random/temp.
    One finding per file_ref (keeps highest-scoring if multiple renames qualify).
    """
    findings: list[SequenceFinding] = []
    base_score = 0.90
    for file_ref, evs in events_by_ref.items():
        evs_sorted = sorted(evs, key=lambda e: e.usn)
        best: SequenceFinding | None = None
        i = 0
        while i < len(evs_sorted):
            ev = evs_sorted[i]
            if ev.event_type != EventType.RENAME or "RENAME_OLD_NAME" not in ev.reason_flags:
                i += 1
                continue
            old_name = ev.filename
            j = i + 1
            while j < len(evs_sorted):
                cand = evs_sorted[j]
                if cand.event_type == EventType.RENAME and "RENAME_NEW_NAME" in cand.reason_flags:
                    break
                j += 1
            if j >= len(evs_sorted):
                break
            new_ev = evs_sorted[j]
            new_name = new_ev.filename
            base_new = (Path(new_name).stem or "").lower()
            if base_new not in _SYSTEM_BINARY_NAMES:
                i = j + 1
                continue
            if not _RANDOM_TEMP_PATTERN.match(old_name):
                i = j + 1
                continue
            score = base_score
            if _is_timestomp_suspicious(ev):
                score += 0.15
            if _is_suspicious_path(ev.full_path):
                score += 0.10
            score = min(score, 1.0)
            evidence = [
                f"Renamed from {old_name!r} to {new_name!r} (system binary)",
                f"Path: {ev.full_path}",
            ]
            candidate = SequenceFinding(
                pattern="MASQUERADE_RENAME",
                file_ref=file_ref,
                filename=new_name,
                path=ev.full_path,
                start_time=ev.timestamp,
                end_time=new_ev.timestamp,
                duration_seconds=(new_ev.timestamp - ev.timestamp).total_seconds(),
                composite_score=score,
                events=[ev, new_ev],
                evidence=evidence,
            )
            if best is None or score > best.composite_score:
                best = candidate
            i = j + 1
        if best is not None:
            findings.append(best)
    return findings


def _detect_staged_dropper(events_by_parent: dict[int, list[NormalizedEvent]]) -> list[SequenceFinding]:
    """STAGED_DROPPER: 3+ CREATEs in same parent within 120s, suspicious or archive extensions.
    One finding per directory path (keeps highest-scoring if multiple bursts in same dir).
    """
    findings: list[SequenceFinding] = []
    base_score = 0.70
    by_dir: dict[str, SequenceFinding] = {}
    for parent_ref, evs in events_by_parent.items():
        creates = [e for e in evs if e.event_type == EventType.CREATE and not e.is_directory]
        if len(creates) < 3:
            continue
        creates_sorted = sorted(creates, key=lambda e: e.usn)
        dir_path = creates_sorted[0].full_path.rsplit("\\", 1)[0] if creates_sorted else "\\"
        if not _is_suspicious_path(dir_path):
            continue
        dir_key = dir_path.lower()
        if dir_key in by_dir:
            continue  # Already have best for this dir
        seen_windows: set[tuple[int, int]] = set()
        best: SequenceFinding | None = None
        for anchor in creates_sorted:
            window_start = anchor.timestamp
            window_end = window_start + timedelta(seconds=120)
            in_window = [e for e in creates_sorted if window_start <= e.timestamp <= window_end]
            # Deduplicate by full_path: same file can have multiple CREATE events (e.g. create/delete/recreate)
            seen_paths: set[str] = set()
            unique_events: list[NormalizedEvent] = []
            for e in in_window:
                path_key = (e.full_path or e.filename or "").lower()
                if path_key and path_key not in seen_paths:
                    seen_paths.add(path_key)
                    unique_events.append(e)
            unique_count = len(unique_events)
            if unique_count < 3:
                continue
            exts = {e.extension for e in unique_events}
            has_suspicious = any(_is_suspicious_extension(ext) for ext in exts)
            has_archive = any(ext in _ARCHIVE_EXTENSIONS for ext in exts)
            if not has_suspicious and not has_archive:
                continue
            key = (anchor.usn, unique_count)
            if key in seen_windows:
                continue
            seen_windows.add(key)
            score = base_score
            if unique_count > 10:
                score += 0.15
            elif unique_count > 5:
                score += 0.08
            if has_archive and has_suspicious:
                score += 0.10
            if any(_is_timestomp_suspicious(e) for e in unique_events):
                score += 0.15
            score = min(score, 1.0)
            first_ev = min(unique_events, key=lambda e: e.usn)
            last_ev = max(unique_events, key=lambda e: e.usn)
            file_list = [e.full_path or e.filename or "(no name)" for e in unique_events[:25]]
            evidence = [
                f"{unique_count} unique files created in 120s ({len(in_window)} CREATE events)",
                f"Extensions: {', '.join(exts) or 'none'}",
                "Files created:",
            ] + [f"  • {f}" for f in file_list]
            if unique_count > 25:
                evidence.append(f"  … and {unique_count - 25} more")
            candidate = SequenceFinding(
                pattern="STAGED_DROPPER",
                file_ref=None,
                filename="",
                path=dir_path,
                start_time=first_ev.timestamp,
                end_time=last_ev.timestamp,
                duration_seconds=(last_ev.timestamp - first_ev.timestamp).total_seconds(),
                composite_score=score,
                events=unique_events,
                evidence=evidence,
            )
            if best is None or score > best.composite_score:
                best = candidate
            break  # One window per parent
        if best is not None:
            by_dir[dir_key] = best
    return list(by_dir.values())


def _detect_overwrite_then_delete(events_by_ref: dict[int, list[NormalizedEvent]]) -> list[SequenceFinding]:
    """OVERWRITE_THEN_DELETE: OVERWRITE then DELETE within 30s."""
    findings: list[SequenceFinding] = []
    base_score = 0.80
    for file_ref, evs in events_by_ref.items():
        evs_sorted = sorted(evs, key=lambda e: e.usn)
        overwrite_ev = None
        delete_ev = None
        for ev in evs_sorted:
            if ev.event_type == EventType.OVERWRITE:
                overwrite_ev = ev
            elif ev.event_type == EventType.DELETE and overwrite_ev:
                delete_ev = ev
                break
        if not overwrite_ev or not delete_ev:
            continue
        duration = (delete_ev.timestamp - overwrite_ev.timestamp).total_seconds()
        if duration < 0 or duration > 30:
            continue
        score = base_score
        if _is_timestomp_suspicious(overwrite_ev):
            score += 0.15
        if _is_suspicious_extension(overwrite_ev.extension):
            score += 0.10
        score = min(score, 1.0)
        evidence = [
            f"OVERWRITE then DELETE within {duration:.1f}s",
            f"File: {overwrite_ev.filename or '(no name)'}",
            f"Path: {overwrite_ev.full_path}",
        ]
        findings.append(SequenceFinding(
            pattern="OVERWRITE_THEN_DELETE",
            file_ref=file_ref,
            filename=overwrite_ev.filename,
            path=overwrite_ev.full_path,
            start_time=overwrite_ev.timestamp,
            end_time=delete_ev.timestamp,
            duration_seconds=duration,
            composite_score=score,
            events=[overwrite_ev, delete_ev],
            evidence=evidence,
        ))
    return findings


def _detect_rapid_mass_deletion(event_stream: list[NormalizedEvent]) -> list[SequenceFinding]:
    """RAPID_MASS_DELETION: 20+ DELETEs within 60s."""
    findings: list[SequenceFinding] = []
    base_score = 0.85
    deletes = [e for e in event_stream if e.event_type == EventType.DELETE]
    deletes_sorted = sorted(deletes, key=lambda e: e.usn)
    i = 0
    while i < len(deletes_sorted):
        anchor = deletes_sorted[i]
        window_end = anchor.timestamp + timedelta(seconds=60)
        count = 0
        j = i
        while j < len(deletes_sorted) and deletes_sorted[j].timestamp <= window_end:
            count += 1
            j += 1
        if count >= 20:
            deleted_events = deletes_sorted[i:j]
            # Deduplicate by full_path: same file can have multiple DELETE events
            seen_paths: set[str] = set()
            unique_deleted: list[NormalizedEvent] = []
            for e in deleted_events:
                path_key = (e.full_path or e.filename or "").lower()
                if path_key and path_key not in seen_paths:
                    seen_paths.add(path_key)
                    unique_deleted.append(e)
            unique_count = len(unique_deleted)
            if unique_count < 20:
                i += 1
                continue
            last_ev = deletes_sorted[j - 1]
            score = base_score
            if unique_count > 100:
                score += 0.15
            elif unique_count > 50:
                score += 0.08
            score = min(score, 1.0)
            file_list = [e.full_path or e.filename or "(no name)" for e in unique_deleted[:30]]
            evidence = [
                f"{unique_count} unique files deleted within 60s ({count} DELETE events)",
                "Files deleted:",
            ] + [f"  • {f}" for f in file_list]
            if unique_count > 30:
                evidence.append(f"  … and {unique_count - 30} more")
            findings.append(SequenceFinding(
                pattern="RAPID_MASS_DELETION",
                file_ref=None,
                filename="",
                path="",
                start_time=anchor.timestamp,
                end_time=last_ev.timestamp,
                duration_seconds=60.0,
                composite_score=score,
                events=unique_deleted,
                evidence=evidence,
            ))
            i = j
        else:
            i += 1
    return findings


def _detect_executable_in_suspicious_path(event_stream: list[NormalizedEvent]) -> list[SequenceFinding]:
    """EXECUTABLE_IN_SUSPICIOUS_PATH: CREATE with suspicious ext in suspicious path.
    One finding per full_path (keeps highest-scoring if same path appears multiple times).
    """
    findings: list[SequenceFinding] = []
    base_score = 0.60
    by_path: dict[str, SequenceFinding] = {}
    for ev in event_stream:
        if ev.event_type != EventType.CREATE:
            continue
        if not _is_suspicious_extension(ev.extension):
            continue
        if not _is_suspicious_path(ev.full_path):
            continue
        score = base_score
        if _is_timestomp_suspicious(ev):
            score += 0.15
        if ev.is_deleted_record:
            score += 0.10
        if _is_script_extension(ev.extension):
            score += 0.10
        score = min(score, 1.0)
        evidence = [
            f"Executable/script created in suspicious path: {ev.full_path}",
            f"File: {ev.filename or '(no name)'}",
        ]
        candidate = SequenceFinding(
            pattern="EXECUTABLE_IN_SUSPICIOUS_PATH",
            file_ref=ev.file_ref,
            filename=ev.filename,
            path=ev.full_path,
            start_time=ev.timestamp,
            end_time=ev.timestamp,
            duration_seconds=0.0,
            composite_score=score,
            events=[ev],
            evidence=evidence,
        )
        path_key = (ev.full_path or "").lower()
        if path_key not in by_path or score > by_path[path_key].composite_score:
            by_path[path_key] = candidate
    return list(by_path.values())


def _detect_timestomp_with_write(events_by_ref: dict[int, list[NormalizedEvent]]) -> list[SequenceFinding]:
    """TIMESTOMP_WITH_WRITE: WRITE then METADATA within 5s AND timestomp detected.
    One finding per file_ref (keeps highest-scoring if multiple WRITE->METADATA pairs exist).
    """
    findings: list[SequenceFinding] = []
    base_score = 0.85
    for file_ref, evs in events_by_ref.items():
        evs_sorted = sorted(evs, key=lambda e: e.usn)
        best: SequenceFinding | None = None
        for i, ev in enumerate(evs_sorted):
            if ev.event_type != EventType.WRITE:
                continue
            for j in range(i + 1, len(evs_sorted)):
                meta_ev = evs_sorted[j]
                if meta_ev.event_type != EventType.METADATA:
                    continue
                duration = (meta_ev.timestamp - ev.timestamp).total_seconds()
                if duration > 5:
                    break
                if not _is_timestomp_suspicious(meta_ev):
                    continue
                score = base_score
                if meta_ev.timestamp_delta_seconds > 86400:
                    score += 0.15
                elif meta_ev.timestamp_delta_seconds > 3600:
                    score += 0.08
                score = min(score, 1.0)
                evidence = [
                    f"WRITE then METADATA within {duration:.1f}s",
                    f"Timestomp: SI vs FN delta={meta_ev.timestamp_delta_seconds:.0f}s",
                    f"File: {ev.filename or '(no name)'}",
                    f"Path: {ev.full_path}",
                ]
                candidate = SequenceFinding(
                    pattern="TIMESTOMP_WITH_WRITE",
                    file_ref=file_ref,
                    filename=ev.filename,
                    path=ev.full_path,
                    start_time=ev.timestamp,
                    end_time=meta_ev.timestamp,
                    duration_seconds=duration,
                    composite_score=score,
                    events=[ev, meta_ev],
                    evidence=evidence,
                )
                if best is None or score > best.composite_score:
                    best = candidate
                break
        if best is not None:
            findings.append(best)
    return findings


def _link_attack_chains(
    findings: list[SequenceFinding],
    gap_seconds: float = 300.0,
) -> tuple[list[AttackChain], list[SequenceFinding]]:
    """
    Link temporally and spatially related findings into AttackChains.
    Returns (chains, unlinked_findings). Only creates chains with 2+ findings.
    """
    sorted_findings = sorted(findings, key=lambda f: f.start_time)
    used: set[int] = set()
    chains: list[AttackChain] = []

    for i, fa in enumerate(sorted_findings):
        if i in used:
            continue
        chain_findings = [fa]
        chain_indices = [i]
        path_a = (fa.path or "").rsplit("\\", 1)[0].lower()
        refs_a = {e.file_ref for e in fa.events if e.file_ref is not None}

        for j, fb in enumerate(sorted_findings):
            if j in used or j in chain_indices:
                continue
            if fb.start_time < fa.end_time:
                continue
            gap = (fb.start_time - fa.end_time).total_seconds()
            if gap > gap_seconds:
                continue
            path_b = (fb.path or "").rsplit("\\", 1)[0].lower()
            refs_b = {e.file_ref for e in fb.events if e.file_ref is not None}
            same_path = path_a and path_b and path_a == path_b
            shared_ref = bool(refs_a & refs_b)
            # Don't chain duplicate patterns (e.g. TIMESTOMP -> TIMESTOMP)
            if fb.pattern in [f.pattern for f in chain_findings]:
                continue
            if same_path or shared_ref:
                chain_findings.append(fb)
                chain_indices.append(j)
                path_a = path_b
                refs_a = refs_a | refs_b
                fa = fb

        if len(chain_findings) >= 2:
            for idx in chain_indices:
                used.add(idx)
            start = min(f.start_time for f in chain_findings)
            end = max(f.end_time for f in chain_findings)
            avg_score = sum(f.composite_score for f in chain_findings) / len(chain_findings)
            chain_score = min(avg_score * 1.3, 1.0)
            patterns = [f.pattern for f in chain_findings]
            narrative = _generate_chain_narrative(chain_findings)
            chains.append(AttackChain(
                chain_length=len(chain_findings),
                patterns=patterns,
                chain_score=chain_score,
                start_time=start,
                end_time=end,
                total_duration_seconds=(end - start).total_seconds(),
                findings=chain_findings,
                narrative=narrative,
            ))

    unlinked = [f for i, f in enumerate(sorted_findings) if i not in used]
    return chains, unlinked


def _generate_chain_narrative(findings: list[SequenceFinding]) -> str:
    """Generate human-readable narrative for a chain, including file details."""
    patterns = [f.pattern for f in findings]
    start = min(f.start_time for f in findings)
    end = max(f.end_time for f in findings)
    duration = (end - start).total_seconds()
    pattern_str = " -> ".join(patterns)

    if "STAGED_DROPPER" in patterns and "DROPPER_CLEANUP" in patterns:
        interp = "malware deployment with post-execution self-deletion"
    elif "MASQUERADE_RENAME" in patterns and "EXECUTABLE_IN_SUSPICIOUS_PATH" in patterns:
        interp = "binary masquerading to impersonate a legitimate Windows process"
    elif "TIMESTOMP_WITH_WRITE" in patterns and "DROPPER_CLEANUP" in patterns:
        interp = "anti-forensic malware attempting to conceal its presence and timing"
    elif "OVERWRITE_THEN_DELETE" in patterns:
        interp = "possible secure wipe — attacker attempting to destroy evidence before deletion"
    elif "RAPID_MASS_DELETION" in patterns:
        interp = "possible ransomware encryption-then-deletion cycle or aggressive attacker cleanup"
    else:
        interp = "coordinated suspicious filesystem activity requiring analyst review"

    lines = [
        f"Starting at {start.isoformat()}, a sequence of {len(findings)} suspicious activities "
        f"was detected over {duration:.0f} seconds: {pattern_str}.",
        f"This chain suggests: {interp}.",
        "",
        "Details by pattern:",
    ]
    for f in findings:
        lines.append(f"  [{f.pattern}]")
        for ev_line in f.evidence:
            lines.append(f"    {ev_line}")
    return "\n".join(lines)


def build_abnormal_sequence_pipeline(
    records: list[MFTRecord],
    usn_records: list[UsnRecord],
    path_table: dict[int, str] | None = None,
) -> tuple[list[AttackChain], list[SequenceFinding], list[str]]:
    """
    Full abnormal sequence pipeline per spec section 8.
    Returns (attack_chains, unlinked_findings, usn_gap_alerts).
    Attack chains sorted by chain_score descending.
    Unlinked findings sorted by composite_score descending.
    """
    if not usn_records:
        return [], [], []

    event_stream, events_by_ref, events_by_parent, usn_gap_alerts = build_abnormal_sequence_event_stream(
        records, usn_records, path_table
    )

    all_findings: list[SequenceFinding] = []
    all_findings.extend(_detect_dropper_cleanup(events_by_ref))
    all_findings.extend(_detect_masquerade_rename(events_by_ref))
    all_findings.extend(_detect_staged_dropper(events_by_parent))
    all_findings.extend(_detect_overwrite_then_delete(events_by_ref))
    all_findings.extend(_detect_rapid_mass_deletion(event_stream))
    all_findings.extend(_detect_executable_in_suspicious_path(event_stream))
    all_findings.extend(_detect_timestomp_with_write(events_by_ref))

    chains, unlinked = _link_attack_chains(all_findings)
    chains.sort(key=lambda c: c.chain_score, reverse=True)
    unlinked.sort(key=lambda f: f.composite_score, reverse=True)

    return chains, unlinked, usn_gap_alerts
