#!/usr/bin/env python3
"""Diagnostic script: reads an $MFT file and prints detailed path resolution info."""
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mft_reader.mft_parser import (
    iter_mft_records, build_path_table, parent_path_for_record,
    detect_record_size,
)

if len(sys.argv) < 2:
    print("Usage: python diagnose_mft.py <path_to_$MFT>")
    sys.exit(1)

mft_path = Path(sys.argv[1])
if not mft_path.is_file():
    print(f"File not found: {mft_path}")
    sys.exit(1)

# 1) Detect record size
with open(mft_path, "rb") as f:
    rec_size = detect_record_size(f)
    print(f"Detected record size: {rec_size}")

    # Show raw header of first record
    f.seek(0)
    hdr = f.read(0x40)
    print(f"First 64 bytes (hex): {hdr.hex(' ', 1)}")
    print(f"  Signature bytes:     {hdr[0:4]!r}")
    print(f"  USA offset (0x04):   0x{struct.unpack_from('<H', hdr, 0x04)[0]:X}")
    print(f"  USA count  (0x06):   {struct.unpack_from('<H', hdr, 0x06)[0]}")
    print(f"  First attr (0x14):   0x{struct.unpack_from('<H', hdr, 0x14)[0]:X}")
    print(f"  Flags      (0x16):   0x{struct.unpack_from('<H', hdr, 0x16)[0]:X}")
    print(f"  Alloc size (0x1C):   {struct.unpack_from('<I', hdr, 0x1C)[0]}")
    print(f"  RecNum 0x2C (u32):   {struct.unpack_from('<I', hdr, 0x2C)[0]}")
    print()

    # Scan for FILE signatures to confirm record size
    f.seek(0)
    buf = f.read(16384)
    file_offsets = []
    for off in range(0, len(buf) - 4, 512):
        if buf[off:off+4] == b"FILE":
            file_offsets.append(off)
    print(f"FILE signatures found at offsets: {file_offsets[:10]}")
    if len(file_offsets) >= 2:
        gaps = [file_offsets[i+1] - file_offsets[i] for i in range(min(5, len(file_offsets)-1))]
        print(f"  Gaps between consecutive FILEs: {gaps}")
    print()

# 2) Load first 30 records and inspect
print("=" * 70)
print("FIRST 30 RECORDS")
print("=" * 70)
records = list(iter_mft_records(mft_path, max_records=30))
for rec in records:
    fn = rec.primary_file_name()
    fn_info = f"name='{fn.name}' parent_ref={fn.parent_ref} ns={fn.namespace}" if fn else "NO FILE_NAME"
    names_count = len(rec.file_names)
    print(f"  Rec#{rec.record_number:>6}  sig={rec.signature!r:>8}  "
          f"in_use={rec.in_use!s:<5}  dir={rec.is_directory!s:<5}  "
          f"fnames={names_count}  {fn_info}"
          + (f"  ERR={rec.parse_error}" if rec.parse_error else ""))

# 3) Load all records and build path table
print()
print("=" * 70)
print("LOADING ALL RECORDS...")
print("=" * 70)
all_records = list(iter_mft_records(mft_path, max_records=None))
print(f"Total records loaded: {len(all_records)}")
valid = sum(1 for r in all_records if not r.parse_error)
with_names = sum(1 for r in all_records if r.file_names)
print(f"Valid (FILE signature): {valid}")
print(f"With file_names:        {with_names}")

# Check for duplicate record numbers
from collections import Counter
num_counts = Counter(r.record_number for r in all_records)
dupes = {n: c for n, c in num_counts.items() if c > 1}
if dupes:
    print(f"WARNING: {len(dupes)} duplicate record numbers! First 10: {dict(list(dupes.items())[:10])}")
else:
    print("No duplicate record numbers (good)")

path_table = build_path_table(all_records)
print(f"Path table entries: {len(path_table)}")
resolved = sum(1 for v in path_table.values() if v and v != "\\")
print(f"Paths resolved (non-root): {resolved}")
root_count = sum(1 for v in path_table.values() if v == "\\")
print(f"Paths = root ('\\'):        {root_count}")

# 4) Show path table entries for first 30 records
print()
print("=" * 70)
print("PATH TABLE FOR FIRST 30 RECORDS")
print("=" * 70)
for rec in records:
    full_path = path_table.get(rec.record_number, "(NOT IN TABLE)")
    parent_path = parent_path_for_record(rec, path_table)
    fn = rec.primary_file_name()
    parent_ref = fn.parent_ref if fn else "N/A"
    parent_in_table = path_table.get(parent_ref, "(NOT FOUND)") if fn else "N/A"
    print(f"  Rec#{rec.record_number:>6}  name={rec.primary_name():<30}  "
          f"parent_ref={str(parent_ref):>8}  "
          f"parent_in_table={parent_in_table:<30}  "
          f"parent_path={parent_path}")

# 5) Show some directory records and their paths
print()
print("=" * 70)
print("SAMPLE DIRECTORY RECORDS WITH PATHS")
print("=" * 70)
dirs_shown = 0
for rec in all_records:
    if rec.is_directory and rec.file_names and not rec.parse_error:
        fn = rec.primary_file_name()
        full = path_table.get(rec.record_number, "(NOT IN TABLE)")
        if full != "\\":
            print(f"  Rec#{rec.record_number:>6}  name={rec.primary_name():<30}  "
                  f"parent_ref={fn.parent_ref:>8}  full_path={full}")
            dirs_shown += 1
            if dirs_shown >= 20:
                break
if dirs_shown == 0:
    print("  NO directory records with non-root paths found!")
    print("  Showing first 10 directory records:")
    dirs_shown2 = 0
    for rec in all_records:
        if rec.is_directory and rec.file_names:
            fn = rec.primary_file_name()
            full = path_table.get(rec.record_number, "(NOT IN TABLE)")
            parent_full = path_table.get(fn.parent_ref, "(NOT FOUND)")
            print(f"  Rec#{rec.record_number:>6}  name={rec.primary_name():<30}  "
                  f"parent_ref={fn.parent_ref:>8}  "
                  f"full_path={full}  parent_ref_path={parent_full}")
            dirs_shown2 += 1
            if dirs_shown2 >= 10:
                break
