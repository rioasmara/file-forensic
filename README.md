# MFT Reader — Forensic $MFT Analysis

A Python Qt6 (PySide6) GUI application for digital forensic analysts to read and analyze the NTFS **Master File Table ($MFT)** and **USN Change Journal ($J)**. Designed for incident response, triage, timeline reconstruction, and artifact analysis on Windows NTFS volumes.

---

## Overview

MFT Reader parses raw $MFT files (extracted from a live volume or forensic image) and optionally the USN Journal to extract file metadata, timestamps, and filesystem activity. It provides a rich set of precomputed anomaly reports to surface suspicious patterns—timestomping, extension changes, directory churn, temporal bursts, and more—without requiring process context (no PIDs, command lines, or parent-child relationships).

**Core principle:** All detection is based purely on what happened to files on disk: when they were created, written, renamed, overwritten, and deleted. USN (Update Sequence Number) is used as the primary ordering key where available, as it is a kernel-managed monotonic counter that cannot be altered from userspace.

---

## Features

### Data Sources

| Source | Description |
|--------|--------------|
| **$MFT** | Master File Table — every file and directory record with timestamps, names, sizes, flags |
| **$J** (optional) | USN Change Journal — log of creates, deletes, renames, data writes; enables richer analysis |

### Main Tabs

| Tab | Description |
|-----|-------------|
| **MFT** | Sortable table of all file records with compound filters, time anchor, and risk highlighting |
| **USN Journal** | Change journal events (Timestamp, USN, MFT #, Filename, Parent path, Reason) with filter copy from MFT |
| **File System Tree** | Reconstructed directory tree with lazy loading; forensic hints (Timestomp?, High seq?, Suspicious path?, Executable?) |
| **Analysis** | Precomputed forensic reports (see below) |
| **Kill Chain** | Map files to Lockheed Martin Cyber Kill Chain phases for attack-lifecycle analysis |

### Analysis Reports

| Report | Description | Requires $J |
|--------|-------------|------------|
| **Anomaly sequences** | Suspicious event sequences (time range, path, payload, persistence artifact, pattern, score) | Yes |
| **Extension change** | Renames where extension changed (e.g. .txt→.exe, .doc→.exe) — disguised executables | Yes |
| **Filename entropy** | High Shannon entropy filenames (random/machine-generated names) | No |
| **Extension entropy per directory** | Extension diversity per folder — unusual diversity may warrant investigation | No |
| **Directory churn** | Directories with many files created in a short window (dropper, payload extraction) | No |
| **Temporal burst** | Unusual file-creation spikes (Poisson) and burstiness by directory | No |
| **Survival metrics** | Deleted files and time-to-delete; histogram of short-lived files | Yes |
| **Sequence gap** | High sequence numbers (reused MFT slots — deleted-file graveyard) | No |

### Filtering & Search

- **Compound filters** — Drag column headers into the filter panel; criteria are ANDed. Operators: contains, equals, starts with, ends with, glob (* ?) for text; equals, not equals, &lt;, &gt;, &lt;=, &gt;= for numbers.
- **Time anchor** — Restrict records to a time window (e.g. ±300 seconds around an anchor timestamp).
- **Copy filters** — Replicate MFT filters to USN Journal tab and vice versa.

### Risk Highlighting

Rows are highlighted by risk level (Critical / High / Medium) based on:

- Timestomping (SI vs FN timestamp disagreement)
- Executables in suspicious paths (Temp, Public, $Recycle.Bin, Startup, Tasks)
- High sequence numbers (reused slots)

### Session & Export

- **Save session** — Persist $MFT/$J paths, filters, time anchor, and column visibility to a `.mftsession` file.
- **Load session** — Resume an investigation without re-opening dialogs.
- **Export CSV** — Export currently visible/filtered MFT rows for timelines or other tools.

---

## Requirements

- Python 3.10+
- PySide6 (Qt 6) ≥ 6.6.0

---

## Installation

```bash
cd /path/to/mft_reader
pip install -r requirements.txt
```

Or with a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

---

## Usage

### Run the application

From the project directory:

```bash
python -m mft_reader
```

Or:

```bash
python main.py
```

With virtual environment:

```bash
.venv/bin/python -m mft_reader
```

### Typical workflow

1. **Open $MFT** — File → Open $MFT... (Ctrl+O) and select your $MFT file.
2. **Open $J (optional)** — File → Open $J (USN Journal)... to load the change journal for the same volume.
3. **Browse & filter** — Use the MFT tab to browse and filter; apply compound filters or time anchor.
4. **Run analysis** — Switch to the Analysis tab; click **Refresh** or **Refresh (compute in background)** to generate reports.
5. **Save session** — File → Save session... (Ctrl+S) to persist state for later.
6. **Export** — File → Export CSV... to export filtered results.

Large MFTs are loaded in the background (up to 200,000 records by default) so the UI stays responsive.

---

## Obtaining $MFT and $J

### Live Windows (administrator)

- **$MFT:** Copy `\\.\C:\$MFT` to a file using a tool that can read NTFS system files (e.g. RawCopy, FTK Imager, or `dd`-style tools).
- **$J:** Copy `\\.\C:\$Extend\$UsnJrnl:$J` to a file (same tools).

### Forensic image

- Mount or open the image and extract the $MFT file from the root of the NTFS volume.
- Extract the USN Journal from `$Extend\$UsnJrnl:$J` if available.

---

## Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+O | Open $MFT |
| Ctrl+S | Save session |
| Ctrl+L | Load session |
| Ctrl+Q | Exit |
| F1 | Application Help |

---

## Project structure

```
mft_reader/
├── main.py           # Entry point
├── __main__.py       # Package entry
├── run.py            # Alternative run script
├── mft_parser.py     # MFT parser, USN parser, anomaly detection
├── gui/
│   ├── main_window.py    # Main application window
│   ├── compound_filter.py # Filter panel
│   └── session_db.py     # Session persistence
├── requirements.txt
└── README.md
```

---

## License

MIT License - use and modify as needed for forensic and educational purposes. See [LICENSE](LICENSE) for details.
