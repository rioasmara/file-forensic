# MFT Reader — Forensic $MFT Analysis

A Python Qt6 (PySide6) GUI application for forensic analysts to read and analyze the NTFS **Master File Table ($MFT)**. It parses $MFT files (e.g. extracted from a volume or image), displays file/directory metadata in a sortable table, and provides search, filtering, and export for timeline and artifact analysis.

## Features

- **Open $MFT file** — Load an $MFT file (e.g. copied from `\\.\C:\$MFT` or from a forensic image).
- **Record table** — Sortable columns: MFT #, Name, Parent path, Type (file/dir), Size, Created, Modified, MFT Modified, Accessed.
- **Search** — Filter by name, path, or MFT record number.
- **Record type filter** — All, Files only, Directories only, In-use only, Deleted (recycled).
- **Record details** — For the selected row: Summary (timestamps, names), Attributes list with hex, and raw header/attribute hex.
- **Export CSV** — Export all loaded records for use in timelines or other tools.
- **Copy selection** — Right-click table → Copy selected row(s) as tab-separated values.

## Requirements

- Python 3.10+
- PySide6 (Qt 6)

## Installation

```bash
cd /path/to/mft_reader
pip install -r requirements.txt
```

## Usage

From the **parent** of `mft_reader/` (e.g. your repo root):

```bash
# Optional: use a virtual environment
python3 -m venv mft_reader/.venv
mft_reader/.venv/bin/pip install -r mft_reader/requirements.txt

# Run the application
mft_reader/.venv/bin/python -m mft_reader
```

Or with system PySide6:

```bash
python -m mft_reader
```

Or from inside `mft_reader/`:

```bash
cd mft_reader
python main.py
```

Then use **Open $MFT...** to select your $MFT file. Large MFTs are loaded in the background (up to 200,000 records by default) so the UI stays responsive.

## Obtaining $MFT

- **Live Windows (admin):** Copy `\\.\C:\$MFT` to a file using a tool that can read NTFS system files (e.g. RawCopy, FTK Imager, or `dd`-style tools).
- **Forensic image:** Mount or open the image and extract the $MFT file from the root of the NTFS volume.

## License

Use and modify as needed for forensic and educational purposes.
