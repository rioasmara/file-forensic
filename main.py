"""MFT Reader - Forensic $MFT analysis application."""

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

# Support both: python main.py (from mft_reader/) and python -m mft_reader (from repo root)
if __package__:
    from .gui.main_window import MFTReaderMainWindow
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from gui.main_window import MFTReaderMainWindow


def main():
    # High DPI: must be set before QApplication
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("MFT Reader")
    app.setApplicationDisplayName("MFT Reader — Forensic $MFT Analysis")
    app.setOrganizationName("Forensic Tools")
    font = QFont("Ubuntu", 10)
    app.setFont(font)
    win = MFTReaderMainWindow()
    win.showMaximized()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
