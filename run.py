#!/usr/bin/env python3
"""Run MFT Reader from the console: python run.py  or  python mft_reader/run.py"""

import sys
import runpy
from pathlib import Path

# Run as the mft_reader package so relative imports (e.g. ..mft_parser) work
_app_dir = Path(__file__).resolve().parent
_parent = _app_dir.parent
if str(_parent) not in sys.path:
    sys.path.insert(0, str(_parent))

if __name__ == "__main__":
    runpy.run_module("mft_reader", run_name="__main__")
