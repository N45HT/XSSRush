#!/usr/bin/env python3

import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from cli import main

if __name__ == "__main__":
    main()
