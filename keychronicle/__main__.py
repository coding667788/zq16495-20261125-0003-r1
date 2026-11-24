from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    # Supports both ``python -m keychronicle`` and ``python keychronicle``.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from keychronicle.cli import main
else:
    from .cli import main

raise SystemExit(main())
