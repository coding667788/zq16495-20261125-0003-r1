#!/usr/bin/env python3
"""Convenience wrapper: ``python keychronicle.py audit ...``."""

from keychronicle.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
