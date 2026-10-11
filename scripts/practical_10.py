#!/usr/bin/env python3
"""
Practical 10 CLI entry point (inside scripts directory):
Delegates execution to practical_10_reusable_pipeline.py
"""
import sys
import os

scripts_dir = os.path.dirname(os.path.abspath(__file__))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from practical_10_reusable_pipeline import main

if __name__ == "__main__":
    main()
