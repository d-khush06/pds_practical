#!/usr/bin/env python3
"""
Practical 10 CLI entry point: Reusable Automated Log Processing Pipeline
Delegates execution to scripts/practical_10_reusable_pipeline.py
"""
import sys
import os

# Add scripts directory to path
scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from practical_10_reusable_pipeline import main

if __name__ == "__main__":
    main()
