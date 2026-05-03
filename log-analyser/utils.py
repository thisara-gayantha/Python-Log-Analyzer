"""Small CLI helper to analyse a single log file from the command line.

Usage: python utils.py path/to/logfile.log
"""

import argparse
from pathlib import Path
from analyser import count_levels


def main():
    parser = argparse.ArgumentParser(description="Analyse a log file and print counts")
    parser.add_argument("file", help="Path to log file")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {path}")
        return

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        lines = fh.readlines()

    counts = count_levels(lines)
    print(counts)


if __name__ == "__main__":
    main()