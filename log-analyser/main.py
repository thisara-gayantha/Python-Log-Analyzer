
"""Small example CLI to show top error messages from a log file."""

from collections import Counter
from pathlib import Path
import argparse


def analyse_log(file_path: str, top_n: int = 5):
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {file_path}")
        return

    error_messages = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if "ERROR" in line:
                error_messages.append(line.strip())

    counter = Counter(error_messages)
    print("Top Errors:")
    for error, count in counter.most_common(top_n):
        print(f"{count}x - {error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to log file")
    parser.add_argument("--top", type=int, default=5, help="Top N errors to show")
    args = parser.parse_args()
    analyse_log(args.file, args.top)



