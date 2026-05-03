"""Log parsing utilities.

This module provides simple, robust log parsing functions that classify
lines into ERROR/WARNING/INFO categories. Functions are small and
well-documented for easy reuse and testing.
"""

from typing import Dict, Iterable, List, Tuple


def count_levels(lines: Iterable[str]) -> Dict[str, int]:
    """Count log level occurrences in an iterable of lines.

    - lines: Iterable of decoded text lines (strings).
    - Returns dict with keys 'ERROR', 'WARNING', 'INFO'.
    """
    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}

    for raw in lines:
        if raw is None:
            continue
        line = raw.strip()
        if not line:
            continue

        upper = line.upper()
        if "ERROR" in upper:
            counts["ERROR"] += 1
        elif "WARNING" in upper:
            counts["WARNING"] += 1
        elif "INFO" in upper:
            counts["INFO"] += 1

    return counts


def classify_lines(lines: Iterable[str]) -> List[Tuple[str, str]]:
    """Return list of (level, line) for each input line.

    Level is one of 'ERROR','WARNING','INFO' or 'OTHER'.
    """
    results: List[Tuple[str, str]] = []
    for raw in lines:
        if raw is None:
            continue
        line = raw.rstrip("\n")
        upper = line.upper()
        if "ERROR" in upper:
            results.append(("ERROR", line))
        elif "WARNING" in upper:
            results.append(("WARNING", line))
        elif "INFO" in upper:
            results.append(("INFO", line))
        else:
            results.append(("OTHER", line))
    return results
