"""Statistics helpers for log analysis.

Provides small helpers to summarise counts and prepare data for charts
or reports.
"""

from typing import Dict, Tuple


def summarize_counts(counts: Dict[str, int]) -> Dict[str, float]:
    """Return a simple summary with totals and percentages.

    Returns a dict: { 'total': int, 'percent_ERROR': float, ... }
    """
    total = sum(counts.values())
    if total == 0:
        return {"total": 0, "percent_ERROR": 0.0, "percent_WARNING": 0.0, "percent_INFO": 0.0}

    return {
        "total": total,
        "percent_ERROR": (counts.get("ERROR", 0) / total) * 100.0,
        "percent_WARNING": (counts.get("WARNING", 0) / total) * 100.0,
        "percent_INFO": (counts.get("INFO", 0) / total) * 100.0,
    }


def chart_data_from_counts(counts: Dict[str, int]):
    """Return labels and data arrays suitable for Chart.js.

    Example return: (['ERROR','WARNING','INFO'], [10,5,2])
    """
    labels = ["ERROR", "WARNING", "INFO"]
    data = [counts.get(l, 0) for l in labels]
    return labels, data


def threat_chart_data_from_report(security_report: Dict[str, object]):
    """Return threat labels and data arrays suitable for Chart.js."""

    threat_counts = (security_report or {}).get("threat_counts", {})
    labels = ["Normal", "Suspicious", "Critical"]
    data = [int(threat_counts.get(label, 0)) for label in labels]
    return labels, data
