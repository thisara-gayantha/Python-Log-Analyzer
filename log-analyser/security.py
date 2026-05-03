"""Security-focused log analysis helpers.

This module detects suspicious IP activity, repeated authentication failures,
and brute-force-style bursts. The helpers are intentionally stateful-friendly so
the same logic can be reused for batch uploads and real-time monitoring.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

FAILURE_KEYWORDS = (
    "failed login",
    "authentication failed",
    "login failed",
    "invalid password",
    "invalid credentials",
    "access denied",
    "permission denied",
)

ISO_TIMESTAMP_REGEX = re.compile(
    r"\b(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)
SYSLOG_TIMESTAMP_REGEX = re.compile(
    r"\b(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
)


@dataclass
class SecurityConfig:
    """Configuration for security detection thresholds."""

    failed_attempt_threshold: int = 5
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60
    critical_error_threshold: int = 10


@dataclass
class SecurityTracker:
    """Incrementally track security signals across log lines."""

    config: SecurityConfig = field(default_factory=SecurityConfig)
    failed_attempts: Counter = field(default_factory=Counter)
    failed_windows: Dict[str, Deque[datetime]] = field(default_factory=lambda: defaultdict(deque))
    suspicious_ips: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    brute_force_attacks: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    threat_counts: Counter = field(default_factory=Counter)
    total_lines: int = 0
    error_lines: int = 0
    suspicious_event_lines: int = 0
    critical_event_lines: int = 0

    def ingest(self, line: str) -> List[Dict[str, Any]]:
        """Process one log line and return any newly generated alerts."""

        self.total_lines += 1
        text = (line or "").strip()
        if not text:
            self.threat_counts["Normal"] += 1
            return []

        upper = text.upper()
        lower = text.lower()
        new_alerts: List[Dict[str, Any]] = []
        severity = "Normal"

        if "ERROR" in upper:
            self.error_lines += 1

        is_failure = any(keyword in lower for keyword in FAILURE_KEYWORDS)
        ips = extract_ip_addresses(text)
        timestamp = extract_timestamp(text)

        if is_failure:
            self.suspicious_event_lines += 1
            severity = "Suspicious"

        if ips and is_failure:
            for ip in ips:
                self.failed_attempts[ip] += 1
                count = self.failed_attempts[ip]
                if count >= self.config.failed_attempt_threshold:
                    alert = self.suspicious_ips.get(ip)
                    if alert is None:
                        alert = {
                            "type": "suspicious_ip",
                            "severity": "Suspicious",
                            "ip": ip,
                            "failed_attempts": count,
                            "threshold": self.config.failed_attempt_threshold,
                            "message": f"Suspicious IP {ip} exceeded failed login threshold.",
                        }
                        self.suspicious_ips[ip] = alert
                        self._append_alert(alert)
                        new_alerts.append(alert)
                    else:
                        alert["failed_attempts"] = count

                if timestamp is not None:
                    window = self.failed_windows[ip]
                    window.append(timestamp)
                    cutoff = timestamp - timedelta(seconds=self.config.brute_force_window_seconds)
                    while window and window[0] < cutoff:
                        window.popleft()

                    if len(window) >= self.config.brute_force_threshold:
                        key = f"{ip}:{window[0].isoformat()}:{window[-1].isoformat()}:{len(window)}"
                        if key not in self.brute_force_attacks:
                            alert = {
                                "type": "brute_force_attack",
                                "severity": "Critical",
                                "ip": ip,
                                "failed_attempts": len(window),
                                "window_seconds": self.config.brute_force_window_seconds,
                                "first_seen": window[0].isoformat(),
                                "last_seen": window[-1].isoformat(),
                                "message": f"Brute force attack detected from {ip}.",
                            }
                            self.brute_force_attacks[key] = alert
                            self.critical_event_lines += 1
                            self._append_alert(alert)
                            new_alerts.append(alert)
                            severity = "Critical"

        if self.error_lines >= self.config.critical_error_threshold:
            severity = "Critical"

        if severity == "Critical":
            self.critical_event_lines += 1

        self.threat_counts[severity] += 1
        return new_alerts

    def snapshot(self) -> Dict[str, Any]:
        """Return a serialisable security summary for dashboards and reports."""

        threat_level = self._overall_threat_level()
        return {
            "threat_level": threat_level,
            "threat_counts": {
                "Normal": self.threat_counts.get("Normal", 0),
                "Suspicious": self.threat_counts.get("Suspicious", 0),
                "Critical": self.threat_counts.get("Critical", 0),
            },
            "suspicious_ips": sorted(
                self.suspicious_ips.values(),
                key=lambda item: (-item.get("failed_attempts", 0), item.get("ip", "")),
            ),
            "brute_force_attacks": list(self.brute_force_attacks.values()),
            "alerts": list(self.alerts),
            "summary": {
                "total_lines": self.total_lines,
                "failed_attempts": sum(self.failed_attempts.values()),
                "unique_suspicious_ips": len(self.suspicious_ips),
                "brute_force_events": len(self.brute_force_attacks),
                "error_lines": self.error_lines,
            },
        }

    def _append_alert(self, alert: Dict[str, Any]) -> None:
        self.alerts.append(alert)

    def _overall_threat_level(self) -> str:
        if self.brute_force_attacks or self.error_lines >= self.config.critical_error_threshold:
            return "Critical"
        if self.suspicious_ips or self.suspicious_event_lines:
            return "Suspicious"
        return "Normal"


def extract_ip_addresses(line: str) -> List[str]:
    """Extract IPv4 addresses from a log line using regex."""

    return IP_REGEX.findall(line or "")


def extract_timestamp(line: str) -> Optional[datetime]:
    """Extract a timestamp from a log line when one is present.

    Supports ISO-8601 timestamps and common syslog timestamps. When a syslog
    timestamp lacks a year, the current year is assumed.
    """

    text = line or ""

    match = ISO_TIMESTAMP_REGEX.search(text)
    if match:
        value = match.group("ts").replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    match = SYSLOG_TIMESTAMP_REGEX.search(text)
    if match:
        value = match.group("ts")
        try:
            parsed = datetime.strptime(value, "%b %d %H:%M:%S")
            return parsed.replace(year=datetime.now().year)
        except ValueError:
            return None

    return None


def is_failed_authentication(line: str) -> bool:
    """Return True when the line looks like a failed authentication event."""

    lower = (line or "").lower()
    return any(keyword in lower for keyword in FAILURE_KEYWORDS)


def analyze_security_lines(lines: Iterable[str], config: Optional[SecurityConfig] = None) -> Dict[str, Any]:
    """Analyze an iterable of log lines and return a structured security report."""

    tracker = SecurityTracker(config=config or SecurityConfig())
    for line in lines:
        tracker.ingest(line)
    return tracker.snapshot()


def security_chart_data(security_report: Optional[Dict[str, Any]]) -> Tuple[List[str], List[int]]:
    """Prepare threat classification data for Chart.js."""

    threat_counts = (security_report or {}).get("threat_counts", {})
    labels = ["Normal", "Suspicious", "Critical"]
    data = [int(threat_counts.get(label, 0)) for label in labels]
    return labels, data