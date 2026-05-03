"""PDF report generation using ReportLab.

The report combines the existing log counts with the security summary so the
downloaded PDF stays useful for both general analysis and incident review.
"""

from io import BytesIO
from typing import Any, Dict, Iterable, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(counts: Dict[str, int], security_report: Optional[Dict[str, Any]] = None) -> bytes:
    """Generate a PDF bytes object summarising log and security findings."""

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0d6efd"),
        spaceAfter=8,
        spaceBefore=10,
    )
    body_style = styles["BodyText"]
    body_style.leading = 14

    threat_level = (security_report or {}).get("threat_level", "Normal")
    threat_counts = (security_report or {}).get("threat_counts", {})
    suspicious_ips = (security_report or {}).get("suspicious_ips", [])
    brute_force_attacks = (security_report or {}).get("brute_force_attacks", [])
    summary = (security_report or {}).get("summary", {})

    story = [
        Paragraph("Log Analysis Report", title_style),
        Spacer(1, 0.15 * inch),
        Paragraph("Summary", heading_style),
        Paragraph(f"ERROR count: {counts.get('ERROR', 0)}", body_style),
        Paragraph(f"WARNING count: {counts.get('WARNING', 0)}", body_style),
        Paragraph(f"INFO count: {counts.get('INFO', 0)}", body_style),
        Paragraph(f"Security threat level: {threat_level}", body_style),
        Spacer(1, 0.1 * inch),
    ]

    summary_table_data = [
        ["Metric", "Value"],
        ["Total log lines", summary.get("total_lines", 0)],
        ["Failed attempts", summary.get("failed_attempts", 0)],
        ["Unique suspicious IPs", summary.get("unique_suspicious_ips", 0)],
        ["Brute force events", summary.get("brute_force_events", 0)],
        ["Critical threat lines", threat_counts.get("Critical", 0)],
    ]
    story.append(_styled_table(summary_table_data))

    story.extend([
        Spacer(1, 0.15 * inch),
        Paragraph("Threat Classification", heading_style),
        _styled_table(
            [["Level", "Count"], ["Normal", threat_counts.get("Normal", 0)], ["Suspicious", threat_counts.get("Suspicious", 0)], ["Critical", threat_counts.get("Critical", 0)]],
        ),
    ])

    story.extend([
        Spacer(1, 0.15 * inch),
        Paragraph("Suspicious IPs", heading_style),
    ])
    if suspicious_ips:
        story.append(_styled_table(_suspicious_ip_table_rows(suspicious_ips)))
    else:
        story.append(Paragraph("No suspicious IPs were detected in the current analysis.", body_style))

    story.extend([
        Spacer(1, 0.15 * inch),
        Paragraph("Attack Detections", heading_style),
    ])
    if brute_force_attacks:
        story.append(_styled_table(_brute_force_rows(brute_force_attacks)))
    else:
        story.append(Paragraph("No brute force attack patterns were detected.", body_style))

    document.build(story)
    buffer.seek(0)
    return buffer.read()


def _styled_table(rows: Iterable[Iterable[Any]]) -> Table:
    table = Table(list(rows), hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _suspicious_ip_table_rows(suspicious_ips: Iterable[Dict[str, Any]]) -> list:
    rows = [["IP Address", "Failed Attempts", "Threshold", "Message"]]
    for item in suspicious_ips:
        rows.append([
            item.get("ip", ""),
            item.get("failed_attempts", 0),
            item.get("threshold", 0),
            item.get("message", ""),
        ])
    return rows


def _brute_force_rows(brute_force_attacks: Iterable[Dict[str, Any]]) -> list:
    rows = [["IP Address", "Failures", "Window (s)", "First Seen", "Last Seen"]]
    for item in brute_force_attacks:
        rows.append([
            item.get("ip", ""),
            item.get("failed_attempts", 0),
            item.get("window_seconds", 0),
            item.get("first_seen", ""),
            item.get("last_seen", ""),
        ])
    return rows
