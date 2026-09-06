"""
==================================================
NetShield-NIDS — Security Report Generator
==================================================
backend/report_generator.py

Generates Security Investigation Reports in PDF, CSV, and JSON formats
using real data from the NetShield database (alerts, sensors, traffic).
"""
import os
import csv
import io
import json
import hashlib
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from backend.database import get_db_session
from backend.models import Alert, Sensor, TrafficMetric

logger = logging.getLogger("netshield.report")

# Data directory for reports (persistent via Docker volume ./data)
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# ─── Data Collection ────────────────────────────────────────────────
def _parse_dt(value: Any) -> Optional[datetime]:
    """Safely parse a datetime from various input formats."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            if value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            return datetime.fromisoformat(value)
        except Exception:
            return None
    return None


def fetch_report_data(
    start_time: datetime,
    end_time: datetime,
    sensor_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch real alerts, sensors, and traffic metrics for a time window."""
    with get_db_session() as db:
        q = db.query(Alert).filter(Alert.timestamp >= start_time, Alert.timestamp <= end_time)
        if sensor_id:
            q = q.filter(Alert.sensor_id == sensor_id)
        alerts = q.order_by(Alert.timestamp.asc()).all()
        alert_dicts = [a.to_dict() for a in alerts]

        sq = db.query(Sensor)
        if sensor_id:
            sq = sq.filter(Sensor.sensor_id == sensor_id)
        sensors = [s.to_dict() for s in sq.all()]

        tq = db.query(TrafficMetric).filter(
            TrafficMetric.timestamp >= start_time,
            TrafficMetric.timestamp <= end_time
        )
        if sensor_id:
            tq = tq.filter(TrafficMetric.sensor_id == sensor_id)
        traffic = [t.to_dict() for t in tq.order_by(TrafficMetric.timestamp.asc()).all()]

    attack_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    protocol_counts: Counter = Counter()
    src_ip_counts: Counter = Counter()
    dst_ip_counts: Counter = Counter()
    port_counts: Counter = Counter()

    for a in alert_dicts:
        attack_counts[a.get("attack_type", "Unknown")] += 1
        severity_counts[a.get("severity", "LOW")] += 1
        protocol_counts[a.get("protocol", "Other")] += 1
        if a.get("source_ip"):
            src_ip_counts[a["source_ip"]] += 1
        if a.get("destination_ip"):
            dst_ip_counts[a["destination_ip"]] += 1
        if a.get("destination_port"):
            port_counts[str(a["destination_port"])] += 1

    total_packets = sum(int(t.get("packets") or 0) for t in traffic)
    total_classified = sum(int(t.get("classified_flows") or 0) for t in traffic)
    total_normal = sum(int(t.get("normal_count") or 0) for t in traffic)
    total_threat = sum(int(t.get("threat_count") or 0) for t in traffic)
    total_review = sum(int(t.get("review_count") or 0) for t in traffic)
    total_uncertain = sum(int(t.get("uncertain_count") or 0) for t in traffic)

    first_ts = alert_dicts[0]["timestamp"] if alert_dicts else ""
    last_ts = alert_dicts[-1]["timestamp"] if alert_dicts else ""
    most_significant = (
        max(alert_dicts, key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x.get("severity", "LOW"), 0)) if alert_dicts else None
    )

    return {
        "window": {
            "start": start_time.isoformat(),
            "end": end_time.isoformat(),
            "sensor_id": sensor_id or "all",
        },
        "generated_at": datetime.utcnow().isoformat(),
        "alerts": alert_dicts,
        "sensors": sensors,
        "traffic": traffic,
        "summary": {
            "total_incidents": len(alert_dicts),
            "packets_observed": total_packets,
            "classified_flows": total_classified,
            "normal_count": total_normal,
            "threat_count": total_threat,
            "review_count": total_review,
            "uncertain_count": total_uncertain,
            "first_incident": first_ts,
            "last_incident": last_ts,
            "most_significant_threat": most_significant,
        },
        "analysis": {
            "attack_distribution": dict(attack_counts),
            "severity_distribution": dict(severity_counts),
            "protocol_distribution": dict(protocol_counts),
            "top_source_ips": dict(src_ip_counts.most_common(10)),
            "top_destinations": dict(dst_ip_counts.most_common(10)),
            "top_ports": dict(port_counts.most_common(10)),
        },
    }


# ─── JSON Generation ────────────────────────────────────────────────
def generate_json_report(data: Dict[str, Any], file_path: str) -> Tuple[int, str]:
    """Write JSON report. Returns (size_bytes, sha256_hex)."""
    payload = json.dumps(data, indent=2, default=str).encode("utf-8")
    with open(file_path, "wb") as f:
        f.write(payload)
    return len(payload), hashlib.sha256(payload).hexdigest()


# ─── CSV Generation ─────────────────────────────────────────────────
def generate_csv_report(data: Dict[str, Any], file_path: str) -> Tuple[int, str]:
    """Write CSV with one row per incident alert."""
    alerts = data.get("alerts", [])
    fieldnames = [
        "incident_id", "timestamp", "sensor_id", "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol", "attack_type",
        "confidence", "severity", "status", "explanation"
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for idx, a in enumerate(alerts, start=1):
        row = {k: a.get(k, "") for k in fieldnames}
        row["incident_id"] = f"NIDS-{idx:04d}"
        writer.writerow(row)
    payload = buf.getvalue().encode("utf-8")
    with open(file_path, "wb") as f:
        f.write(payload)
    return len(payload), hashlib.sha256(payload).hexdigest()


# ─── PDF Generation ─────────────────────────────────────────────────
def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _wrap_text(text: str, width: int) -> List[str]:
    """Simple word-wrap for reportlab unavailable environments."""
    words = text.split()
    lines: List[str] = []
    current = ""
    for w in words:
        if not current:
            current = w
        elif len(current) + 1 + len(w) <= width:
            current += " " + w
        else:
            lines.append(current)
            current = w
    if current:
        lines.append(current)
    return lines


def generate_pdf_report(data: Dict[str, Any], file_path: str) -> Tuple[int, str]:
    """Generate a PDF Security Investigation Report using reportlab.

    Returns (file_size_bytes, sha256_hex).
    """
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleX", parent=styles["Title"], fontSize=20,
        textColor=colors.HexColor("#0F172A"), spaceAfter=14
    )
    h2 = ParagraphStyle(
        "H2X", parent=styles["Heading2"], fontSize=14,
        textColor=colors.HexColor("#0EA5E9"), spaceBefore=14, spaceAfter=8
    )
    body = ParagraphStyle(
        "BodyX", parent=styles["BodyText"], fontSize=10,
        textColor=colors.HexColor("#0F172A"), leading=13
    )
    small = ParagraphStyle(
        "SmallX", parent=styles["BodyText"], fontSize=8,
        textColor=colors.HexColor("#475569"), leading=10
    )

    doc = SimpleDocTemplate(
        file_path, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        title="NetShield Security Investigation Report"
    )
    story: List[Any] = []

    summary = data.get("summary", {})
    analysis = data.get("analysis", {})
    sensors = data.get("sensors", [])
    alerts = data.get("alerts", [])
    window = data.get("window", {})

    report_id = data.get("report_id", "NIDS-RPT-UNKNOWN")
    generated_at = data.get("generated_at", datetime.utcnow().isoformat())

    # ── Title ────────────────────────────────────────────────────────
    story.append(Paragraph("NetShield-NIDS Security Investigation Report", title_style))
    story.append(Paragraph(
        f"<b>Report ID:</b> {_safe_str(report_id)}<br/>"
        f"<b>Generated:</b> {_safe_str(generated_at)}<br/>"
        f"<b>Sensor Scope:</b> {_safe_str(window.get('sensor_id', 'all'))}<br/>"
        f"<b>Monitoring Period:</b> {_safe_str(window.get('start'))} → {_safe_str(window.get('end'))}",
        body
    ))
    story.append(Spacer(1, 0.15 * inch))

    # ── Executive Summary ───────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2))
    if not alerts:
        story.append(Paragraph(
            "No security incidents were recorded during the selected monitoring period. "
            "All monitored network flows were classified as benign or no alerts were raised "
            "by the NetShield ML detection engine.", body
        ))
    else:
        most = summary.get("most_significant_threat") or {}
        story.append(Paragraph(
            f"During the monitoring period, the NetShield NIDS observed "
            f"<b>{summary.get('packets_observed', 0):,}</b> packets across "
            f"<b>{summary.get('classified_flows', 0):,}</b> classified flow records, "
            f"identifying <b>{summary.get('total_incidents', 0):,}</b> confirmed security "
            f"incidents. The most significant threat was "
            f"<b>{_safe_str(most.get('attack_type', 'N/A'))}</b> "
            f"from <b>{_safe_str(most.get('source_ip', 'N/A'))}</b> at "
            f"<b>{_safe_str(most.get('timestamp', 'N/A'))}</b> "
            f"with <b>{_safe_str(most.get('severity', 'N/A'))}</b> severity.", body
        ))

    # Summary table
    summary_rows = [
        ["Metric", "Value"],
        ["Total Incidents", f"{summary.get('total_incidents', 0):,}"],
        ["Packets Observed", f"{summary.get('packets_observed', 0):,}"],
        ["Classified Flows", f"{summary.get('classified_flows', 0):,}"],
        ["Normal", f"{summary.get('normal_count', 0):,}"],
        ["Threats", f"{summary.get('threat_count', 0):,}"],
        ["Review", f"{summary.get('review_count', 0):,}"],
        ["Uncertain", f"{summary.get('uncertain_count', 0):,}"],
        ["First Incident", _safe_str(summary.get('first_incident', 'N/A'))],
        ["Last Incident", _safe_str(summary.get('last_incident', 'N/A'))],
    ]
    t = Table(summary_rows, colWidths=[2.2 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0EA5E9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.2 * inch))

    # ── Threat Analysis ─────────────────────────────────────────────
    story.append(Paragraph("Threat Analysis", h2))

    def _two_col_table(d: Dict[str, Any], label: str) -> None:
        if not d:
            story.append(Paragraph(f"No data available for {label}.", body))
            return
        rows = [[label, "Count"]]
        for k, v in sorted(d.items(), key=lambda x: -x[1]):
            rows.append([_safe_str(k), str(v)])
        tbl = Table(rows, colWidths=[4.5 * inch, 1.5 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 0.12 * inch))

    story.append(Paragraph("<b>Attack Distribution</b>", body))
    _two_col_table(analysis.get("attack_distribution", {}), "Attack Type")
    story.append(Paragraph("<b>Severity Distribution</b>", body))
    _two_col_table(analysis.get("severity_distribution", {}), "Severity")
    story.append(Paragraph("<b>Top Source IPs</b>", body))
    _two_col_table(analysis.get("top_source_ips", {}), "Source IP")
    story.append(Paragraph("<b>Top Destinations</b>", body))
    _two_col_table(analysis.get("top_destinations", {}), "Destination IP")
    story.append(Paragraph("<b>Top Destination Ports</b>", body))
    _two_col_table(analysis.get("top_ports", {}), "Port")

    # ── Incident Timeline ───────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Incident Timeline", h2))
    if not alerts:
        story.append(Paragraph("No incidents to display.", body))
    else:
        rows = [["Timestamp", "Attack", "Source → Dest", "Proto", "Sev", "Conf"]]
        for a in alerts[:100]:
            rows.append([
                _safe_str(a.get("timestamp", ""))[:19],
                _safe_str(a.get("attack_type", "")),
                f"{_safe_str(a.get('source_ip', ''))} → {_safe_str(a.get('destination_ip', ''))}",
                _safe_str(a.get("protocol", "")),
                _safe_str(a.get("severity", "")),
                _safe_str(a.get("confidence", "")),
            ])
        tbl = Table(rows, colWidths=[1.4*inch, 1.2*inch, 1.9*inch, 0.55*inch, 0.7*inch, 0.7*inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0EA5E9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        story.append(tbl)
        if len(alerts) > 100:
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph(f"<i>Showing first 100 of {len(alerts):,} incidents. Full list in CSV/JSON export.</i>", small))

    # ── Sensor Information ──────────────────────────────────────────
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Sensor Information", h2))
    if not sensors:
        story.append(Paragraph("No registered sensors for this period.", body))
    else:
        srows = [["Sensor ID", "Hostname", "Platform", "Status", "First Seen", "Last Seen", "Threats"]]
        for s in sensors:
            srows.append([
                _safe_str(s.get("sensor_id", "")),
                _safe_str(s.get("hostname", "")),
                _safe_str(s.get("platform", "")),
                _safe_str(s.get("status", "")),
                _safe_str(s.get("first_seen", ""))[:19],
                _safe_str(s.get("last_seen", ""))[:19],
                str(s.get("threat_count", 0)),
            ])
        stbl = Table(srows, colWidths=[0.9*inch, 1.0*inch, 0.9*inch, 0.7*inch, 1.2*inch, 1.2*inch, 0.6*inch])
        stbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        story.append(stbl)

    # ── Evidence Integrity ──────────────────────────────────────────
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph("Evidence Integrity", h2))
    story.append(Paragraph(
        f"Report ID: <b>{_safe_str(report_id)}</b><br/>"
        f"Generated At (UTC): <b>{_safe_str(generated_at)}</b><br/>"
        f"Incident Count: <b>{summary.get('total_incidents', 0):,}</b><br/>"
        f"SHA-256 (over exported report file): <font face=\"Courier\" size=\"8\">{_safe_str(data.get('sha256', ''))}</font><br/>"
        f"<i>The hash above is computed over the bytes of the final exported report file. It can be used to detect later modification. "
        f"NetShield does not claim legal admissibility of this artifact.</i>", body
    ))

    doc.build(story)

    size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    return size, sha
