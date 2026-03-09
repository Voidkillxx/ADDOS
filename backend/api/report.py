import io
import datetime
from flask import Blueprint, jsonify, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from backend.database.db import query

bp = Blueprint("report", __name__)


def _validate_dates(body: dict) -> tuple[str, str, str | None]:
    today = datetime.date.today()
    start_str = body.get("start_date", "")
    end_str   = body.get("end_date", "")

    try:
        start_dt = datetime.date.fromisoformat(start_str)
        end_dt   = datetime.date.fromisoformat(end_str)
    except ValueError:
        return None, None, "Invalid date format. Use YYYY-MM-DD."

    if end_dt < start_dt:
        return None, None, "End date must be >= start date."
    if end_dt > today:
        return None, None, "End date cannot be in the future."

    return start_str, end_str, None


@bp.post("/api/report")
def generate_report():
    body      = request.get_json(silent=True) or {}
    start_str, end_str, err = _validate_dates(body)
    if err:
        return jsonify({"error": err}), 400

    start_sql = f"{start_str} 00:00:00"
    end_sql   = f"{end_str} 23:59:59"

    # UNION ALL across hot and archive tables so no historical data is missed
    rows = query("""
        SELECT timestamp, src_ip, predicted_class, attack_vector,
               confidence, priority, action_taken, is_manual
        FROM mitigation_events
        WHERE timestamp >= ? AND timestamp <= ?
        UNION ALL
        SELECT timestamp, src_ip, predicted_class, attack_vector,
               confidence, priority, action_taken, is_manual
        FROM mitigation_events_archive
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC
    """, (start_sql, end_sql, start_sql, end_sql))

    if not rows:
        return jsonify({
            "error": "No data found for the selected date range. "
                     "Please choose a different range."
        }), 404

    pdf_bytes = _build_pdf(start_str, end_str, rows)
    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)

    filename = f"ddos_report_{start_str}_to_{end_str}.pdf"
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


def _build_pdf(start_str: str, end_str: str, rows: list[dict]) -> bytes:
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4,
                               leftMargin=2*cm, rightMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 fontSize=16, spaceAfter=6)
    h1_style    = ParagraphStyle("h1", parent=styles["Heading1"],
                                 fontSize=13, spaceBefore=14, spaceAfter=4)
    body_style  = styles["Normal"]

    # --- Cover ---
    story.append(Paragraph(
        f"DDoS Mitigation Report — {start_str} to {end_str}", title_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                            color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.4*cm))

    # --- Executive Summary ---
    story.append(Paragraph("1. Executive Summary", h1_style))

    total_threats = len(rows)

    # Attack vector breakdown
    vectors: dict[str, int] = {}
    for r in rows:
        v = r["attack_vector"] or "Uncertain"
        vectors[v] = vectors.get(v, 0) + 1

    # Action breakdown
    actions: dict[str, int] = {}
    for r in rows:
        a = r["action_taken"] or "—"
        actions[a] = actions.get(a, 0) + 1

    # Manual actions
    manual_release = sum(1 for r in rows if r["is_manual"] and "Release" in str(r["action_taken"]))
    manual_block   = sum(1 for r in rows if r["is_manual"] and "Block"   in str(r["action_taken"]))

    # Traffic statistics from traffic_summary for the period
    summary_rows = query("""
        SELECT SUM(total_flows_observed) AS total_flows,
               SUM(true_negatives_passed) AS true_neg,
               SUM(false_positives) AS fp
        FROM traffic_summary
        WHERE timestamp >= ? AND timestamp <= ?
    """, (f"{start_str} 00:00:00", f"{end_str} 23:59:59"))

    sr       = summary_rows[0] if summary_rows else {}
    tot_flows = sr.get("total_flows") or 0
    true_neg  = sr.get("true_neg")    or 0
    fp_count  = sr.get("fp")          or 0
    fp_rate   = (fp_count / max(tot_flows, 1)) * 100

    summary_data = [
        ["Date Range",              f"{start_str}  →  {end_str}"],
        ["Total Threats Mitigated", str(total_threats)],
        ["",                        ""],
        ["ICMP Flood",              str(vectors.get("ICMP Flood", 0))],
        ["SYN Flood",               str(vectors.get("SYN Flood",  0))],
        ["UDP Flood",               str(vectors.get("UDP Flood",  0))],
        ["Uncertain",               str(vectors.get("Uncertain",  0))],
        ["",                        ""],
        ["Quarantined",             str(actions.get("Quarantined", 0))],
        ["Rate Limited",            str(actions.get("Rate Limited", 0))],
        ["Blocked",                 str(actions.get("Blocked",     0))],
        ["",                        ""],
        ["Manual Release",          str(manual_release)],
        ["Manual Block",            str(manual_block)],
        ["",                        ""],
        ["Total Flows Observed",    str(tot_flows)],
        ["True Negatives Passed",   str(true_neg)],
        ["False Positives",         str(fp_count)],
        ["FP Rate (period)",        f"{fp_rate:.2f}%"],
    ]

    tbl = Table(summary_data, colWidths=[8*cm, 8*cm])
    tbl.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("FONTNAME",    (0, 0), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",   (0, 0), (0, -1),  colors.HexColor("#374151")),
        ("TEXTCOLOR",   (1, 0), (1, -1),  colors.HexColor("#111827")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#f9fafb"), colors.white]),
        ("LINEBELOW",   (0, -1), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.6*cm))

    # --- Chronological Log ---
    story.append(Paragraph("2. Chronological Mitigation Log", h1_style))

    log_headers = ["Timestamp", "Source IP", "Class",
                   "Vector", "Confidence", "Priority", "Action"]
    log_data    = [log_headers]
    for r in rows:
        conf_pct = f"{r['confidence']*100:.1f}%" if r["confidence"] else "—"
        log_data.append([
            r["timestamp"],
            r["src_ip"],
            r["predicted_class"],
            r["attack_vector"] or "—",
            conf_pct,
            r["priority"] or "—",
            r["action_taken"] or "—",
        ])

    col_widths = [3.8*cm, 3.2*cm, 2*cm, 2.5*cm, 2*cm, 1.8*cm, 2.2*cm]
    log_tbl = Table(log_data, colWidths=col_widths, repeatRows=1)
    log_tbl.setStyle(TableStyle([
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1a1a21")),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [colors.HexColor("#f9fafb"), colors.white]),
        ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(log_tbl)

    doc.build(story)
    return buf.getvalue()