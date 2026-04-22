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
from backend.database import writer

bp = Blueprint("report", __name__)


@bp.get("/api/history_dates")
def history_dates():
    """Return list of YYYY-MM-DD dates that have attack history records.
    Used by the calendar widget to disable dates with no data and future dates.
    """
    dates = writer.get_history_dates()
    return jsonify({"dates": dates})


def _validate_dates(body: dict) -> tuple[str, str, str | None]:
    today     = datetime.date.today()
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
    body                    = request.get_json(silent=True) or {}
    start_str, end_str, err = _validate_dates(body)
    if err:
        return jsonify({"error": err}), 400

    start_sql = f"{start_str} 00:00:00"
    end_sql   = f"{end_str} 23:59:59"

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
    # L16 fix: removed dead `body_style = styles["Normal"]` — assigned but
    # never referenced anywhere in this function.

    story.append(Paragraph(
        f"A-DDoS — DDoS Mitigation Report", title_style
    ))
    story.append(Paragraph(
        f"Report Period: {start_str}  →  {end_str}",
        ParagraphStyle("subtitle", parent=styles["Normal"],
                       fontSize=10, textColor=colors.HexColor("#6b7280"),
                       spaceAfter=6),
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                            color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("1. Executive Summary", h1_style))

    # Deduplicate rows so summary counts match the chronological log exactly.
    # Raw rows contain repeated detections per IP/phase — keep first (src_ip, action_taken).
    seen_for_summary: set = set()
    deduped_rows = []
    for r in rows:
        key = (r["src_ip"], r["action_taken"])
        if key not in seen_for_summary:
            seen_for_summary.add(key)
            deduped_rows.append(r)

    total_threats = len(deduped_rows)

    vectors: dict[str, int] = {}
    for r in deduped_rows:
        v = r["attack_vector"] or "Uncertain"
        vectors[v] = vectors.get(v, 0) + 1

    actions: dict[str, int] = {}
    for r in deduped_rows:
        a = r["action_taken"] or "—"
        actions[a] = actions.get(a, 0) + 1

    manual_release = sum(
        1 for r in deduped_rows if r["is_manual"] and "Release" in str(r["action_taken"])
    )
    manual_block = sum(
        1 for r in deduped_rows if r["is_manual"] and "Block" in str(r["action_taken"])
    )

    summary_rows = query("""
        SELECT SUM(total_flows_observed) AS total_flows,
               SUM(true_negatives_passed) AS true_neg,
               SUM(false_positives) AS fp
        FROM traffic_summary
        WHERE timestamp >= ? AND timestamp <= ?
    """, (f"{start_str} 00:00:00", f"{end_str} 23:59:59"))

    sr        = summary_rows[0] if summary_rows else {}
    tot_flows = sr.get("total_flows") or 0
    true_neg  = sr.get("true_neg")    or 0
    fp_count  = sr.get("fp")          or 0
    # FP rate denominator: ml_processed flows (tot_flows) not raw total.
    # H4 fix in writer.py ensures fp_count is non-zero when operators release IPs.
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
        ["Quarantined",             str(actions.get("Quarantined",  0))],
        ["Rate Limited",            str(actions.get("Rate Limited", 0))],
        ["Blocked",                 str(actions.get("Blocked",      0))],
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
        ("FONTNAME",       (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",       (0, 0), (-1, -1), 10),
        ("FONTNAME",       (0, 0), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",      (0, 0), (0, -1),  colors.HexColor("#374151")),
        ("TEXTCOLOR",      (1, 0), (1, -1),  colors.HexColor("#111827")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#f9fafb"), colors.white]),
        ("LINEBELOW",      (0, -1), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.6*cm))

    story.append(Paragraph("2. Chronological Mitigation Log", h1_style))

    # deduped_rows already computed above for summary — reuse directly.
    log_headers = ["Timestamp", "Source IP", "Class",
                   "Vector", "Confidence", "Priority", "Action"]
    log_data    = [log_headers]
    for r in deduped_rows:
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
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#1a1a21")),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [colors.HexColor("#f9fafb"), colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(log_tbl)

    # ── Section 3: IP Attack History ──────────────────────────────────────────
    history_rows = query("""
        SELECT src_ip, attack_vector, if_score, confidence, priority,
               phase_reached, first_seen, unblocked_at, duration_sec, unblock_reason
        FROM ip_attack_history
        WHERE date(unblocked_at) >= ? AND date(unblocked_at) <= ?
        ORDER BY unblocked_at DESC
    """, (start_str, end_str))

    if history_rows:
        story.append(Spacer(1, 0.6*cm))
        story.append(Paragraph("3. IP Attack History (Completed Sessions)", h1_style))

        hist_headers = ["Source IP", "Vector", "IF Score", "Conf",
                        "Phase", "Duration", "Unblocked At", "Reason"]
        hist_data = [hist_headers]
        for r in history_rows:
            dur = r["duration_sec"] or 0
            dur_str = f"{dur//60}m {dur%60}s" if dur >= 60 else f"{dur}s"
            conf_pct = f"{r['confidence']*100:.1f}%" if r["confidence"] else "—"
            hist_data.append([
                r["src_ip"],
                r["attack_vector"] or "—",
                f"{r['if_score']:.4f}",
                conf_pct,
                f"Phase {r['phase_reached']}",
                dur_str,
                r["unblocked_at"],
                r["unblock_reason"] or "—",
            ])

        hist_col_widths = [3*cm, 2.5*cm, 1.8*cm, 1.5*cm, 1.5*cm, 1.5*cm, 3.5*cm, 2.2*cm]
        hist_tbl = Table(hist_data, colWidths=hist_col_widths, repeatRows=1)
        hist_tbl.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#1a1a21")),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),
             [colors.HexColor("#f9fafb"), colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(hist_tbl)

    doc.build(story)
    return buf.getvalue()