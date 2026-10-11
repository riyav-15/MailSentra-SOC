import os
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import Incident, Report
from ..security import settings
from .framework_mapper import nist_lifecycle_for_incident


def generate_incident_pdf(db: Session, incident: Incident, generated_by: int) -> Report:
    output_dir = Path(settings.report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / f"phishguard_incident_{incident.id}_{int(datetime.utcnow().timestamp())}.pdf"

    try:
        _write_reportlab_pdf(str(file_path), incident)
    except Exception:
        _write_minimal_pdf(str(file_path), incident)

    report = Report(incident_id=incident.id, file_path=str(file_path), generated_by=generated_by)
    db.add(report)
    db.flush()
    return report


def _write_reportlab_pdf(file_path: str, incident: Incident) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(file_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []

    story.append(Paragraph("PhishGuard SOC Incident Report", styles["Title"]))
    story.append(Paragraph("Defensive analysis only. No links or attachments were opened or executed.", styles["Normal"]))
    story.append(Spacer(1, 14))

    email_report = incident.email_report
    metadata = [
        ["Incident ID", str(incident.id)],
        ["Reporter", getattr(email_report.reporter, "email", "Unknown")],
        ["Subject", email_report.subject],
        ["Sender", email_report.sender],
        ["Date Reported", email_report.created_at.isoformat()],
        ["Risk Score", str(incident.risk_score)],
        ["Severity", incident.severity],
        ["Verdict", incident.verdict],
        ["Status", incident.status],
        ["Campaign", incident.campaign.name if incident.campaign else "Not correlated"],
    ]
    table = Table(metadata, colWidths=[120, 380])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Extracted Indicators", styles["Heading2"]))
    if incident.iocs:
        for ioc in incident.iocs:
            story.append(Paragraph(f"{ioc.type}: {ioc.value} ({ioc.source})", styles["Normal"]))
    else:
        story.append(Paragraph("No indicators were extracted.", styles["Normal"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Triggered Detection Rules", styles["Heading2"]))
    if incident.triggered_rules:
        for triggered in incident.triggered_rules:
            rule_name = triggered.rule.name if triggered.rule else "Rule unavailable"
            story.append(Paragraph(f"{rule_name}: +{triggered.score_added} - {triggered.evidence}", styles["Normal"]))
    else:
        story.append(Paragraph("No detection rules were triggered.", styles["Normal"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("MITRE ATT&CK and NIST Mapping", styles["Heading2"]))
    if incident.framework_mappings:
        for mapping in incident.framework_mappings:
            story.append(
                Paragraph(
                    f"{mapping.framework} | {mapping.tactic} | {mapping.technique_id} {mapping.technique_name} "
                    f"({mapping.confidence}%): {mapping.reason}",
                    styles["Normal"],
                )
            )
    else:
        story.append(Paragraph("No framework mappings were recorded.", styles["Normal"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("NIST Incident Lifecycle", styles["Heading2"]))
    for section in nist_lifecycle_for_incident(incident):
        story.append(Paragraph(f"{section['phase']}: {section['recommended_work']}", styles["Normal"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Analyst Notes", styles["Heading2"]))
    if incident.notes:
        for note in incident.notes:
            story.append(Paragraph(f"{note.created_at.isoformat()} - Analyst {note.analyst_id}: {note.note}", styles["Normal"]))
    else:
        story.append(Paragraph("No analyst notes were added.", styles["Normal"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Recommended Remediation", styles["Heading2"]))
    story.append(Paragraph(incident.recommended_action or "No remediation recorded.", styles["Normal"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Final Action Taken", styles["Heading2"]))
    story.append(Paragraph(f"Current status: {incident.status}. Verdict: {incident.verdict}.", styles["Normal"]))

    doc.build(story)


def _write_minimal_pdf(file_path: str, incident: Incident) -> None:
    lines = [
        "PhishGuard SOC Incident Report",
        f"Incident ID: {incident.id}",
        f"Subject: {incident.email_report.subject}",
        f"Sender: {incident.email_report.sender}",
        f"Risk Score: {incident.risk_score}",
        f"Severity: {incident.severity}",
        f"Verdict: {incident.verdict}",
        f"Campaign: {incident.campaign.name if incident.campaign else 'Not correlated'}",
        "Framework Mappings:",
        *[
            f"- {item.framework} {item.technique_id} {item.technique_name}: {item.reason}"
            for item in incident.framework_mappings
        ],
        "NIST Lifecycle:",
        *[
            f"- {item['phase']}: {item['recommended_work']}"
            for item in nist_lifecycle_for_incident(incident)
        ],
        "Disclaimer: Defensive analysis only.",
    ]
    escaped = "\\n".join(line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for line in lines)
    stream = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET"
    pdf = (
        "%PDF-1.4\n"
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        "3 0 obj << /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        "/MediaBox [0 0 612 792] /Contents 5 0 R >> endobj\n"
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        f"5 0 obj << /Length {len(stream)} >> stream\n{stream}\nendstream endobj\n"
        "xref\n0 6\n0000000000 65535 f \n"
        "trailer << /Root 1 0 R /Size 6 >>\nstartxref\n0\n%%EOF"
    )
    with open(file_path, "w", encoding="latin-1") as handle:
        handle.write(pdf)
