from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import DetectionRule, EmailReport, IOC, Incident, Report, TriggeredRule, User
from ..schemas import EmailReportPublic
from ..services.audit_logger import log_action
from ..services.risk_engine import analyze_raw_email

router = APIRouter(prefix="/reports", tags=["Email Reports"])


@router.post("/submit", status_code=status.HTTP_201_CREATED)
async def submit_report(
    subject: str = Form(...),
    sender: str = Form(...),
    report_reason: str = Form(...),
    raw_email_text: str | None = Form(None),
    eml_file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    uploaded_file_name = None
    uploaded_text = ""
    if eml_file:
        uploaded_file_name = eml_file.filename
        content = await eml_file.read()
        lower_name = (uploaded_file_name or "").lower()
        if lower_name.endswith((".eml", ".txt", ".msg")):
            uploaded_text = content.decode("utf-8", errors="ignore")
        elif lower_name.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
            # Image or QR code sample uploaded for quishing triage
            uploaded_text = (raw_email_text or "").strip()
            if not uploaded_text:
                uploaded_text = (
                    f"Subject: {subject}\n"
                    f"From: {sender}\n"
                    f"Attachment: {uploaded_file_name}\n\n"
                    f"Scan the QR code in the attached image sample ({uploaded_file_name}) to authenticate."
                )
        else:
            # Fallback to UTF-8 decoding if possible
            uploaded_text = content.decode("utf-8", errors="ignore")

    final_raw_text = (raw_email_text or uploaded_text or "").strip()
    if not final_raw_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Paste email text or upload a valid file")

    rules = db.query(DetectionRule).all()
    disabled_rules = {rule.name for rule in rules if not rule.enabled}
    rule_weights = {rule.name: rule.severity_weight for rule in rules}
    analysis = analyze_raw_email(final_raw_text, disabled_rules=disabled_rules, rule_weights=rule_weights)
    parsed = analysis["parsed_email"]
    risk = analysis["risk"]

    email_report = EmailReport(
        reporter_id=current_user.id,
        subject=subject,
        sender=sender,
        raw_email_text=final_raw_text,
        uploaded_file_name=uploaded_file_name,
        report_reason=report_reason,
    )
    db.add(email_report)
    db.flush()

    incident = Incident(
        title=subject or parsed.get("subject") or "Suspicious email report",
        email_report_id=email_report.id,
        status="New",
        severity=risk["severity"],
        verdict=risk["verdict_suggestion"],
        risk_score=risk["score"],
        recommended_action=risk["recommended_action"],
    )
    db.add(incident)
    db.flush()

    _store_iocs(db, incident.id, parsed)
    _store_triggered_rules(db, incident.id, risk["triggered_rules"])
    log_action(db, current_user.id, "report_submitted", f"Submitted email report {email_report.id}")
    db.commit()

    return {
        "report": EmailReportPublic.model_validate(email_report),
        "incident_id": incident.id,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "verdict_suggestion": incident.verdict,
        "triggered_rules": risk["triggered_rules"],
        "recommended_action": incident.recommended_action,
        "subscores": risk.get("subscores", {}),
        "summary": risk.get("summary", ""),
        "confidence_percentage": risk.get("confidence_percentage", 80),
    }


@router.get("/my")
def my_reports(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    reports = (
        db.query(EmailReport)
        .filter(EmailReport.reporter_id == current_user.id)
        .order_by(EmailReport.created_at.desc())
        .all()
    )
    return [_serialize_report_with_incident(report) for report in reports]


@router.get("/{report_id}/download")
def download_generated_report(report_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Generated report not found")
    incident = report.incident
    if current_user.role == "employee" and incident.email_report.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PDF file is missing from storage")

    log_action(db, current_user.id, "pdf_downloaded", f"Downloaded PDF report {report.id}")
    db.commit()
    return FileResponse(path=str(file_path), filename=file_path.name, media_type="application/pdf")


@router.get("/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    report = db.query(EmailReport).filter(EmailReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if current_user.role == "employee" and report.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    log_action(db, current_user.id, "report_viewed", f"Viewed email report {report.id}")
    db.commit()
    return _serialize_report_with_incident(report, include_raw=True)


def _store_iocs(db: Session, incident_id: int, parsed: dict) -> None:
    seen: set[tuple[str, str]] = set()

    def add_ioc(ioc_type: str, value: str, source: str) -> None:
        key = (ioc_type, value)
        if not value or key in seen:
            return
        seen.add(key)
        db.add(IOC(incident_id=incident_id, type=ioc_type, value=value, source=source))

    for url in parsed.get("urls", []):
        add_ioc("url", url, "body")
    for domain in parsed.get("domains", []):
        add_ioc("domain", domain, "url")
    for ip_address in parsed.get("ip_addresses", []):
        add_ioc("ip_address", ip_address, "headers_or_body")
    for email in parsed.get("email_addresses", []):
        add_ioc("email_address", email, "headers_or_body")
    for file_name in parsed.get("attachment_names", []):
        add_ioc("file_name", file_name, "attachment_metadata")
    for extension in parsed.get("attachment_extensions", []):
        add_ioc("file_extension", extension, "attachment_metadata")
    for mechanism, result in parsed.get("header_auth_results", {}).items():
        if result != "not_found":
            add_ioc("header_auth", f"{mechanism}={result}", "headers")
    for redirect in parsed.get("open_redirect_urls", []):
        add_ioc("open_redirect", f"{redirect['url']} -> {redirect['target']}", "url_query")


def _store_triggered_rules(db: Session, incident_id: int, triggered_rules: list[dict]) -> None:
    rules_by_name = {rule.name: rule for rule in db.query(DetectionRule).all()}
    for triggered in triggered_rules:
        rule = rules_by_name.get(triggered["name"])
        db.add(
            TriggeredRule(
                incident_id=incident_id,
                rule_id=rule.id if rule else None,
                evidence=triggered["evidence"],
                score_added=triggered["score_added"],
            )
        )


def _serialize_report_with_incident(report: EmailReport, include_raw: bool = False) -> dict:
    incident = report.incident
    payload = {
        "id": report.id,
        "subject": report.subject,
        "sender": report.sender,
        "report_reason": report.report_reason,
        "uploaded_file_name": report.uploaded_file_name,
        "created_at": report.created_at,
        "incident": None,
    }
    if include_raw:
        payload["raw_email_text"] = report.raw_email_text
    if incident:
        payload["incident"] = {
            "id": incident.id,
            "status": incident.status,
            "severity": incident.severity,
            "verdict": incident.verdict,
            "risk_score": incident.risk_score,
            "recommended_action": incident.recommended_action,
        }
    return payload
