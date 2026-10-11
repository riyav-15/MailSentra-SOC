from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import AnalysisExplanation, BECChecklistItem, DetectionRule, EmailReport, IOC, Incident, Report, TriggeredRule, User
from ..schemas import EmailReportPublic
from ..services.audit_logger import log_action
from ..services.brand_watchlist import brand_profiles_from_db
from ..services.campaign_correlation import correlate_incident
from ..services.framework_mapper import store_framework_mappings
from ..services.qr_analyzer import extract_qr_payloads_from_bytes, is_supported_image
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
    uploaded_qr_payloads = []
    if eml_file:
        uploaded_file_name = eml_file.filename
        content = await eml_file.read()
        if uploaded_file_name.lower().endswith(".eml"):
            uploaded_text = content.decode("utf-8", errors="ignore")
        elif is_supported_image(uploaded_file_name, eml_file.content_type):
            uploaded_qr_payloads = extract_qr_payloads_from_bytes(content, uploaded_file_name, eml_file.content_type)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only .eml files or QR image files are supported")

    final_raw_text = (raw_email_text or uploaded_text or "").strip()
    if not final_raw_text and uploaded_qr_payloads:
        final_raw_text = "\n".join(item["payload"] for item in uploaded_qr_payloads)
    if not final_raw_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Paste email text or upload a .eml or QR image file")

    rules = db.query(DetectionRule).all()
    disabled_rules = {rule.name for rule in rules if not rule.enabled}
    rule_weights = {rule.name: rule.severity_weight for rule in rules}
    analysis = analyze_raw_email(
        final_raw_text,
        disabled_rules=disabled_rules,
        rule_weights=rule_weights,
        extra_qr_payloads=uploaded_qr_payloads,
        brand_profiles=brand_profiles_from_db(db),
    )
    parsed = analysis["parsed_email"]
    risk = analysis["risk"]

    email_report = EmailReport(
        reporter_id=current_user.id,
        subject=_short(subject),
        sender=_short(sender),
        raw_email_text=final_raw_text,
        uploaded_file_name=uploaded_file_name,
        report_reason=report_reason,
    )
    db.add(email_report)
    db.flush()

    incident = Incident(
        title=_short(subject or parsed.get("subject") or "Suspicious email report"),
        email_report_id=email_report.id,
        status="New",
        severity=risk["severity"],
        verdict=risk["verdict_suggestion"],
        risk_score=risk["score"],
        recommended_action=risk["recommended_action"],
        suspected_bec=risk["bec_analysis"].get("suspected_bec", False),
        financial_risk_type=risk["bec_analysis"].get("financial_risk_type"),
        requested_amount=risk["bec_analysis"].get("requested_amount"),
        impersonated_person_or_vendor=risk["bec_analysis"].get("impersonated_person_or_vendor"),
    )
    db.add(incident)
    db.flush()

    _store_iocs(db, incident.id, parsed)
    _store_triggered_rules(db, incident.id, risk["triggered_rules"])
    _store_analysis_explanation(db, incident.id, risk)
    _store_bec_checklist(db, incident.id, risk["bec_analysis"])
    store_framework_mappings(db, incident.id, parsed, risk)
    campaign = correlate_incident(db, incident)
    log_action(db, current_user.id, "report_submitted", f"Submitted email report {email_report.id}")
    db.commit()

    return {
        "report": EmailReportPublic.model_validate(email_report),
        "incident_id": incident.id,
        "campaign_id": campaign.id,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "verdict_suggestion": incident.verdict,
        "explanation_summary": risk["explanation_summary"],
        "evidence_items": risk["evidence_items"],
        "triggered_rules": risk["triggered_rules"],
        "score_breakdown": risk["score_breakdown"],
        "bec_analysis": risk["bec_analysis"],
        "recommended_action": incident.recommended_action,
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
    for attachment in parsed.get("attachment_metadata", []):
        if attachment.get("sha256"):
            add_ioc("sha256", attachment["sha256"], f"attachment:{attachment.get('file_name', 'unknown')}")
    for extension in parsed.get("attachment_extensions", []):
        add_ioc("file_extension", extension, "attachment_metadata")
    for finding in parsed.get("brand_impersonation", []):
        add_ioc("brand_signal", finding["brand"], "brand_impersonation")
    for qr in parsed.get("qr_payloads", []):
        add_ioc("qr_payload", qr["payload"], f"qr:{qr.get('source', 'image')}")
        if qr.get("is_url"):
            add_ioc("url", qr["payload"], f"qr:{qr.get('source', 'image')}")
    for mechanism, result in parsed.get("header_auth_results", {}).items():
        if result != "not_found":
            add_ioc("header_auth", f"{mechanism}={result}", "headers")


def _store_triggered_rules(db: Session, incident_id: int, triggered_rules: list[dict]) -> None:
    rules_by_name = {rule.name: rule for rule in db.query(DetectionRule).all()}
    for triggered in triggered_rules:
        rule = rules_by_name.get(triggered["name"])
        db.add(
            TriggeredRule(
                incident_id=incident_id,
                rule_id=rule.id if rule else None,
                evidence=triggered.get("evidence") or triggered.get("reason", ""),
                score_added=triggered.get("score_added", triggered.get("score_impact", 0)),
            )
        )


def _store_analysis_explanation(db: Session, incident_id: int, risk: dict) -> None:
    db.add(
        AnalysisExplanation(
            incident_id=incident_id,
            risk_score=risk["score"],
            severity=risk["severity"],
            verdict_suggestion=risk["verdict_suggestion"],
            explanation_summary=risk["explanation_summary"],
            evidence_items=risk["evidence_items"],
            triggered_rules=risk["triggered_rules"],
            score_breakdown=risk["score_breakdown"],
        )
    )


def _store_bec_checklist(db: Session, incident_id: int, bec_analysis: dict) -> None:
    if not bec_analysis.get("suspected_bec"):
        return
    items = [
        ("verify_sender_out_of_band", "Verify sender out-of-band"),
        ("check_vendor_master_data", "Check vendor master data"),
        ("confirm_bank_account_change", "Confirm bank account change"),
        ("notify_finance_team", "Notify finance team"),
        ("preserve_headers", "Preserve headers"),
    ]
    for item_key, label in items:
        db.add(BECChecklistItem(incident_id=incident_id, item_key=item_key, label=label))


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
            "campaign_id": incident.campaign_id,
            "status": incident.status,
            "severity": incident.severity,
            "verdict": incident.verdict,
            "risk_score": incident.risk_score,
            "recommended_action": incident.recommended_action,
        }
    return payload


def _short(value: str, limit: int = 255) -> str:
    value = (value or "").strip()
    return value[:limit] if len(value) > limit else value
