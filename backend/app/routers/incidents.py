from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_roles
from ..database import get_db
from ..models import AnalystNote, BECChecklistItem, IOC, Incident, PlaybookTemplate, Report, User
from ..schemas import (
    BECChecklistUpdate,
    AnalystNoteCreate,
    AnalystNotePublic,
    CopilotSummaryPublic,
    IncidentFieldUpdate,
    IncidentPublic,
    IOCPublic,
    PlaybookRunRequest,
    ReportPublic,
)
from ..services.audit_logger import log_action
from ..services.copilot import generate_rule_based_soc_summary
from ..services.framework_mapper import nist_lifecycle_for_incident
from ..services.pdf_generator import generate_incident_pdf
from ..services.playbooks import run_playbook_simulation

router = APIRouter(prefix="/incidents", tags=["Incidents"])

VALID_STATUSES = {"New", "In Review", "Escalated", "Closed"}
VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_VERDICTS = {"Safe", "Spam", "Suspicious", "Likely Phishing", "Confirmed Phishing", "Pending Review"}


@router.get("", response_model=list[IncidentPublic])
def list_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    return db.query(Incident).order_by(Incident.created_at.desc()).all()


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    incident = _get_incident_or_404(db, incident_id)
    log_action(db, current_user.id, "incident_viewed", f"Viewed incident {incident_id}")
    db.commit()
    return _serialize_incident(incident)


@router.patch("/{incident_id}/status", response_model=IncidentPublic)
def update_status(
    incident_id: int,
    payload: IncidentFieldUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    if payload.value not in VALID_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid incident status")
    incident = _get_incident_or_404(db, incident_id)
    incident.status = payload.value
    if current_user.role == "analyst" and not incident.assigned_analyst_id:
        incident.assigned_analyst_id = current_user.id
    log_action(db, current_user.id, "status_changed", f"Incident {incident_id} status changed to {payload.value}")
    db.commit()
    db.refresh(incident)
    return incident


@router.patch("/{incident_id}/severity", response_model=IncidentPublic)
def update_severity(
    incident_id: int,
    payload: IncidentFieldUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    if payload.value not in VALID_SEVERITIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid incident severity")
    incident = _get_incident_or_404(db, incident_id)
    incident.severity = payload.value
    log_action(db, current_user.id, "severity_changed", f"Incident {incident_id} severity changed to {payload.value}")
    db.commit()
    db.refresh(incident)
    return incident


@router.patch("/{incident_id}/verdict", response_model=IncidentPublic)
def update_verdict(
    incident_id: int,
    payload: IncidentFieldUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    if payload.value not in VALID_VERDICTS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verdict")
    incident = _get_incident_or_404(db, incident_id)
    incident.verdict = payload.value
    log_action(db, current_user.id, "verdict_changed", f"Incident {incident_id} verdict changed to {payload.value}")
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/{incident_id}/notes", response_model=AnalystNotePublic, status_code=status.HTTP_201_CREATED)
def add_note(
    incident_id: int,
    payload: AnalystNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    _get_incident_or_404(db, incident_id)
    note = AnalystNote(incident_id=incident_id, analyst_id=current_user.id, note=payload.note)
    db.add(note)
    log_action(db, current_user.id, "note_added", f"Added note to incident {incident_id}")
    db.commit()
    db.refresh(note)
    return note


@router.get("/{incident_id}/iocs", response_model=list[IOCPublic])
def get_iocs(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    _get_incident_or_404(db, incident_id)
    return db.query(IOC).filter(IOC.incident_id == incident_id).order_by(IOC.type.asc()).all()


@router.patch("/{incident_id}/bec-checklist/{item_key}")
def update_bec_checklist_item(
    incident_id: int,
    item_key: str,
    payload: BECChecklistUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    _get_incident_or_404(db, incident_id)
    item = (
        db.query(BECChecklistItem)
        .filter(BECChecklistItem.incident_id == incident_id, BECChecklistItem.item_key == item_key)
        .first()
    )
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found")
    item.completed = payload.completed
    item.completed_by = current_user.id if payload.completed else None
    item.completed_at = datetime.utcnow() if payload.completed else None
    log_action(db, current_user.id, "bec_checklist_updated", f"Updated BEC checklist item {item_key} on incident {incident_id}")
    db.commit()
    db.refresh(item)
    return _serialize_bec_checklist_item(item)


@router.post("/{incident_id}/copilot-summary", response_model=CopilotSummaryPublic)
def copilot_summary(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    incident = _get_incident_or_404(db, incident_id)
    summary = generate_rule_based_soc_summary(incident)
    log_action(db, current_user.id, "copilot_summary_generated", f"Generated deterministic SOC summary for incident {incident_id}")
    db.commit()
    return summary


@router.get("/{incident_id}/playbooks")
def incident_playbooks(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    incident = _get_incident_or_404(db, incident_id)
    templates = db.query(PlaybookTemplate).filter(PlaybookTemplate.enabled == True).order_by(PlaybookTemplate.name.asc()).all()
    return {
        "templates": [_serialize_playbook_template(item) for item in templates],
        "runs": [_serialize_playbook_run(item) for item in sorted(incident.playbook_runs, key=lambda run: run.created_at, reverse=True)],
    }


@router.post("/{incident_id}/playbooks/run")
def run_incident_playbook(
    incident_id: int,
    payload: PlaybookRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    incident = _get_incident_or_404(db, incident_id)
    query = db.query(PlaybookTemplate).filter(PlaybookTemplate.enabled == True)
    if payload.template_id is not None:
        template = query.filter(PlaybookTemplate.id == payload.template_id).first()
    elif payload.action_key:
        template = query.filter(PlaybookTemplate.action_key == payload.action_key).first()
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="template_id or action_key is required")
    if not template:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook template not found")
    run = run_playbook_simulation(db, incident, template, current_user)
    log_action(db, current_user.id, "playbook_simulated", f"Ran simulated playbook {template.name} for incident {incident_id}")
    db.commit()
    db.refresh(run)
    return _serialize_playbook_run(run)


@router.post("/{incident_id}/generate-report", response_model=ReportPublic)
def generate_pdf_report(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    incident = _get_incident_or_404(db, incident_id)
    report = generate_incident_pdf(db, incident, generated_by=current_user.id)
    log_action(db, current_user.id, "pdf_generated", f"Generated PDF report {report.id} for incident {incident_id}")
    db.commit()
    db.refresh(report)
    return report


def _get_incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _serialize_incident(incident: Incident) -> dict:
    explanation = incident.analysis_explanation
    return {
        "id": incident.id,
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
        "verdict": incident.verdict,
        "risk_score": incident.risk_score,
        "recommended_action": incident.recommended_action,
        "campaign_id": incident.campaign_id,
        "campaign": _serialize_campaign_summary(incident.campaign) if incident.campaign else None,
        "suspected_bec": incident.suspected_bec,
        "financial_risk_type": incident.financial_risk_type,
        "requested_amount": incident.requested_amount,
        "impersonated_person_or_vendor": incident.impersonated_person_or_vendor,
        "analysis_explanation": _serialize_analysis_explanation(explanation) if explanation else None,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "reporter": {
            "id": incident.email_report.reporter.id,
            "name": incident.email_report.reporter.name,
            "email": incident.email_report.reporter.email,
        },
        "email_report": {
            "id": incident.email_report.id,
            "subject": incident.email_report.subject,
            "sender": incident.email_report.sender,
            "report_reason": incident.email_report.report_reason,
            "uploaded_file_name": incident.email_report.uploaded_file_name,
            "created_at": incident.email_report.created_at,
        },
        "iocs": [
            {"id": ioc.id, "type": ioc.type, "value": ioc.value, "source": ioc.source}
            for ioc in incident.iocs
        ],
        "triggered_rules": [
            {
                "id": item.id,
                "rule_name": item.rule.name if item.rule else "Unknown rule",
                "evidence": item.evidence,
                "score_added": item.score_added,
            }
            for item in incident.triggered_rules
        ],
        "notes": [
            {
                "id": note.id,
                "analyst_id": note.analyst_id,
                "analyst_name": note.analyst.name,
                "note": note.note,
                "created_at": note.created_at,
            }
            for note in incident.notes
        ],
        "reports": [
            {"id": report.id, "created_at": report.created_at, "generated_by": report.generated_by}
            for report in incident.reports
        ],
        "bec_checklist": [_serialize_bec_checklist_item(item) for item in incident.bec_checklist],
        "framework_mappings": [_serialize_framework_mapping(item) for item in incident.framework_mappings],
        "nist_lifecycle": nist_lifecycle_for_incident(incident),
    }


def _serialize_analysis_explanation(explanation) -> dict:
    return {
        "id": explanation.id,
        "incident_id": explanation.incident_id,
        "risk_score": explanation.risk_score,
        "severity": explanation.severity,
        "verdict_suggestion": explanation.verdict_suggestion,
        "explanation_summary": explanation.explanation_summary,
        "evidence_items": explanation.evidence_items or [],
        "triggered_rules": explanation.triggered_rules or [],
        "score_breakdown": explanation.score_breakdown or [],
        "created_at": explanation.created_at,
    }


def _serialize_bec_checklist_item(item: BECChecklistItem) -> dict:
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "item_key": item.item_key,
        "label": item.label,
        "completed": item.completed,
        "completed_by": item.completed_by,
        "completed_at": item.completed_at,
        "created_at": item.created_at,
    }


def _serialize_campaign_summary(campaign) -> dict:
    return {
        "id": campaign.id,
        "name": campaign.name,
        "label": campaign.label,
        "severity": campaign.severity,
        "status": campaign.status,
        "related_incident_count": campaign.related_incident_count,
        "primary_brand": campaign.primary_brand,
        "primary_sender_domain": campaign.primary_sender_domain,
        "primary_url_domain": campaign.primary_url_domain,
    }


def _serialize_framework_mapping(item) -> dict:
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "framework": item.framework,
        "tactic": item.tactic,
        "technique_id": item.technique_id,
        "technique_name": item.technique_name,
        "confidence": item.confidence,
        "reason": item.reason,
        "created_at": item.created_at,
    }


def _serialize_playbook_template(item: PlaybookTemplate) -> dict:
    return {
        "id": item.id,
        "action_key": item.action_key,
        "name": item.name,
        "description": item.description,
        "requires_integration_type": item.requires_integration_type,
        "enabled": item.enabled,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _serialize_playbook_run(item) -> dict:
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "template_id": item.template_id,
        "action_key": item.action_key,
        "name": item.name,
        "status": item.status,
        "mode": item.mode,
        "action_results": item.action_results or [],
        "created_by": item.created_by,
        "created_at": item.created_at,
    }
