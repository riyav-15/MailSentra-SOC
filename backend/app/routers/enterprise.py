from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_roles
from ..database import get_db
from ..models import (
    BulkImportJob,
    CaseQueueItem,
    DetectionRule,
    EmailReport,
    EnterpriseIntegration,
    Incident,
    SiemExport,
    ThreatEnrichment,
    User,
)
from ..schemas import BulkImportRequest, CaseQueueUpdate, EnterpriseIntegrationPublic, EnterpriseIntegrationUpdate, SiemExportRequest
from ..services.audit_logger import log_action
from ..services.brand_watchlist import brand_profiles_from_db
from ..services.campaign_correlation import correlate_incident
from ..services.framework_mapper import store_framework_mappings
from ..services.risk_engine import analyze_raw_email
from ..services.threat_intel import enrich_indicator
from .reports import _store_analysis_explanation, _store_bec_checklist, _store_iocs, _store_triggered_rules

router = APIRouter(prefix="/enterprise", tags=["Enterprise"])

DEFAULT_INTEGRATIONS = [
    ("Microsoft Entra ID", "sso", "OIDC/SAML identity provider for paid workspaces and role provisioning."),
    ("Google Workspace SSO", "sso", "OIDC identity provider for domain-based team access."),
    ("Microsoft 365 Report Message", "email_gateway", "Internal reporting button ingestion for suspicious emails."),
    ("Google Workspace Gmail Add-on", "email_gateway", "Internal reporting button ingestion for Google Workspace."),
    ("Threat Intelligence Provider", "threat_intel", "Domain, URL, IP, and hash reputation enrichment."),
    ("Sandbox Metadata Connector", "sandbox", "Safe ingestion of attachment hashes and sandbox verdict metadata."),
    ("SIEM Webhook", "siem", "JSON webhook export for SIEM, SOAR, or ticketing systems."),
    ("Syslog Export", "siem", "Syslog-style export queue for security operations pipelines."),
]


def seed_enterprise_integrations(db: Session) -> None:
    existing = {integration.name for integration in db.query(EnterpriseIntegration).all()}
    for name, integration_type, summary in DEFAULT_INTEGRATIONS:
        if name not in existing:
            db.add(
                EnterpriseIntegration(
                    name=name,
                    type=integration_type,
                    status="Not configured",
                    config_summary=summary,
                    last_result="Waiting for tenant configuration.",
                )
            )


@router.get("/overview")
def enterprise_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    _sync_case_queue(db)
    open_queue = db.query(CaseQueueItem).filter(CaseQueueItem.queue_status != "Closed").all()
    now = datetime.utcnow()
    return {
        "totals": {
            "integrations": db.query(EnterpriseIntegration).count(),
            "active_integrations": db.query(EnterpriseIntegration).filter(EnterpriseIntegration.status == "Active").count(),
            "open_queue": len(open_queue),
            "sla_breaches": sum(1 for item in open_queue if item.sla_due_at < now),
            "enrichments": db.query(ThreatEnrichment).count(),
            "bulk_imports": db.query(BulkImportJob).count(),
            "siem_exports": db.query(SiemExport).count(),
        },
        "queue": [_serialize_queue_item(item) for item in sorted(open_queue, key=lambda item: item.sla_due_at)[:8]],
        "integrations": [
            EnterpriseIntegrationPublic.model_validate(item)
            for item in db.query(EnterpriseIntegration).order_by(EnterpriseIntegration.type.asc(), EnterpriseIntegration.name.asc()).all()
        ],
        "recent_imports": [
            _serialize_import_job(item)
            for item in db.query(BulkImportJob).order_by(BulkImportJob.created_at.desc()).limit(5).all()
        ],
        "recent_exports": [
            _serialize_siem_export(item)
            for item in db.query(SiemExport).order_by(SiemExport.created_at.desc()).limit(5).all()
        ],
    }


@router.get("/integrations", response_model=list[EnterpriseIntegrationPublic])
def list_integrations(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    return db.query(EnterpriseIntegration).order_by(EnterpriseIntegration.type.asc(), EnterpriseIntegration.name.asc()).all()


@router.patch("/integrations/{integration_id}", response_model=EnterpriseIntegrationPublic)
def update_integration(
    integration_id: int,
    payload: EnterpriseIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    integration = db.query(EnterpriseIntegration).filter(EnterpriseIntegration.id == integration_id).first()
    if not integration:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    if payload.status is not None:
        integration.status = payload.status
    if payload.config_summary is not None:
        integration.config_summary = payload.config_summary
    if payload.last_result is not None:
        integration.last_result = payload.last_result
    log_action(db, current_user.id, "integration_updated", f"Updated {integration.name}")
    db.commit()
    db.refresh(integration)
    return integration


@router.get("/queue")
def case_queue(db: Session = Depends(get_db), current_user: User = Depends(require_roles("analyst", "admin"))):
    _sync_case_queue(db)
    return [
        _serialize_queue_item(item)
        for item in db.query(CaseQueueItem).order_by(CaseQueueItem.sla_due_at.asc()).all()
    ]


@router.patch("/queue/{incident_id}")
def update_queue_item(
    incident_id: int,
    payload: CaseQueueUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    item = db.query(CaseQueueItem).filter(CaseQueueItem.incident_id == incident_id).first()
    if not item:
        incident = _get_incident(db, incident_id)
        item = _create_queue_item(db, incident, campaign_key=payload.campaign_key)
    if payload.assigned_to_id is not None:
        assignee = db.query(User).filter(User.id == payload.assigned_to_id, User.role.in_(["analyst", "admin"])).first()
        if not assignee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignee not found")
        item.assigned_to_id = assignee.id
    if payload.priority is not None:
        item.priority = payload.priority
    if payload.queue_status is not None:
        item.queue_status = payload.queue_status
    if payload.campaign_key is not None:
        item.campaign_key = payload.campaign_key
    if payload.sla_hours is not None:
        item.sla_due_at = datetime.utcnow() + timedelta(hours=payload.sla_hours)
    log_action(db, current_user.id, "queue_updated", f"Updated queue item for incident {incident_id}")
    db.commit()
    db.refresh(item)
    return _serialize_queue_item(item)


@router.post("/incidents/{incident_id}/enrich")
def enrich_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    incident = _get_incident(db, incident_id)
    created = []
    existing = {
        (item.indicator_type, item.indicator_value)
        for item in db.query(ThreatEnrichment).filter(ThreatEnrichment.incident_id == incident_id).all()
    }
    for ioc in incident.iocs:
        key = (ioc.type, ioc.value)
        if key in existing:
            continue
        enrichment = enrich_indicator(ioc.type, ioc.value)
        record = ThreatEnrichment(incident_id=incident_id, **enrichment)
        db.add(record)
        created.append(record)
    log_action(db, current_user.id, "incident_enriched", f"Enriched indicators for incident {incident_id}")
    db.commit()
    for record in created:
        db.refresh(record)
    return [_serialize_enrichment(item) for item in db.query(ThreatEnrichment).filter(ThreatEnrichment.incident_id == incident_id).all()]


@router.get("/incidents/{incident_id}/enrichment")
def incident_enrichment(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    _get_incident(db, incident_id)
    return [
        _serialize_enrichment(item)
        for item in db.query(ThreatEnrichment).filter(ThreatEnrichment.incident_id == incident_id).order_by(ThreatEnrichment.created_at.desc()).all()
    ]


@router.post("/bulk-import")
def bulk_import(
    payload: BulkImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    raw_messages = _split_batch(payload.raw_batch_text)
    rules = db.query(DetectionRule).all()
    disabled_rules = {rule.name for rule in rules if not rule.enabled}
    rule_weights = {rule.name: rule.severity_weight for rule in rules}
    created_incidents = 0

    job = BulkImportJob(
        submitted_by=current_user.id,
        campaign_key=payload.campaign_key,
        total_records=len(raw_messages),
        created_incidents=0,
        status="Running",
    )
    db.add(job)
    db.flush()

    for raw in raw_messages:
        analysis = analyze_raw_email(
            raw,
            disabled_rules=disabled_rules,
            rule_weights=rule_weights,
            brand_profiles=brand_profiles_from_db(db),
        )
        parsed = analysis["parsed_email"]
        risk = analysis["risk"]
        report = EmailReport(
            reporter_id=current_user.id,
            subject=_short(parsed.get("subject") or f"Bulk import {job.id}"),
            sender=_short(parsed.get("from_address") or "unknown sender"),
            raw_email_text=raw,
            uploaded_file_name=f"bulk-import-{job.id}.eml",
            report_reason=f"Bulk import campaign: {payload.campaign_key or 'uncategorized'}",
        )
        db.add(report)
        db.flush()
        incident = Incident(
            title=report.subject,
            email_report_id=report.id,
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
        _create_queue_item(db, incident, campaign_key=payload.campaign_key)
        if not payload.campaign_key and campaign:
            queue_item = db.query(CaseQueueItem).filter(CaseQueueItem.incident_id == incident.id).first()
            if queue_item:
                queue_item.campaign_key = campaign.label
        created_incidents += 1

    job.created_incidents = created_incidents
    job.status = "Completed"
    log_action(db, current_user.id, "bulk_import_completed", f"Imported {created_incidents} incidents")
    db.commit()
    db.refresh(job)
    return _serialize_import_job(job)


@router.post("/siem-export")
def create_siem_export(
    payload: SiemExportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    incident = _get_incident(db, payload.incident_id) if payload.incident_id else None
    summary = (
        f"Incident #{incident.id}: {incident.title} | severity={incident.severity} | risk={incident.risk_score}"
        if incident
        else "Bulk platform export request"
    )
    record = SiemExport(
        incident_id=incident.id if incident else None,
        destination=payload.destination,
        format=payload.format,
        status="Queued",
        payload_summary=summary,
    )
    db.add(record)
    log_action(db, current_user.id, "siem_export_queued", f"Queued SIEM export to {payload.destination}")
    db.commit()
    db.refresh(record)
    return _serialize_siem_export(record)


def _get_incident(db: Session, incident_id: int | None) -> Incident:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _sync_case_queue(db: Session) -> None:
    queued_ids = {item.incident_id for item in db.query(CaseQueueItem).all()}
    incidents = db.query(Incident).filter(Incident.status != "Closed").all()
    for incident in incidents:
        if incident.id not in queued_ids:
            _create_queue_item(db, incident)
    db.commit()


def _create_queue_item(db: Session, incident: Incident, campaign_key: str | None = None) -> CaseQueueItem:
    item = CaseQueueItem(
        incident_id=incident.id,
        assigned_to_id=incident.assigned_analyst_id,
        priority=incident.severity,
        queue_status="Open" if incident.status == "New" else "In Progress",
        campaign_key=campaign_key,
        sla_due_at=datetime.utcnow() + _sla_window(incident.severity),
    )
    db.add(item)
    return item


def _sla_window(severity: str) -> timedelta:
    return {
        "Critical": timedelta(hours=4),
        "High": timedelta(hours=8),
        "Medium": timedelta(hours=24),
        "Low": timedelta(hours=72),
    }.get(severity, timedelta(hours=24))


def _serialize_queue_item(item: CaseQueueItem) -> dict:
    incident = item.incident
    assignee = item.assigned_to
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "incident_title": incident.title,
        "incident_status": incident.status,
        "incident_severity": incident.severity,
        "risk_score": incident.risk_score,
        "assigned_to_id": item.assigned_to_id,
        "assigned_to_name": assignee.name if assignee else None,
        "priority": item.priority,
        "queue_status": item.queue_status,
        "campaign_key": item.campaign_key,
        "sla_due_at": item.sla_due_at,
        "sla_breached": item.sla_due_at < datetime.utcnow() and item.queue_status != "Closed",
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _serialize_enrichment(item: ThreatEnrichment) -> dict:
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "indicator_type": item.indicator_type,
        "indicator_value": item.indicator_value,
        "provider": item.provider,
        "reputation": item.reputation,
        "confidence": item.confidence,
        "details": item.details,
        "created_at": item.created_at,
    }


def _serialize_import_job(item: BulkImportJob) -> dict:
    return {
        "id": item.id,
        "file_name": item.file_name,
        "submitted_by": item.submitted_by,
        "campaign_key": item.campaign_key,
        "total_records": item.total_records,
        "created_incidents": item.created_incidents,
        "status": item.status,
        "created_at": item.created_at,
    }


def _serialize_siem_export(item: SiemExport) -> dict:
    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "destination": item.destination,
        "format": item.format,
        "status": item.status,
        "payload_summary": item.payload_summary,
        "created_at": item.created_at,
    }


def _split_batch(raw_batch_text: str) -> list[str]:
    chunks = [chunk.strip() for chunk in raw_batch_text.split("--- PHISHGUARD EMAIL ---") if chunk.strip()]
    return chunks or [raw_batch_text.strip()]


def _short(value: str, limit: int = 255) -> str:
    value = value.strip()
    return value[:limit] if len(value) > limit else value
