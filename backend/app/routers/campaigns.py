from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_roles
from ..database import get_db
from ..models import Campaign, Incident, User
from ..schemas import CampaignMergeRequest, CampaignPublic
from ..services.audit_logger import log_action
from ..services.campaign_correlation import correlate_incident, merge_campaigns, refresh_campaign_metadata

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


@router.get("", response_model=list[CampaignPublic])
def list_campaigns(db: Session = Depends(get_db), current_user: User = Depends(require_roles("analyst", "admin"))):
    _correlate_unassigned_incidents(db)
    campaigns = db.query(Campaign).order_by(Campaign.last_seen.desc()).all()
    for campaign in campaigns:
        refresh_campaign_metadata(db, campaign)
    db.commit()
    return campaigns


@router.get("/{campaign_id}")
def get_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    _correlate_unassigned_incidents(db)
    campaign = _get_campaign_or_404(db, campaign_id)
    refresh_campaign_metadata(db, campaign)
    db.commit()
    return _serialize_campaign_detail(campaign)


@router.post("/{campaign_id}/merge")
def merge_campaign(
    campaign_id: int,
    payload: CampaignMergeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    target = _get_campaign_or_404(db, campaign_id)
    source = _get_campaign_or_404(db, payload.source_campaign_id)
    merged = merge_campaigns(db, target, source)
    log_action(db, current_user.id, "campaign_merged", f"Merged campaign {source.id} into {target.id}")
    db.commit()
    db.refresh(merged)
    return _serialize_campaign_detail(merged)


@router.post("/{campaign_id}/close", response_model=CampaignPublic)
def close_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    campaign = _get_campaign_or_404(db, campaign_id)
    campaign.status = "Closed"
    refresh_campaign_metadata(db, campaign)
    log_action(db, current_user.id, "campaign_closed", f"Closed campaign {campaign.id}")
    db.commit()
    db.refresh(campaign)
    return campaign


def _get_campaign_or_404(db: Session, campaign_id: int) -> Campaign:
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    return campaign


def _correlate_unassigned_incidents(db: Session) -> None:
    for incident in db.query(Incident).filter(Incident.campaign_id.is_(None)).order_by(Incident.created_at.asc()).all():
        correlate_incident(db, incident)


def _serialize_campaign_detail(campaign: Campaign) -> dict:
    incidents = sorted(campaign.incidents, key=lambda item: item.created_at)
    ioc_counts = Counter()
    brand_counts = Counter()
    for incident in incidents:
        for ioc in incident.iocs:
            ioc_counts[f"{ioc.type}:{ioc.value}"] += 1
            if ioc.type == "brand_signal":
                brand_counts[ioc.value] += 1
        explanation = incident.analysis_explanation
        for item in (explanation.evidence_items if explanation else []) or []:
            if item.get("type") in {"brand_impersonation", "qr_brand_mismatch"}:
                brand_counts[(item.get("matched_value") or "Unknown").split("->")[0].strip()] += 1

    return {
        "id": campaign.id,
        "name": campaign.name,
        "label": campaign.label,
        "first_seen": campaign.first_seen,
        "last_seen": campaign.last_seen,
        "severity": campaign.severity,
        "status": campaign.status,
        "related_incident_count": campaign.related_incident_count,
        "primary_brand": campaign.primary_brand,
        "primary_sender_domain": campaign.primary_sender_domain,
        "primary_url_domain": campaign.primary_url_domain,
        "created_at": campaign.created_at,
        "updated_at": campaign.updated_at,
        "timeline": [
            {
                "incident_id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "created_at": incident.created_at,
            }
            for incident in incidents
        ],
        "related_incidents": [
            {
                "id": incident.id,
                "title": incident.title,
                "status": incident.status,
                "severity": incident.severity,
                "verdict": incident.verdict,
                "risk_score": incident.risk_score,
                "sender": incident.email_report.sender,
                "subject": incident.email_report.subject,
                "created_at": incident.created_at,
            }
            for incident in sorted(incidents, key=lambda item: item.created_at, reverse=True)
        ],
        "top_iocs": [
            {"type": key.split(":", 1)[0], "value": key.split(":", 1)[1], "count": value}
            for key, value in ioc_counts.most_common(12)
        ],
        "brands": [{"name": key, "value": value} for key, value in brand_counts.most_common(8)],
    }
