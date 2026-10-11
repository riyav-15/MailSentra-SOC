from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..models import AnalysisExplanation, Campaign, CaseQueueItem, EmailReport, Incident, TriggeredRule, User
from ..schemas import DashboardSummary, ExecutiveDashboardSummary

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/employee", response_model=DashboardSummary)
def employee_dashboard(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    reports = db.query(EmailReport).filter(EmailReport.reporter_id == current_user.id).all()
    incidents = [report.incident for report in reports if report.incident]
    return _build_summary(db, incidents, reports)


@router.get("/soc", response_model=DashboardSummary)
def soc_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
):
    reports = db.query(EmailReport).all()
    incidents = db.query(Incident).all()
    return _build_summary(db, incidents, reports)


@router.get("/admin", response_model=DashboardSummary)
def admin_dashboard(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    reports = db.query(EmailReport).all()
    incidents = db.query(Incident).all()
    summary = _build_summary(db, incidents, reports)
    summary.totals["users"] = db.query(User).count()
    return summary


@router.get("/executive", response_model=ExecutiveDashboardSummary)
def executive_dashboard(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    reports = db.query(EmailReport).all()
    incidents = db.query(Incident).all()
    campaigns = db.query(Campaign).all()
    queue_items = db.query(CaseQueueItem).all()
    now = datetime.utcnow()

    closed = [incident for incident in incidents if incident.status == "Closed"]
    phishing_positive = [incident for incident in closed if incident.verdict in {"Likely Phishing", "Confirmed Phishing"}]
    false_positive = [incident for incident in closed if incident.verdict in {"Safe", "Spam"}]
    triage_hours = [_hours_between(incident.created_at, incident.updated_at) for incident in incidents if incident.updated_at]
    close_hours = [_hours_between(incident.created_at, incident.updated_at) for incident in closed if incident.updated_at]

    brand_counts = _brand_counts(db, {incident.id for incident in incidents})
    sender_counts = Counter(_sender_domain(report.sender) for report in reports if report.sender)
    severity_counts = Counter(campaign.severity for campaign in campaigns)
    breaches = [
        item
        for item in queue_items
        if item.sla_due_at < now and item.queue_status != "Closed"
    ]

    denominator = max(len(closed), 1)
    return ExecutiveDashboardSummary(
        totals={
            "reports": len(reports),
            "incidents": len(incidents),
            "campaigns": len(campaigns),
            "average_triage_time_hours": round(sum(triage_hours) / max(len(triage_hours), 1), 2),
            "mean_time_to_close_hours": round(sum(close_hours) / max(len(close_hours), 1), 2),
            "sla_breaches": len(breaches),
            "true_positive_rate": round((len(phishing_positive) / denominator) * 100, 1),
            "false_positive_rate": round((len(false_positive) / denominator) * 100, 1),
        },
        reports_over_time=_reports_over_time(reports),
        top_targeted_brands=[{"name": key, "value": value} for key, value in brand_counts.most_common(8)],
        top_sender_domains=[{"name": key, "value": value} for key, value in sender_counts.most_common(8)],
        campaigns_by_severity=[{"name": key, "value": value} for key, value in sorted(severity_counts.items())],
        sla_breaches=[
            {
                "incident_id": item.incident_id,
                "incident_title": item.incident.title,
                "priority": item.priority,
                "sla_due_at": item.sla_due_at,
            }
            for item in sorted(breaches, key=lambda item: item.sla_due_at)[:10]
        ],
    )


def _build_summary(db: Session, incidents: list[Incident], reports: list[EmailReport]) -> DashboardSummary:
    status_counts = Counter(incident.status for incident in incidents)
    severity_counts = Counter(incident.severity for incident in incidents)
    domain_counts = Counter(_sender_domain(report.sender) for report in reports if report.sender)

    triggered = db.query(TriggeredRule).all()
    incident_ids = {incident.id for incident in incidents}
    rule_counts = Counter(
        item.rule.name if item.rule else "Unknown rule"
        for item in triggered
        if item.incident_id in incident_ids
    )
    brand_counts = _brand_counts(db, incident_ids)

    recent = sorted(incidents, key=lambda item: item.created_at, reverse=True)[:8]
    totals = {
        "reported_emails": len(reports),
        "open_incidents": sum(1 for incident in incidents if incident.status != "Closed"),
        "closed_incidents": sum(1 for incident in incidents if incident.status == "Closed"),
        "high_risk_incidents": sum(1 for incident in incidents if incident.severity in {"High", "Critical"}),
        "phishing_verdict_count": sum(
            1 for incident in incidents if incident.verdict in {"Likely Phishing", "Confirmed Phishing"}
        ),
    }

    return DashboardSummary(
        totals=totals,
        by_status=[{"name": key, "value": value} for key, value in sorted(status_counts.items())],
        by_severity=[{"name": key, "value": value} for key, value in sorted(severity_counts.items())],
        top_sender_domains=[{"name": key, "value": value} for key, value in domain_counts.most_common(8)],
        top_triggered_rules=[{"name": key, "value": value} for key, value in rule_counts.most_common(8)],
        top_impersonated_brands=[{"name": key, "value": value} for key, value in brand_counts.most_common(8)],
        recent_incidents=[
            {
                "id": incident.id,
                "title": incident.title,
                "status": incident.status,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "created_at": incident.created_at,
            }
            for incident in recent
        ],
    )


def _sender_domain(sender: str) -> str:
    if "@" in sender:
        return sender.split("@")[-1].strip("<> ").lower()
    return sender.strip().lower() or "unknown"


def _brand_counts(db: Session, incident_ids: set[int]) -> Counter:
    explanations = db.query(AnalysisExplanation).all()
    brand_counts = Counter()
    for explanation in explanations:
        if explanation.incident_id not in incident_ids:
            continue
        for item in explanation.evidence_items or []:
            if item.get("type") in {"brand_impersonation", "lookalike_domain", "qr_brand_mismatch"}:
                value = item.get("matched_value") or "Unknown brand"
                brand = value.split("->")[0].strip()
                brand_counts[brand] += 1
    return brand_counts


def _reports_over_time(reports: list[EmailReport]) -> list[dict]:
    start = datetime.utcnow().date() - timedelta(days=13)
    counts = Counter(report.created_at.date() for report in reports)
    return [
        {"name": (start + timedelta(days=offset)).isoformat(), "value": counts[start + timedelta(days=offset)]}
        for offset in range(14)
    ]


def _hours_between(start: datetime, end: datetime) -> float:
    return max((end - start).total_seconds() / 3600, 0)
