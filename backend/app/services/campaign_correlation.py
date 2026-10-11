from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from difflib import SequenceMatcher
import re
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..models import AnalysisExplanation, Campaign, IOC, Incident


SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CORRELATION_WINDOW = timedelta(days=14)


@dataclass
class CorrelationFeatures:
    normalized_subject: str
    sender_domain: str
    url_domains: set[str]
    attachment_hashes: set[str]
    brands: set[str]
    created_at: datetime

    @property
    def primary_label(self) -> str:
        return _most_common(self.brands) or self.sender_domain or _most_common(self.url_domains) or "uncategorized"


def normalize_subject(subject: str) -> str:
    cleaned = re.sub(r"^(re|fw|fwd):\s*", "", subject or "", flags=re.IGNORECASE).lower()
    cleaned = re.sub(r"[^a-z0-9\s]", " ", cleaned)
    tokens = [
        token
        for token in cleaned.split()
        if token not in {"urgent", "important", "notice", "alert", "action", "required", "please"}
    ]
    return " ".join(tokens[:12]).strip()


def subject_similarity(left: str, right: str) -> float:
    left_normalized = normalize_subject(left)
    right_normalized = normalize_subject(right)
    if not left_normalized or not right_normalized:
        return 0.0
    left_tokens = set(left_normalized.split())
    right_tokens = set(right_normalized.split())
    jaccard = len(left_tokens & right_tokens) / max(len(left_tokens | right_tokens), 1)
    ratio = SequenceMatcher(None, left_normalized, right_normalized).ratio()
    return max(jaccard, ratio)


def correlate_incident(db: Session, incident: Incident) -> Campaign:
    db.flush()
    features = incident_features(db, incident)
    candidates = (
        db.query(Campaign)
        .filter(Campaign.status != "Merged", Campaign.last_seen >= features.created_at - CORRELATION_WINDOW)
        .order_by(Campaign.last_seen.desc())
        .all()
    )
    best_campaign = None
    best_score = 0
    for campaign in candidates:
        score = campaign_match_score(campaign_features(db, campaign), features)
        if score > best_score:
            best_campaign = campaign
            best_score = score

    if best_campaign and best_score >= 35:
        incident.campaign_id = best_campaign.id
        refresh_campaign_metadata(db, best_campaign)
        return best_campaign

    campaign = Campaign(
        name=_campaign_name(features),
        label=features.normalized_subject or features.primary_label,
        first_seen=features.created_at,
        last_seen=features.created_at,
        severity=incident.severity,
        status="Open",
        related_incident_count=1,
        primary_brand=_most_common(features.brands),
        primary_sender_domain=features.sender_domain or None,
        primary_url_domain=_most_common(features.url_domains),
    )
    db.add(campaign)
    db.flush()
    incident.campaign_id = campaign.id
    refresh_campaign_metadata(db, campaign)
    return campaign


def campaign_match_score(campaign: CorrelationFeatures, incident: CorrelationFeatures) -> int:
    if campaign.created_at and incident.created_at and campaign.created_at < incident.created_at - CORRELATION_WINDOW:
        return 0

    score = 0
    if campaign.sender_domain and incident.sender_domain and campaign.sender_domain == incident.sender_domain:
        score += 30
    if campaign.url_domains & incident.url_domains:
        score += 25
    if campaign.attachment_hashes & incident.attachment_hashes:
        score += 45
    if campaign.brands & incident.brands:
        score += 25
    if subject_similarity(campaign.normalized_subject, incident.normalized_subject) >= 0.55:
        score += 20
    if incident.created_at >= campaign.created_at - CORRELATION_WINDOW:
        score += 10
    return score


def incident_features(db: Session, incident: Incident) -> CorrelationFeatures:
    iocs = db.query(IOC).filter(IOC.incident_id == incident.id).all()
    explanation = db.query(AnalysisExplanation).filter(AnalysisExplanation.incident_id == incident.id).first()
    url_domains = set()
    hashes = set()
    brands = set()
    for ioc in iocs:
        value = (ioc.value or "").lower().strip()
        if ioc.type == "domain":
            url_domains.add(value)
        elif ioc.type == "url":
            domain = _domain_from_url(value)
            if domain:
                url_domains.add(domain)
        elif ioc.type == "sha256":
            hashes.add(value)
        elif ioc.type == "brand_signal":
            brands.add(value)

    for item in (explanation.evidence_items if explanation else []) or []:
        if item.get("type") in {"brand_impersonation", "qr_brand_mismatch"}:
            brand = (item.get("matched_value") or "").split("->")[0].strip().lower()
            if brand:
                brands.add(brand)

    return CorrelationFeatures(
        normalized_subject=normalize_subject(incident.email_report.subject or incident.title),
        sender_domain=_sender_domain(incident.email_report.sender),
        url_domains=url_domains,
        attachment_hashes=hashes,
        brands=brands,
        created_at=incident.created_at or datetime.utcnow(),
    )


def campaign_features(db: Session, campaign: Campaign) -> CorrelationFeatures:
    incidents = db.query(Incident).filter(Incident.campaign_id == campaign.id).all()
    if not incidents:
        return CorrelationFeatures(
            normalized_subject=campaign.label,
            sender_domain=campaign.primary_sender_domain or "",
            url_domains={campaign.primary_url_domain} if campaign.primary_url_domain else set(),
            attachment_hashes=set(),
            brands={campaign.primary_brand} if campaign.primary_brand else set(),
            created_at=campaign.last_seen,
        )

    features = [incident_features(db, incident) for incident in incidents]
    return CorrelationFeatures(
        normalized_subject=campaign.label,
        sender_domain=_most_common([item.sender_domain for item in features if item.sender_domain]) or "",
        url_domains=set().union(*(item.url_domains for item in features)),
        attachment_hashes=set().union(*(item.attachment_hashes for item in features)),
        brands=set().union(*(item.brands for item in features)),
        created_at=max(item.created_at for item in features),
    )


def refresh_campaign_metadata(db: Session, campaign: Campaign) -> None:
    db.flush()
    incidents = db.query(Incident).filter(Incident.campaign_id == campaign.id).all()
    if not incidents:
        campaign.related_incident_count = 0
        return

    features = [incident_features(db, incident) for incident in incidents]
    campaign.first_seen = min(incident.created_at for incident in incidents)
    campaign.last_seen = max(incident.created_at for incident in incidents)
    campaign.severity = max((incident.severity for incident in incidents), key=lambda value: SEVERITY_ORDER.get(value, 0))
    campaign.related_incident_count = len(incidents)
    campaign.primary_sender_domain = _most_common([item.sender_domain for item in features if item.sender_domain])
    campaign.primary_url_domain = _most_common([domain for item in features for domain in item.url_domains])
    campaign.primary_brand = _most_common([brand for item in features for brand in item.brands])
    if not campaign.label:
        campaign.label = _most_common([item.normalized_subject for item in features if item.normalized_subject]) or f"campaign-{campaign.id}"
    campaign.name = _campaign_name(features[0], campaign.id)


def merge_campaigns(db: Session, target: Campaign, source: Campaign) -> Campaign:
    if target.id == source.id:
        return target
    for incident in db.query(Incident).filter(Incident.campaign_id == source.id).all():
        incident.campaign_id = target.id
    source.status = "Merged"
    source.related_incident_count = 0
    refresh_campaign_metadata(db, target)
    return target


def _campaign_name(features: CorrelationFeatures, campaign_id: int | None = None) -> str:
    anchor = features.primary_label
    date_label = features.created_at.strftime("%Y-%m-%d")
    suffix = f" #{campaign_id}" if campaign_id else ""
    return f"{anchor.title()} campaign {date_label}{suffix}"


def _sender_domain(sender: str) -> str:
    if not sender:
        return ""
    if "@" in sender:
        return sender.split("@")[-1].strip("<> ").lower().rstrip(".")
    return sender.strip().lower().rstrip(".")


def _domain_from_url(value: str) -> str:
    parsed = urlparse(value if value.startswith(("http://", "https://")) else f"http://{value}")
    return (parsed.hostname or "").lower().rstrip(".")


def _most_common(values) -> str | None:
    cleaned = [value for value in values if value]
    if not cleaned:
        return None
    return Counter(cleaned).most_common(1)[0][0]
