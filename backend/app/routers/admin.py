from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_roles
from ..database import get_db
from ..models import (
    AnalystNote,
    AnalysisExplanation,
    AuditLog,
    BECChecklistItem,
    BrandWatchlist,
    Campaign,
    CaseQueueItem,
    DetectionRule,
    EmailReport,
    IncidentFrameworkMapping,
    IOC,
    Incident,
    PlaybookRun,
    Report,
    SiemExport,
    ThreatEnrichment,
    TriggeredRule,
    User,
)
from ..schemas import (
    AuditLogPublic,
    BrandWatchlistCreate,
    BrandWatchlistPublic,
    BrandWatchlistUpdate,
    DetectionRulePublic,
    DetectionRuleUpdate,
    ReportPublic,
    UserPublic,
    UserRoleUpdate,
)
from ..services.audit_logger import log_action

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users", response_model=list[UserPublic])
def list_users(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.patch("/users/{user_id}/role", response_model=UserPublic)
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.role = payload.role
    log_action(db, current_user.id, "user_role_changed", f"{user.email} role changed to {payload.role}")
    db.commit()
    db.refresh(user)
    return user


@router.get("/rules", response_model=list[DetectionRulePublic])
def list_rules(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    return db.query(DetectionRule).order_by(DetectionRule.name.asc()).all()


@router.patch("/rules/{rule_id}", response_model=DetectionRulePublic)
def update_rule(
    rule_id: int,
    payload: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection rule not found")
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.severity_weight is not None:
        rule.severity_weight = payload.severity_weight
    log_action(db, current_user.id, "rule_updated", f"Detection rule {rule.name} was updated")
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/audit-logs", response_model=list[AuditLogPublic])
def audit_logs(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(300).all()


@router.get("/reports", response_model=list[ReportPublic])
def generated_reports(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    return db.query(Report).order_by(Report.created_at.desc()).all()


@router.get("/brand-watchlist", response_model=list[BrandWatchlistPublic])
def list_brand_watchlist(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    return db.query(BrandWatchlist).order_by(BrandWatchlist.brand_name.asc()).all()


@router.post("/brand-watchlist", response_model=BrandWatchlistPublic, status_code=status.HTTP_201_CREATED)
def create_brand_watchlist_item(
    payload: BrandWatchlistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    existing = db.query(BrandWatchlist).filter(BrandWatchlist.brand_name == payload.brand_name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Brand already exists")
    item = BrandWatchlist(
        brand_name=payload.brand_name,
        legitimate_domains=_clean_list(payload.legitimate_domains),
        keywords=_clean_list(payload.keywords),
        logo_hint=payload.logo_hint,
    )
    db.add(item)
    log_action(db, current_user.id, "brand_watchlist_created", f"Created brand watchlist item {payload.brand_name}")
    db.commit()
    db.refresh(item)
    return item


@router.patch("/brand-watchlist/{brand_id}", response_model=BrandWatchlistPublic)
def update_brand_watchlist_item(
    brand_id: int,
    payload: BrandWatchlistUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = db.query(BrandWatchlist).filter(BrandWatchlist.id == brand_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brand watchlist item not found")
    if payload.brand_name is not None:
        item.brand_name = payload.brand_name
    if payload.legitimate_domains is not None:
        item.legitimate_domains = _clean_list(payload.legitimate_domains)
    if payload.keywords is not None:
        item.keywords = _clean_list(payload.keywords)
    if payload.logo_hint is not None:
        item.logo_hint = payload.logo_hint
    log_action(db, current_user.id, "brand_watchlist_updated", f"Updated brand watchlist item {item.brand_name}")
    db.commit()
    db.refresh(item)
    return item


@router.delete("/brand-watchlist/{brand_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_brand_watchlist_item(
    brand_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = db.query(BrandWatchlist).filter(BrandWatchlist.id == brand_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brand watchlist item not found")
    log_action(db, current_user.id, "brand_watchlist_deleted", f"Deleted brand watchlist item {item.brand_name}")
    db.delete(item)
    db.commit()


@router.delete("/demo-data")
def delete_demo_data(db: Session = Depends(get_db), current_user: User = Depends(require_roles("admin"))):
    report_paths = [report.file_path for report in db.query(Report).all()]
    db.query(Report).delete()
    db.query(AnalystNote).delete()
    db.query(BECChecklistItem).delete()
    db.query(AnalysisExplanation).delete()
    db.query(IncidentFrameworkMapping).delete()
    db.query(PlaybookRun).delete()
    db.query(TriggeredRule).delete()
    db.query(IOC).delete()
    db.query(ThreatEnrichment).delete()
    db.query(CaseQueueItem).delete()
    db.query(SiemExport).delete()
    db.query(Incident).delete()
    db.query(Campaign).delete()
    db.query(EmailReport).delete()
    db.query(AuditLog).delete()
    log_action(db, current_user.id, "demo_data_deleted", "Deleted reports, incidents, notes, IOCs, PDFs, and audit logs")
    db.commit()
    for report_path in report_paths:
        path = Path(report_path)
        try:
            if path.exists() and path.is_file():
                path.unlink()
        except OSError:
            pass
    return {"message": "Demo data deleted. User accounts and detection rules were kept."}


def _clean_list(values: list[str]) -> list[str]:
    return sorted({value.strip().lower() for value in values if value and value.strip()})
