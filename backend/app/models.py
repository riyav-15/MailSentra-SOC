from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(30), default="employee", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    reports: Mapped[list["EmailReport"]] = relationship(back_populates="reporter")
    assigned_incidents: Mapped[list["Incident"]] = relationship(back_populates="assigned_analyst")
    notes: Mapped[list["AnalystNote"]] = relationship(back_populates="analyst")


class EmailReport(Base):
    __tablename__ = "email_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    sender: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_email_text: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_file_name: Mapped[str | None] = mapped_column(String(255))
    report_reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    reporter: Mapped[User] = relationship(back_populates="reports")
    incident: Mapped["Incident"] = relationship(back_populates="email_report", uselist=False)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    email_report_id: Mapped[int] = mapped_column(ForeignKey("email_reports.id"), nullable=False, unique=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    assigned_analyst_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="New", index=True)
    severity: Mapped[str] = mapped_column(String(40), default="Low", index=True)
    verdict: Mapped[str] = mapped_column(String(80), default="Pending Review", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    suspected_bec: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    financial_risk_type: Mapped[str | None] = mapped_column(String(120))
    requested_amount: Mapped[str | None] = mapped_column(String(120))
    impersonated_person_or_vendor: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    email_report: Mapped[EmailReport] = relationship(back_populates="incident")
    campaign: Mapped["Campaign | None"] = relationship(back_populates="incidents")
    assigned_analyst: Mapped[User | None] = relationship(back_populates="assigned_incidents")
    iocs: Mapped[list["IOC"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    triggered_rules: Mapped[list["TriggeredRule"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    notes: Mapped[list["AnalystNote"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    bec_checklist: Mapped[list["BECChecklistItem"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    framework_mappings: Mapped[list["IncidentFrameworkMapping"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    playbook_runs: Mapped[list["PlaybookRun"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    analysis_explanation: Mapped["AnalysisExplanation"] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        uselist=False,
    )


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(40), default="Low", index=True)
    status: Mapped[str] = mapped_column(String(40), default="Open", index=True)
    related_incident_count: Mapped[int] = mapped_column(Integer, default=0)
    primary_brand: Mapped[str | None] = mapped_column(String(120), index=True)
    primary_sender_domain: Mapped[str | None] = mapped_column(String(255), index=True)
    primary_url_domain: Mapped[str | None] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    incidents: Mapped[list[Incident]] = relationship(back_populates="campaign")


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="iocs")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity_weight: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    triggered_rules: Mapped[list["TriggeredRule"]] = relationship(back_populates="rule")


class TriggeredRule(Base):
    __tablename__ = "triggered_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("detection_rules.id"), nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    score_added: Mapped[int] = mapped_column(Integer, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="triggered_rules")
    rule: Mapped[DetectionRule | None] = relationship(back_populates="triggered_rules")


class AnalysisExplanation(Base):
    __tablename__ = "analysis_explanations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), unique=True, nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    verdict_suggestion: Mapped[str] = mapped_column(String(80), nullable=False)
    explanation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_items: Mapped[list] = mapped_column(JSON, default=list)
    triggered_rules: Mapped[list] = mapped_column(JSON, default=list)
    score_breakdown: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped[Incident] = relationship(back_populates="analysis_explanation")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    analyst_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped[Incident] = relationship(back_populates="notes")
    analyst: Mapped[User] = relationship(back_populates="notes")


class BECChecklistItem(Base):
    __tablename__ = "bec_checklist_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    item_key: Mapped[str] = mapped_column(String(80), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    completed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped[Incident] = relationship(back_populates="bec_checklist")


class IncidentFrameworkMapping(Base):
    __tablename__ = "incident_framework_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    framework: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    tactic: Mapped[str] = mapped_column(String(120), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(80), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(160), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped[Incident] = relationship(back_populates="framework_mappings")


class PlaybookTemplate(Base):
    __tablename__ = "playbook_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    action_key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    requires_integration_type: Mapped[str | None] = mapped_column(String(60), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    runs: Mapped[list["PlaybookRun"]] = relationship(back_populates="template")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    template_id: Mapped[int | None] = mapped_column(ForeignKey("playbook_templates.id"), nullable=True)
    action_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="Simulated", index=True)
    mode: Mapped[str] = mapped_column(String(40), default="simulation")
    action_results: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped[Incident] = relationship(back_populates="playbook_runs")
    template: Mapped[PlaybookTemplate | None] = relationship(back_populates="runs")


class BrandWatchlist(Base):
    __tablename__ = "brand_watchlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    brand_name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    legitimate_domains: Mapped[list] = mapped_column(JSON, default=list)
    keywords: Mapped[list] = mapped_column(JSON, default=list)
    logo_hint: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    generated_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped[Incident] = relationship(back_populates="reports")


class EnterpriseIntegration(Base):
    __tablename__ = "enterprise_integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), default="Not configured", index=True)
    config_summary: Mapped[str | None] = mapped_column(Text)
    last_result: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ThreatEnrichment(Base):
    __tablename__ = "threat_enrichments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    indicator_value: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(120), nullable=False)
    reputation: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CaseQueueItem(Base):
    __tablename__ = "case_queue_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), unique=True, nullable=False, index=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    priority: Mapped[str] = mapped_column(String(40), default="Medium", index=True)
    queue_status: Mapped[str] = mapped_column(String(40), default="Open", index=True)
    campaign_key: Mapped[str | None] = mapped_column(String(120), index=True)
    sla_due_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    incident: Mapped[Incident] = relationship()
    assigned_to: Mapped[User | None] = relationship()


class BulkImportJob(Base):
    __tablename__ = "bulk_import_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    file_name: Mapped[str | None] = mapped_column(String(255))
    submitted_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    campaign_key: Mapped[str | None] = mapped_column(String(120), index=True)
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    created_incidents: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(40), default="Completed", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SiemExport(Base):
    __tablename__ = "siem_exports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    destination: Mapped[str] = mapped_column(String(120), nullable=False)
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="Queued", index=True)
    payload_summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
