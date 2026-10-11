from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserPublic"


class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return _normalize_email(value)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return _normalize_email(value)


class UserPublic(BaseModel):
    id: int
    name: str
    email: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserRoleUpdate(BaseModel):
    role: str = Field(pattern="^(employee|analyst|admin)$")


class EmailReportPublic(BaseModel):
    id: int
    reporter_id: int
    subject: str
    sender: str
    uploaded_file_name: str | None = None
    report_reason: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentPublic(BaseModel):
    id: int
    title: str
    email_report_id: int
    campaign_id: int | None = None
    assigned_analyst_id: int | None = None
    status: str
    severity: str
    verdict: str
    risk_score: int
    recommended_action: str | None = None
    suspected_bec: bool = False
    financial_risk_type: str | None = None
    requested_amount: str | None = None
    impersonated_person_or_vendor: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCPublic(BaseModel):
    id: int
    incident_id: int
    type: str
    value: str
    source: str

    model_config = ConfigDict(from_attributes=True)


class DetectionRulePublic(BaseModel):
    id: int
    name: str
    description: str
    severity_weight: int
    enabled: bool

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleUpdate(BaseModel):
    enabled: bool | None = None
    severity_weight: int | None = Field(default=None, ge=0, le=40)


class TriggeredRulePublic(BaseModel):
    id: int
    incident_id: int
    rule_id: int | None
    evidence: str
    score_added: int

    model_config = ConfigDict(from_attributes=True)


class ExplainableTriggeredRule(BaseModel):
    name: str
    rule_name: str
    evidence_type: str
    category: str
    matched_value: str
    reason: str
    score_impact: int
    score_added: int
    evidence: str
    explanation: str


class EvidenceItem(BaseModel):
    type: str
    category: str
    matched_value: str
    reason: str
    score_impact: int
    rule_name: str


class ScoreBreakdownItem(BaseModel):
    category: str
    score: int


class AnalysisExplanationPublic(BaseModel):
    id: int
    incident_id: int
    risk_score: int
    severity: str
    verdict_suggestion: str
    explanation_summary: str
    evidence_items: list[EvidenceItem]
    triggered_rules: list[ExplainableTriggeredRule]
    score_breakdown: list[ScoreBreakdownItem]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AnalystNoteCreate(BaseModel):
    note: str = Field(min_length=2, max_length=3000)


class AnalystNotePublic(BaseModel):
    id: int
    incident_id: int
    analyst_id: int
    note: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BECChecklistUpdate(BaseModel):
    completed: bool


class BrandWatchlistCreate(BaseModel):
    brand_name: str = Field(min_length=2, max_length=120)
    legitimate_domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    logo_hint: str | None = Field(default=None, max_length=255)


class BrandWatchlistUpdate(BaseModel):
    brand_name: str | None = Field(default=None, min_length=2, max_length=120)
    legitimate_domains: list[str] | None = None
    keywords: list[str] | None = None
    logo_hint: str | None = Field(default=None, max_length=255)


class BrandWatchlistPublic(BaseModel):
    id: int
    brand_name: str
    legitimate_domains: list[str]
    keywords: list[str]
    logo_hint: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CampaignMergeRequest(BaseModel):
    source_campaign_id: int


class CampaignPublic(BaseModel):
    id: int
    name: str
    label: str
    first_seen: datetime
    last_seen: datetime
    severity: str
    status: str
    related_incident_count: int
    primary_brand: str | None = None
    primary_sender_domain: str | None = None
    primary_url_domain: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FrameworkMappingPublic(BaseModel):
    id: int
    incident_id: int
    framework: str
    tactic: str
    technique_id: str
    technique_name: str
    confidence: int
    reason: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CopilotSummaryPublic(BaseModel):
    analyst_summary: str
    user_friendly_explanation: str
    suggested_next_steps: list[str]
    containment_checklist: list[str]
    limitations_disclaimer: str
    safety_notes: list[str]


class PlaybookRunRequest(BaseModel):
    template_id: int | None = None
    action_key: str | None = Field(default=None, max_length=80)


class PlaybookTemplatePublic(BaseModel):
    id: int
    action_key: str
    name: str
    description: str
    requires_integration_type: str | None = None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookRunPublic(BaseModel):
    id: int
    incident_id: int
    template_id: int | None = None
    action_key: str
    name: str
    status: str
    mode: str
    action_results: list[dict[str, Any]]
    created_by: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentFieldUpdate(BaseModel):
    value: str


class AuditLogPublic(BaseModel):
    id: int
    user_id: int | None
    action: str
    details: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportPublic(BaseModel):
    id: int
    incident_id: int
    file_path: str
    generated_by: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EnterpriseIntegrationPublic(BaseModel):
    id: int
    name: str
    type: str
    status: str
    config_summary: str | None = None
    last_result: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EnterpriseIntegrationUpdate(BaseModel):
    status: str | None = Field(default=None, max_length=40)
    config_summary: str | None = Field(default=None, max_length=2000)
    last_result: str | None = Field(default=None, max_length=2000)


class CaseQueueUpdate(BaseModel):
    assigned_to_id: int | None = None
    priority: str | None = Field(default=None, pattern="^(Low|Medium|High|Critical)$")
    queue_status: str | None = Field(default=None, pattern="^(Open|In Progress|Waiting|Closed)$")
    campaign_key: str | None = Field(default=None, max_length=120)
    sla_hours: int | None = Field(default=None, ge=1, le=720)


class BulkImportRequest(BaseModel):
    campaign_key: str | None = Field(default=None, max_length=120)
    raw_batch_text: str = Field(min_length=10)


class SiemExportRequest(BaseModel):
    incident_id: int | None = None
    destination: str = Field(min_length=2, max_length=120)
    format: str = Field(pattern="^(json|webhook|syslog)$")


class DashboardSummary(BaseModel):
    totals: dict[str, int]
    by_status: list[dict[str, Any]]
    by_severity: list[dict[str, Any]]
    top_sender_domains: list[dict[str, Any]]
    top_triggered_rules: list[dict[str, Any]]
    top_impersonated_brands: list[dict[str, Any]]
    recent_incidents: list[dict[str, Any]]


class ExecutiveDashboardSummary(BaseModel):
    totals: dict[str, Any]
    reports_over_time: list[dict[str, Any]]
    top_targeted_brands: list[dict[str, Any]]
    top_sender_domains: list[dict[str, Any]]
    campaigns_by_severity: list[dict[str, Any]]
    sla_breaches: list[dict[str, Any]]


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    local_part, separator, domain = email.partition("@")
    if not separator or not local_part or not domain or "." not in domain:
        raise ValueError("Enter a valid email address")
    return email


Token.model_rebuild()
