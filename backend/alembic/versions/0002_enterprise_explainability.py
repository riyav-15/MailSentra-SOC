"""Enterprise operations and explainable analysis.

Revision ID: 0002_enterprise_explainability
Revises: 0001_initial
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_enterprise_explainability"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_explanations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False, unique=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=40), nullable=False),
        sa.Column("verdict_suggestion", sa.String(length=80), nullable=False),
        sa.Column("explanation_summary", sa.Text(), nullable=False),
        sa.Column("evidence_items", sa.JSON(), nullable=False),
        sa.Column("triggered_rules", sa.JSON(), nullable=False),
        sa.Column("score_breakdown", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_analysis_explanations_incident_id", "analysis_explanations", ["incident_id"])

    op.create_table(
        "enterprise_integrations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("type", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("config_summary", sa.Text()),
        sa.Column("last_result", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_enterprise_integrations_name", "enterprise_integrations", ["name"])
    op.create_index("ix_enterprise_integrations_type", "enterprise_integrations", ["type"])
    op.create_index("ix_enterprise_integrations_status", "enterprise_integrations", ["status"])

    op.create_table(
        "threat_enrichments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id")),
        sa.Column("indicator_type", sa.String(length=60), nullable=False),
        sa.Column("indicator_value", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(length=120), nullable=False),
        sa.Column("reputation", sa.String(length=40), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_threat_enrichments_incident_id", "threat_enrichments", ["incident_id"])
    op.create_index("ix_threat_enrichments_indicator_type", "threat_enrichments", ["indicator_type"])
    op.create_index("ix_threat_enrichments_reputation", "threat_enrichments", ["reputation"])

    op.create_table(
        "case_queue_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False, unique=True),
        sa.Column("assigned_to_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("priority", sa.String(length=40), nullable=False),
        sa.Column("queue_status", sa.String(length=40), nullable=False),
        sa.Column("campaign_key", sa.String(length=120)),
        sa.Column("sla_due_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_case_queue_items_incident_id", "case_queue_items", ["incident_id"])
    op.create_index("ix_case_queue_items_assigned_to_id", "case_queue_items", ["assigned_to_id"])
    op.create_index("ix_case_queue_items_priority", "case_queue_items", ["priority"])
    op.create_index("ix_case_queue_items_queue_status", "case_queue_items", ["queue_status"])
    op.create_index("ix_case_queue_items_campaign_key", "case_queue_items", ["campaign_key"])

    op.create_table(
        "bulk_import_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("file_name", sa.String(length=255)),
        sa.Column("submitted_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("campaign_key", sa.String(length=120)),
        sa.Column("total_records", sa.Integer(), nullable=False),
        sa.Column("created_incidents", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_bulk_import_jobs_submitted_by", "bulk_import_jobs", ["submitted_by"])
    op.create_index("ix_bulk_import_jobs_campaign_key", "bulk_import_jobs", ["campaign_key"])
    op.create_index("ix_bulk_import_jobs_status", "bulk_import_jobs", ["status"])

    op.create_table(
        "siem_exports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id")),
        sa.Column("destination", sa.String(length=120), nullable=False),
        sa.Column("format", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("payload_summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_siem_exports_incident_id", "siem_exports", ["incident_id"])
    op.create_index("ix_siem_exports_status", "siem_exports", ["status"])


def downgrade() -> None:
    for table in [
        "siem_exports",
        "bulk_import_jobs",
        "case_queue_items",
        "threat_enrichments",
        "enterprise_integrations",
        "analysis_explanations",
    ]:
        op.drop_table(table)
