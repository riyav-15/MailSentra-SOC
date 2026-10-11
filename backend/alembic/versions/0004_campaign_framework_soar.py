"""Campaign correlation, framework mapping, copilot, and playbooks.

Revision ID: 0004_campaign_framework_soar
Revises: 0003_quishing_brand_bec
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_campaign_framework_soar"
down_revision = "0003_quishing_brand_bec"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("label", sa.String(length=160), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("severity", sa.String(length=40), nullable=False, server_default="Low"),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="Open"),
        sa.Column("related_incident_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("primary_brand", sa.String(length=120)),
        sa.Column("primary_sender_domain", sa.String(length=255)),
        sa.Column("primary_url_domain", sa.String(length=255)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_campaigns_name", "campaigns", ["name"])
    op.create_index("ix_campaigns_label", "campaigns", ["label"])
    op.create_index("ix_campaigns_last_seen", "campaigns", ["last_seen"])
    op.create_index("ix_campaigns_severity", "campaigns", ["severity"])
    op.create_index("ix_campaigns_status", "campaigns", ["status"])
    op.create_index("ix_campaigns_primary_brand", "campaigns", ["primary_brand"])
    op.create_index("ix_campaigns_primary_sender_domain", "campaigns", ["primary_sender_domain"])
    op.create_index("ix_campaigns_primary_url_domain", "campaigns", ["primary_url_domain"])

    op.add_column("incidents", sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=True))
    op.create_index("ix_incidents_campaign_id", "incidents", ["campaign_id"])

    op.create_table(
        "incident_framework_mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("framework", sa.String(length=80), nullable=False),
        sa.Column("tactic", sa.String(length=120), nullable=False),
        sa.Column("technique_id", sa.String(length=80), nullable=False),
        sa.Column("technique_name", sa.String(length=160), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_incident_framework_mappings_incident_id", "incident_framework_mappings", ["incident_id"])
    op.create_index("ix_incident_framework_mappings_framework", "incident_framework_mappings", ["framework"])

    op.create_table(
        "playbook_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("action_key", sa.String(length=80), nullable=False, unique=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("requires_integration_type", sa.String(length=60)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_playbook_templates_action_key", "playbook_templates", ["action_key"])
    op.create_index("ix_playbook_templates_requires_integration_type", "playbook_templates", ["requires_integration_type"])

    op.create_table(
        "playbook_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("template_id", sa.Integer(), sa.ForeignKey("playbook_templates.id")),
        sa.Column("action_key", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="Simulated"),
        sa.Column("mode", sa.String(length=40), nullable=False, server_default="simulation"),
        sa.Column("action_results", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_playbook_runs_incident_id", "playbook_runs", ["incident_id"])
    op.create_index("ix_playbook_runs_action_key", "playbook_runs", ["action_key"])
    op.create_index("ix_playbook_runs_status", "playbook_runs", ["status"])
    op.create_index("ix_playbook_runs_created_by", "playbook_runs", ["created_by"])


def downgrade() -> None:
    op.drop_table("playbook_runs")
    op.drop_table("playbook_templates")
    op.drop_table("incident_framework_mappings")
    op.drop_index("ix_incidents_campaign_id", table_name="incidents")
    op.drop_column("incidents", "campaign_id")
    op.drop_table("campaigns")
