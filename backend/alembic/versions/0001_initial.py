"""Initial PhishGuard SOC schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_table(
        "email_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("reporter_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("sender", sa.String(length=255), nullable=False),
        sa.Column("raw_email_text", sa.Text(), nullable=False),
        sa.Column("uploaded_file_name", sa.String(length=255)),
        sa.Column("report_reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity_weight", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("email_report_id", sa.Integer(), sa.ForeignKey("email_reports.id"), nullable=False, unique=True),
        sa.Column("assigned_analyst_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("severity", sa.String(length=40), nullable=False),
        sa.Column("verdict", sa.String(length=80), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("recommended_action", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("type", sa.String(length=60), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
    )
    op.create_table(
        "triggered_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("detection_rules.id")),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("score_added", sa.Integer(), nullable=False),
    )
    op.create_table(
        "analyst_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("analyst_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("file_path", sa.String(length=500), nullable=False),
        sa.Column("generated_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    for table in [
        "reports",
        "audit_logs",
        "analyst_notes",
        "triggered_rules",
        "iocs",
        "incidents",
        "detection_rules",
        "email_reports",
        "users",
    ]:
        op.drop_table(table)
