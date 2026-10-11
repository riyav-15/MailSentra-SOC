"""Quishing, brand watchlist, and BEC workflow.

Revision ID: 0003_quishing_brand_bec
Revises: 0002_enterprise_explainability
Create Date: 2026-06-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_quishing_brand_bec"
down_revision = "0002_enterprise_explainability"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("suspected_bec", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("incidents", sa.Column("financial_risk_type", sa.String(length=120)))
    op.add_column("incidents", sa.Column("requested_amount", sa.String(length=120)))
    op.add_column("incidents", sa.Column("impersonated_person_or_vendor", sa.String(length=255)))
    op.create_index("ix_incidents_suspected_bec", "incidents", ["suspected_bec"])

    op.create_table(
        "bec_checklist_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("item_key", sa.String(length=80), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("completed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("completed_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("completed_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_bec_checklist_items_incident_id", "bec_checklist_items", ["incident_id"])

    op.create_table(
        "brand_watchlist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("brand_name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("legitimate_domains", sa.JSON(), nullable=False),
        sa.Column("keywords", sa.JSON(), nullable=False),
        sa.Column("logo_hint", sa.String(length=255)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_brand_watchlist_brand_name", "brand_watchlist", ["brand_name"])


def downgrade() -> None:
    op.drop_table("brand_watchlist")
    op.drop_table("bec_checklist_items")
    op.drop_index("ix_incidents_suspected_bec", table_name="incidents")
    op.drop_column("incidents", "impersonated_person_or_vendor")
    op.drop_column("incidents", "requested_amount")
    op.drop_column("incidents", "financial_risk_type")
    op.drop_column("incidents", "suspected_bec")
