from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine
from .models import DetectionRule, User
from .routers import admin, auth, campaigns, dashboard, enterprise, incidents, reports
from .security import get_password_hash, settings
from .services.brand_watchlist import seed_brand_watchlist
from .services.email_analyzer import DEFAULT_RULES
from .services.playbooks import seed_playbook_templates

app = FastAPI(title="PhishGuard SOC API", version="1.0.0")

origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_runtime_schema()
    with SessionLocal() as db:
        seed_detection_rules(db)
        seed_demo_users(db)
        seed_brand_watchlist(db, settings.college_domain or None, settings.college_name or None)
        seed_playbook_templates(db)
        enterprise.seed_enterprise_integrations(db)
        db.commit()


@app.get("/")
def health_check():
    return {"name": settings.app_name, "status": "ok", "mode": "defensive-analysis-only"}


app.include_router(auth.router)
app.include_router(reports.router)
app.include_router(incidents.router)
app.include_router(campaigns.router)
app.include_router(admin.router)
app.include_router(dashboard.router)
app.include_router(enterprise.router)


def seed_detection_rules(db: Session) -> None:
    existing = {rule.name for rule in db.query(DetectionRule).all()}
    for rule in DEFAULT_RULES:
        if rule["name"] not in existing:
            db.add(
                DetectionRule(
                    name=rule["name"],
                    description=rule["description"],
                    severity_weight=rule["severity_weight"],
                    enabled=True,
                )
            )


def seed_demo_users(db: Session) -> None:
    demo_users = [
        ("Admin User", "admin@phishguard.local", "AdminPass123!", "admin"),
        ("SOC Analyst", "analyst@phishguard.local", "AnalystPass123!", "analyst"),
        ("Employee User", "employee@phishguard.local", "EmployeePass123!", "employee"),
    ]
    existing = {user.email for user in db.query(User).filter(User.email.in_([item[1] for item in demo_users])).all()}
    for name, email, password, role in demo_users:
        if email not in existing:
            db.add(User(name=name, email=email, password_hash=get_password_hash(password), role=role))


def ensure_runtime_schema() -> None:
    inspector = inspect(engine)
    if "incidents" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("incidents")}
    dialect = engine.dialect.name
    columns = {
        "campaign_id": {
            "sqlite": "ALTER TABLE incidents ADD COLUMN campaign_id INTEGER",
            "postgresql": "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_id INTEGER",
        },
        "suspected_bec": {
            "sqlite": "ALTER TABLE incidents ADD COLUMN suspected_bec BOOLEAN DEFAULT 0",
            "postgresql": "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS suspected_bec BOOLEAN DEFAULT false",
        },
        "financial_risk_type": {
            "sqlite": "ALTER TABLE incidents ADD COLUMN financial_risk_type VARCHAR(120)",
            "postgresql": "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS financial_risk_type VARCHAR(120)",
        },
        "requested_amount": {
            "sqlite": "ALTER TABLE incidents ADD COLUMN requested_amount VARCHAR(120)",
            "postgresql": "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS requested_amount VARCHAR(120)",
        },
        "impersonated_person_or_vendor": {
            "sqlite": "ALTER TABLE incidents ADD COLUMN impersonated_person_or_vendor VARCHAR(255)",
            "postgresql": "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS impersonated_person_or_vendor VARCHAR(255)",
        },
    }
    with engine.begin() as connection:
        for column_name, statements in columns.items():
            if column_name not in existing:
                statement = statements.get(dialect)
                if statement:
                    connection.execute(text(statement))
