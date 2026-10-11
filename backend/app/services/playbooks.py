from sqlalchemy.orm import Session

from ..models import EnterpriseIntegration, Incident, PlaybookRun, PlaybookTemplate, User


DEFAULT_PLAYBOOK_TEMPLATES = [
    (
        "block_domain",
        "Block domain",
        "Simulate adding suspicious domains or URLs to a mail/web security blocklist.",
        "siem",
    ),
    (
        "search_mailbox",
        "Search mailbox",
        "Simulate a mailbox search for related messages by sender, subject, campaign, and IOCs.",
        "email_gateway",
    ),
    (
        "notify_users",
        "Notify affected users",
        "Simulate a user notification workflow with defensive guidance.",
        "email_gateway",
    ),
    (
        "reset_password",
        "Reset password",
        "Simulate an identity-team handoff for password reset or session revocation.",
        "sso",
    ),
    (
        "escalate_ir",
        "Escalate to incident response",
        "Create an internal escalation record for higher-severity incidents.",
        None,
    ),
    (
        "export_siem",
        "Export to SIEM",
        "Simulate exporting incident and IOC details to a SIEM or webhook destination.",
        "siem",
    ),
]


def seed_playbook_templates(db: Session) -> None:
    existing = {item.action_key for item in db.query(PlaybookTemplate).all()}
    for action_key, name, description, integration_type in DEFAULT_PLAYBOOK_TEMPLATES:
        if action_key not in existing:
            db.add(
                PlaybookTemplate(
                    action_key=action_key,
                    name=name,
                    description=description,
                    requires_integration_type=integration_type,
                    enabled=True,
                )
            )


def run_playbook_simulation(db: Session, incident: Incident, template: PlaybookTemplate, user: User) -> PlaybookRun:
    integration_ready = _integration_ready(db, template.requires_integration_type)
    mode = "integration-ready-simulation" if integration_ready else "simulation"
    status = "Simulated"
    results = _simulated_results(incident, template, integration_ready)
    run = PlaybookRun(
        incident_id=incident.id,
        template_id=template.id,
        action_key=template.action_key,
        name=template.name,
        status=status,
        mode=mode,
        action_results=results,
        created_by=user.id,
    )
    db.add(run)
    db.flush()
    return run


def _integration_ready(db: Session, integration_type: str | None) -> bool:
    if not integration_type:
        return True
    return (
        db.query(EnterpriseIntegration)
        .filter(EnterpriseIntegration.type == integration_type, EnterpriseIntegration.status == "Active")
        .first()
        is not None
    )


def _simulated_results(incident: Incident, template: PlaybookTemplate, integration_ready: bool) -> list[dict]:
    iocs_by_type = {}
    for ioc in incident.iocs:
        iocs_by_type.setdefault(ioc.type, []).append(ioc.value)
    integration_note = (
        "Matching integration is active; this run still records a controlled simulation only."
        if integration_ready
        else "No active integration is configured, so no external action was attempted."
    )
    common = {"mode": "simulated", "integration_note": integration_note}

    if template.action_key == "block_domain":
        values = sorted(set(iocs_by_type.get("domain", []) + iocs_by_type.get("url", [])))[:12]
        return [{**common, "action": "blocklist_submission", "result": f"Would submit {len(values)} domain or URL indicators.", "values": values}]
    if template.action_key == "search_mailbox":
        return [
            {
                **common,
                "action": "mailbox_search",
                "result": "Would search mailboxes for matching sender, subject, campaign label, and extracted IOCs.",
                "values": [incident.email_report.sender, incident.email_report.subject],
            }
        ]
    if template.action_key == "notify_users":
        return [{**common, "action": "user_notification", "result": "Would notify affected users with safe reporting guidance.", "values": []}]
    if template.action_key == "reset_password":
        return [{**common, "action": "identity_handoff", "result": "Would request password reset/session review for confirmed exposed accounts.", "values": []}]
    if template.action_key == "escalate_ir":
        return [{**common, "action": "ir_escalation", "result": f"Would escalate Incident #{incident.id} with severity {incident.severity}.", "values": []}]
    if template.action_key == "export_siem":
        return [
            {
                **common,
                "action": "siem_export",
                "result": "Would export incident summary, framework mappings, and IOCs to SIEM.",
                "values": [f"incident:{incident.id}", f"risk:{incident.risk_score}"],
            }
        ]
    return [{**common, "action": template.action_key, "result": "Would record this defensive action.", "values": []}]
