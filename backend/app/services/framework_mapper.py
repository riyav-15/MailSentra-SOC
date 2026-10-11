from sqlalchemy.orm import Session

from ..models import Incident, IncidentFrameworkMapping


def build_framework_mappings(parsed_email: dict, risk: dict) -> list[dict]:
    evidence_types = {item.get("type") for item in risk.get("evidence_items", [])}
    mappings = []

    def add(framework: str, tactic: str, technique_id: str, technique_name: str, confidence: int, reason: str) -> None:
        key = (framework, tactic, technique_id, technique_name)
        if any((item["framework"], item["tactic"], item["technique_id"], item["technique_name"]) == key for item in mappings):
            return
        mappings.append(
            {
                "framework": framework,
                "tactic": tactic,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "confidence": confidence,
                "reason": reason,
            }
        )

    if evidence_types & {"suspicious_url", "shortened_url", "ip_address_url", "qr_url", "qr_shortened_url"}:
        add(
            "MITRE ATT&CK",
            "Initial Access",
            "T1566.002",
            "Phishing: Spearphishing Link",
            78,
            "Message or QR payload contains suspicious links, shortened URLs, IP-address URLs, or mismatched visible links.",
        )
    if evidence_types & {"risky_attachment_extension"} or parsed_email.get("attachment_metadata"):
        add(
            "MITRE ATT&CK",
            "Initial Access",
            "T1566.001",
            "Phishing: Spearphishing Attachment",
            70,
            "Attachment metadata or risky extension was present. Files were hashed only and not executed.",
        )
    if evidence_types & {"credential_harvesting_keywords", "oauth_device_code"}:
        add(
            "MITRE ATT&CK",
            "Credential Access",
            "T1566",
            "Phishing",
            82,
            "Email includes credential, OTP, OAuth consent, or device-code language consistent with phishing tradecraft.",
        )
    if evidence_types & {"brand_impersonation", "lookalike_domain", "qr_brand_mismatch"}:
        add(
            "MITRE ATT&CK",
            "Resource Development",
            "T1583.001",
            "Acquire Infrastructure: Domains",
            65,
            "Observed domain or brand impersonation indicators suggest lookalike or brand-abuse infrastructure.",
        )
    if evidence_types & {"bec_payment_fraud"}:
        add(
            "MITRE ATT&CK",
            "Impact",
            "T1657",
            "Financial Theft",
            68,
            "Business email compromise or payment redirection language indicates potential financial fraud impact.",
        )

    for item in nist_lifecycle_sections_from_risk(risk):
        add(
            "NIST Incident Lifecycle",
            item["phase"],
            item["technique_id"],
            item["technique_name"],
            item["confidence"],
            item["reason"],
        )

    return mappings


def store_framework_mappings(db: Session, incident_id: int, parsed_email: dict, risk: dict) -> None:
    for mapping in build_framework_mappings(parsed_email, risk):
        db.add(IncidentFrameworkMapping(incident_id=incident_id, **mapping))


def nist_lifecycle_for_incident(incident: Incident) -> list[dict]:
    risk = {
        "severity": incident.severity,
        "score": incident.risk_score,
        "recommended_action": incident.recommended_action,
        "evidence_items": incident.analysis_explanation.evidence_items if incident.analysis_explanation else [],
    }
    return nist_lifecycle_sections_from_risk(risk)


def nist_lifecycle_sections_from_risk(risk: dict) -> list[dict]:
    severity = risk.get("severity") or "Low"
    score = risk.get("score") or risk.get("risk_score") or 0
    high_risk = severity in {"High", "Critical"} or score >= 61
    return [
        {
            "phase": "Detect",
            "technique_id": "NIST-IR-Detect",
            "technique_name": "Detection and Analysis",
            "confidence": 80,
            "reason": "IOC extraction, rule triggers, score contribution, and analyst triage establish detection evidence.",
            "recommended_work": "Validate sender, URLs, attachments, affected users, and campaign overlap.",
        },
        {
            "phase": "Respond",
            "technique_id": "NIST-IR-Respond",
            "technique_name": "Containment and Eradication",
            "confidence": 75 if high_risk else 60,
            "reason": "Recommended action is based on severity and observed phishing indicators.",
            "recommended_work": risk.get("recommended_action") or "Review the report and apply containment only if analyst review confirms risk.",
        },
        {
            "phase": "Recover",
            "technique_id": "NIST-IR-Recover",
            "technique_name": "Recovery and User Assurance",
            "confidence": 60,
            "reason": "Recovery should focus on account safety, user communication, and restoring normal mailbox state.",
            "recommended_work": "Confirm no credentials were entered, restore quarantined false positives, and document user impact.",
        },
        {
            "phase": "Lessons Learned",
            "technique_id": "NIST-IR-Lessons",
            "technique_name": "Post-Incident Improvement",
            "confidence": 55,
            "reason": "Campaign and rule outcomes can improve watchlists, awareness training, and controls.",
            "recommended_work": "Tune rules, update brand watchlists, capture campaign IOCs, and review response timing.",
        },
    ]
