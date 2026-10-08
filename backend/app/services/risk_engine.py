from .email_analyzer import (
    DEFAULT_RULES,
    calculate_risk_score,
    generate_detection_summary,
    parse_email,
    recommended_action,
    severity_from_score,
    verdict_from_score,
)


def analyze_raw_email(
    raw_email_text: str,
    disabled_rules: set[str] | None = None,
    rule_weights: dict[str, int] | None = None,
) -> dict:
    """
    Execute full end-to-end safe email analysis:
    1. Parse headers, MIME tree, body, indicators, and attachments safely.
    2. Evaluate heuristic rules across sender, URLs, content, attachments, and auth.
    3. Calculate normalized risk score, subscores, severity, and remediation guidance.
    """
    parsed = parse_email(raw_email_text)
    risk = calculate_risk_score(parsed, disabled_rules=disabled_rules, rule_weights=rule_weights)
    return {
        "parsed_email": parsed,
        "risk": risk,
    }


def get_risk_subscores(risk_result: dict) -> dict[str, int]:
    """Retrieve dimensional risk scores across sender, url, content, attachment, and auth."""
    return risk_result.get("subscores", {
        "sender": 0,
        "url": 0,
        "content": 0,
        "attachment": 0,
        "authentication": 0,
    })


def evaluate_threat_level(score: int) -> dict:
    """Classify threat level, color tier, and verdict suggestion."""
    severity = severity_from_score(score)
    verdict = verdict_from_score(score)
    colors = {
        "Low": "#16a34a",
        "Medium": "#d97706",
        "High": "#ea580c",
        "Critical": "#dc2626",
    }
    return {
        "score": score,
        "severity": severity,
        "verdict": verdict,
        "badge_color": colors.get(severity, "#64748b"),
        "is_actionable": score > 30,
    }
