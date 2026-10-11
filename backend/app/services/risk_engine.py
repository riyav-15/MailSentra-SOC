from .email_analyzer import DEFAULT_RULES, calculate_risk_score, generate_detection_summary, parse_email


def analyze_raw_email(
    raw_email_text: str,
    disabled_rules: set[str] | None = None,
    rule_weights: dict[str, int] | None = None,
    extra_qr_payloads: list[dict] | None = None,
    brand_profiles: dict | None = None,
) -> dict:
    parsed = parse_email(raw_email_text, extra_qr_payloads=extra_qr_payloads, brand_profiles=brand_profiles)
    risk = calculate_risk_score(parsed, disabled_rules=disabled_rules, rule_weights=rule_weights)
    return {"parsed_email": parsed, "risk": risk}
