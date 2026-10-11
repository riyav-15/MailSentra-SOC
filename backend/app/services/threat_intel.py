from urllib.parse import urlparse

from .email_analyzer import SUSPICIOUS_TLDS, URL_SHORTENERS


def enrich_indicator(indicator_type: str, value: str) -> dict:
    indicator_type = (indicator_type or "").lower()
    value = value or ""
    reputation = "Unknown"
    confidence = 45
    details = "No external lookup was performed. Local defensive heuristics were applied."

    if indicator_type == "url":
        hostname = urlparse(value if value.startswith(("http://", "https://")) else f"http://{value}").hostname or ""
        if _is_ip(hostname):
            reputation, confidence = "Suspicious", 78
            details = "URL uses a raw IP address host, which is common in phishing lures."
        elif hostname in URL_SHORTENERS:
            reputation, confidence = "Suspicious", 70
            details = "URL uses a known shortening service. Analyst review is recommended."
        elif any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            reputation, confidence = "Suspicious", 68
            details = "URL domain uses a top-level domain frequently seen in suspicious campaigns."
        else:
            reputation, confidence = "Unrated", 55
            details = "URL did not match local high-risk heuristics."

    elif indicator_type == "domain":
        if value in URL_SHORTENERS:
            reputation, confidence = "Suspicious", 70
            details = "Domain is a known URL shortener."
        elif any(value.endswith(tld) for tld in SUSPICIOUS_TLDS):
            reputation, confidence = "Suspicious", 68
            details = "Domain uses a suspicious top-level domain."
        elif "xn--" in value:
            reputation, confidence = "Suspicious", 72
            details = "Domain includes punycode, which can indicate brand impersonation."
        else:
            reputation, confidence = "Unrated", 55
            details = "Domain did not match local high-risk heuristics."

    elif indicator_type == "ip_address":
        reputation, confidence = ("Suspicious", 75) if _is_ip(value) else ("Unknown", 40)
        details = "IP address indicator requires external reputation provider review for final disposition."

    elif indicator_type == "sha256":
        reputation, confidence = "Unrated", 50
        details = "Attachment hash captured safely. Submit to an approved sandbox or threat intelligence provider if configured."

    elif indicator_type == "brand_signal":
        reputation, confidence = "Suspicious", 74
        details = "Known brand language appears without aligned sender or link domains."

    return {
        "indicator_type": indicator_type,
        "indicator_value": value,
        "provider": "Local Defensive Heuristics",
        "reputation": reputation,
        "confidence": confidence,
        "details": details,
    }


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
