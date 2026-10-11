import ipaddress
import hashlib
import re
from email import policy
from email.parser import Parser
from html import unescape
from urllib.parse import urlparse

from .qr_analyzer import extract_qr_payloads_from_bytes


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}

SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".xyz", ".icu", ".click", ".country", ".gq", ".tk"}
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".iso", ".lnk", ".hta"}

BRAND_PROFILES = {
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "office365.com"},
    "google": {"google.com", "gmail.com", "accounts.google.com"},
    "paypal": {"paypal.com", "paypalobjects.com"},
    "netflix": {"netflix.com", "nflxext.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com"},
    "amazon": {"amazon.com", "amazonaws.com"},
    "apple": {"apple.com", "icloud.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "chase": {"chase.com", "jpmorgan.com"},
    "wells fargo": {"wellsfargo.com"},
    "citibank": {"citi.com", "citibank.com"},
    "hdfc bank": {"hdfcbank.com"},
    "icici bank": {"icicibank.com"},
    "state bank of india": {"sbi.co.in", "onlinesbi.sbi"},
}

KEYWORD_CATEGORIES = {
    "urgent_language": [
        "urgent",
        "immediately",
        "act now",
        "final notice",
        "last warning",
        "account suspended",
        "verify now",
    ],
    "password_reset_language": [
        "password reset",
        "reset your password",
        "change your password",
        "account verification",
    ],
    "payment_invoice_language": [
        "invoice",
        "payment due",
        "wire transfer",
        "bank details",
        "overdue",
        "purchase order",
    ],
    "prize_gift_language": [
        "gift card",
        "winner",
        "you have won",
        "claim your prize",
        "reward",
        "bonus payout",
    ],
    "credential_otp_request": [
        "login credentials",
        "one-time password",
        "otp",
        "security code",
        "enter your password",
        "verify your identity",
    ],
    "oauth_device_code": [
        "device code",
        "device login",
        "enter this code",
        "approve sign in",
        "grant access",
        "oauth",
        "consent required",
        "aka.ms/devicelogin",
        "microsoft.com/devicelogin",
    ],
    "bec_payment_fraud": [
        "wire transfer",
        "routing number",
        "ach",
        "bank details",
        "payment instructions",
        "change of bank",
        "bank account change",
        "vendor payment",
        "vendor payment update",
        "remittance",
        "swift code",
        "gift card",
        "gift cards",
        "ceo",
        "cfo",
    ],
    "generic_greeting": ["dear user", "dear customer", "hello user", "valued customer"],
}

DEFAULT_RULES = [
    {
        "name": "Sender domain mismatch",
        "description": "From, Reply-To, or Return-Path domains do not align.",
        "severity_weight": 12,
    },
    {"name": "Reply-To mismatch", "description": "Reply-To domain differs from From domain.", "severity_weight": 10},
    {"name": "URL shortener detected", "description": "Email includes a known URL shortener.", "severity_weight": 12},
    {"name": "IP address URL", "description": "A link uses an IP address instead of a domain name.", "severity_weight": 14},
    {"name": "Excessive links", "description": "Email contains an unusually high number of URLs.", "severity_weight": 8},
    {"name": "Urgent language", "description": "Email uses urgency or pressure tactics.", "severity_weight": 8},
    {
        "name": "Password reset language",
        "description": "Email references password reset or account verification.",
        "severity_weight": 10,
    },
    {
        "name": "Payment or invoice language",
        "description": "Email references payment, invoice, or banking action.",
        "severity_weight": 8,
    },
    {"name": "Prize or gift language", "description": "Email references prizes, rewards, or gift cards.", "severity_weight": 8},
    {
        "name": "Risky attachment",
        "description": "Attachment has an extension commonly abused in malware delivery.",
        "severity_weight": 18,
    },
    {"name": "Failed SPF", "description": "Headers indicate SPF failed or soft-failed.", "severity_weight": 12},
    {"name": "Failed DKIM", "description": "Headers indicate DKIM failed.", "severity_weight": 10},
    {"name": "Failed DMARC", "description": "Headers indicate DMARC failed.", "severity_weight": 12},
    {"name": "Missing SPF", "description": "Headers did not provide an SPF authentication result.", "severity_weight": 4},
    {"name": "Missing DKIM", "description": "Headers did not provide a DKIM authentication result.", "severity_weight": 4},
    {"name": "Missing DMARC", "description": "Headers did not provide a DMARC authentication result.", "severity_weight": 4},
    {
        "name": "Mismatched visible URL",
        "description": "Visible link text appears to point to a different domain than the actual href.",
        "severity_weight": 16,
    },
    {
        "name": "Suspicious top-level domain",
        "description": "A URL domain uses a TLD commonly seen in suspicious campaigns.",
        "severity_weight": 9,
    },
    {
        "name": "Unicode or punycode domain",
        "description": "Domain includes Unicode or punycode indicators that may support impersonation.",
        "severity_weight": 10,
    },
    {
        "name": "Lookalike domain",
        "description": "Domain appears visually similar to a known brand domain.",
        "severity_weight": 14,
    },
    {
        "name": "Excessive capitalization",
        "description": "Body contains a high proportion of uppercase words.",
        "severity_weight": 5,
    },
    {"name": "Generic greeting", "description": "Email uses a generic greeting.", "severity_weight": 6},
    {
        "name": "Credential or OTP request",
        "description": "Email asks for credentials, codes, or identity verification.",
        "severity_weight": 16,
    },
    {
        "name": "OAuth or device-code phishing",
        "description": "Email asks the user to approve access, enter a device code, or grant OAuth consent.",
        "severity_weight": 18,
    },
    {
        "name": "BEC or payment fraud indicators",
        "description": "Email includes payment-routing or business email compromise language.",
        "severity_weight": 16,
    },
    {
        "name": "QR code contains URL",
        "description": "A QR code payload contains a URL. The URL was extracted locally and not visited.",
        "severity_weight": 10,
    },
    {
        "name": "QR code shortened URL",
        "description": "A QR code points to a known URL shortener.",
        "severity_weight": 12,
    },
    {
        "name": "QR brand domain mismatch",
        "description": "QR payload references a known brand but points to an unapproved domain.",
        "severity_weight": 14,
    },
    {
        "name": "QR credential or payment terms",
        "description": "QR payload contains login, credential, or payment terms.",
        "severity_weight": 12,
    },
    {
        "name": "Brand impersonation signal",
        "description": "Email references a known brand while sender and link domains do not align with that brand.",
        "severity_weight": 14,
    },
]


def _normalize_domain(value: str | None) -> str:
    if not value:
        return ""
    if "@" in value:
        value = value.split("@")[-1]
    value = value.strip().strip("<>").lower()
    return value.rstrip(".")


def _domain_from_email(value: str | None) -> str:
    matches = extract_email_addresses(value or "")
    if matches:
        return _normalize_domain(matches[0])
    return _normalize_domain(value)


def _message_body(message) -> str:
    body_parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            if content_type in {"text/plain", "text/html"}:
                try:
                    body_parts.append(str(part.get_content()))
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode(errors="ignore"))
    else:
        try:
            body_parts.append(str(message.get_content()))
        except Exception:
            body_parts.append(message.get_payload(decode=True).decode(errors="ignore"))
    return "\n".join(body_parts)


def parse_email(
    raw_email_text: str,
    extra_qr_payloads: list[dict] | None = None,
    brand_profiles: dict | None = None,
) -> dict:
    """Parse email text safely. Attachments are named only and are never opened or executed."""
    message = Parser(policy=policy.default).parsestr(raw_email_text or "")
    headers = {key.lower(): str(value) for key, value in message.items()}
    received_headers = [str(value) for key, value in message.items() if key.lower() == "received"]
    body = _message_body(message)
    attachment_names = []
    attachment_metadata = []
    qr_payloads = list(extra_qr_payloads or [])

    if message.is_multipart():
        for part in message.walk():
            filename = part.get_filename()
            if filename:
                attachment_names.append(filename)
                payload = part.get_payload(decode=True) or b""
                attachment_metadata.append(
                    {
                        "file_name": filename,
                        "content_type": part.get_content_type(),
                        "size_bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                    }
                )
                qr_payloads.extend(extract_qr_payloads_from_bytes(payload, filename, part.get_content_type()))

    text_for_iocs = f"{raw_email_text}\n{body}"
    urls = extract_urls(text_for_iocs)
    domains = extract_domains(urls)
    ips = extract_ips(text_for_iocs)
    email_addresses = extract_email_addresses(text_for_iocs)
    attachment_extensions = sorted({_extension(name) for name in attachment_names if _extension(name)})
    qr_urls = sorted({item["payload"] for item in qr_payloads if item.get("is_url")})
    qr_domains = sorted({item["domain"] for item in qr_payloads if item.get("domain")})

    return {
        "from_address": headers.get("from", ""),
        "reply_to": headers.get("reply-to", ""),
        "return_path": headers.get("return-path", ""),
        "subject": headers.get("subject", ""),
        "received_headers": received_headers,
        "headers": headers,
        "body": body,
        "urls": urls,
        "domains": domains,
        "ip_addresses": ips,
        "email_addresses": email_addresses,
        "attachment_names": attachment_names,
        "attachment_metadata": attachment_metadata,
        "attachment_extensions": attachment_extensions,
        "header_auth_results": detect_header_auth_results(headers),
        "suspicious_keywords": detect_suspicious_keywords(text_for_iocs),
        "risky_attachments": detect_risky_attachments(attachment_names),
        "mismatched_visible_urls": detect_mismatched_visible_urls(raw_email_text),
        "qr_payloads": qr_payloads,
        "qr_urls": qr_urls,
        "qr_domains": qr_domains,
        "qr_brand_mismatches": detect_qr_brand_mismatch(qr_payloads, body, headers, brand_profiles),
        "brand_impersonation": detect_brand_impersonation(text_for_iocs, domains + qr_domains, headers, brand_profiles),
        "lookalike_domains": detect_lookalike_domains(domains + qr_domains, brand_profiles),
        "bec_analysis": detect_bec_indicators(text_for_iocs, headers),
    }


def extract_urls(text: str) -> list[str]:
    text = text or ""
    urls = re.findall(r"https?://[^\s<>'\")]+|www\.[^\s<>'\")]+", text, flags=re.IGNORECASE)
    hrefs = re.findall(r"href=[\"']([^\"']+)[\"']", text, flags=re.IGNORECASE)
    combined = urls + [href for href in hrefs if href.lower().startswith(("http://", "https://"))]
    return sorted({url.rstrip(".,;]}>") for url in combined})


def extract_domains(urls: list[str]) -> list[str]:
    domains: set[str] = set()
    for url in urls:
        candidate = url if url.lower().startswith(("http://", "https://")) else f"http://{url}"
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        if hostname:
            domains.add(hostname.lower().rstrip("."))
    return sorted(domains)


def extract_ips(text: str) -> list[str]:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    valid_ips = set()
    for candidate in candidates:
        try:
            valid_ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return sorted(valid_ips)


def extract_email_addresses(text: str) -> list[str]:
    matches = re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text or "", flags=re.IGNORECASE)
    return sorted({match.lower() for match in matches})


def detect_header_auth_results(headers: dict) -> dict[str, str]:
    joined = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
    results = {"spf": "not_found", "dkim": "not_found", "dmarc": "not_found"}
    for mechanism in results:
        match = re.search(rf"\b{mechanism}\s*=\s*([a-zA-Z]+)", joined)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def detect_suspicious_keywords(text: str) -> dict[str, list[str]]:
    lowered = (text or "").lower()
    findings: dict[str, list[str]] = {}
    for category, keywords in KEYWORD_CATEGORIES.items():
        hits = sorted({keyword for keyword in keywords if keyword in lowered})
        if hits:
            findings[category] = hits
    return findings


def detect_risky_attachments(file_names: list[str]) -> list[dict[str, str]]:
    risky = []
    for name in file_names:
        extension = _extension(name)
        if extension in RISKY_EXTENSIONS:
            risky.append({"file_name": name, "extension": extension})
    return risky


def detect_mismatched_visible_urls(text: str) -> list[dict[str, str]]:
    findings = []
    anchor_pattern = re.compile(r"<a\s+[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
    for href, visible in anchor_pattern.findall(text or ""):
        visible_text = re.sub(r"<[^>]+>", "", unescape(visible)).strip()
        visible_urls = extract_urls(visible_text)
        if not visible_urls:
            continue
        href_domain = extract_domains([href])
        visible_domain = extract_domains([visible_urls[0]])
        if href_domain and visible_domain and href_domain[0] != visible_domain[0]:
            findings.append({"visible": visible_urls[0], "actual": href})
    return findings


def detect_brand_impersonation(
    text: str,
    domains: list[str],
    headers: dict,
    brand_profiles: dict | None = None,
) -> list[dict[str, str]]:
    profiles = normalize_brand_profiles(brand_profiles)
    lowered = (text or "").lower()
    sender_domain = _domain_from_email(headers.get("from"))
    findings = []
    observed_domains = set(domains)
    if sender_domain:
        observed_domains.add(sender_domain)

    for brand, profile in profiles.items():
        keywords = {brand, *profile["keywords"]}
        if not any(keyword and keyword.lower() in lowered for keyword in keywords):
            continue
        allowed_domains = profile["domains"]
        aligned = any(
            is_legitimate_domain(domain, allowed_domain)
            for domain in observed_domains
            for allowed_domain in allowed_domains
        )
        if not aligned:
            findings.append(
                {
                    "brand": brand,
                    "sender_domain": sender_domain or "unknown",
                    "observed_domains": ", ".join(sorted(observed_domains)) or "none",
                }
            )
    return findings


def detect_lookalike_domains(domains: list[str], brand_profiles: dict | None = None) -> list[dict[str, str]]:
    profiles = normalize_brand_profiles(brand_profiles)
    findings = []
    for domain in domains:
        normalized_domain = normalize_domain_for_comparison(domain)
        label = normalized_domain.split(".")[0]
        for brand, profile in profiles.items():
            allowed_domains = profile["domains"]
            if any(is_legitimate_domain(domain, allowed) for allowed in allowed_domains):
                continue
            brand_token = normalize_domain_for_comparison(brand).replace(" ", "")
            keywords = {normalize_domain_for_comparison(keyword).replace(" ", "") for keyword in profile["keywords"]}
            keywords.add(brand_token)
            allowed_labels = {normalize_domain_for_comparison(allowed).split(".")[0] for allowed in allowed_domains}

            if any(keyword and keyword in normalized_domain for keyword in keywords):
                findings.append({"domain": domain, "brand": brand, "reason": "Domain contains a brand keyword but is not an approved brand domain."})
                break

            if any(levenshtein_distance(label, allowed_label) <= 2 for allowed_label in allowed_labels if len(allowed_label) >= 5):
                findings.append({"domain": domain, "brand": brand, "reason": "Domain is a close edit-distance match to a legitimate brand domain."})
                break

            if any(label.endswith(allowed_label) and label != allowed_label for allowed_label in allowed_labels):
                findings.append({"domain": domain, "brand": brand, "reason": "Subdomain or label structure appears to abuse a legitimate brand domain."})
                break
    return findings


def normalize_brand_profiles(brand_profiles: dict | None = None) -> dict[str, dict[str, set[str]]]:
    source = brand_profiles or BRAND_PROFILES
    profiles = {}
    for brand, value in source.items():
        if isinstance(value, dict):
            domains = set(value.get("domains") or value.get("legitimate_domains") or [])
            keywords = set(value.get("keywords") or [])
        else:
            domains = set(value)
            keywords = set()
        profiles[brand.lower()] = {
            "domains": {domain.lower().rstrip(".") for domain in domains},
            "keywords": {keyword.lower() for keyword in keywords} | {brand.lower()},
        }
    return profiles


def normalize_domain_for_comparison(value: str) -> str:
    value = (value or "").lower().strip().rstrip(".")
    try:
        value = value.encode("ascii").decode("idna")
    except UnicodeError:
        pass
    replacements = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "@": "a",
            "а": "a",
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "х": "x",
            "і": "i",
            "ӏ": "l",
        }
    )
    return value.translate(replacements).replace("-", "")


def is_legitimate_domain(domain: str, allowed_domain: str) -> bool:
    domain = (domain or "").lower().rstrip(".")
    allowed_domain = (allowed_domain or "").lower().rstrip(".")
    return domain == allowed_domain or domain.endswith(f".{allowed_domain}")


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def detect_bec_indicators(text: str, headers: dict) -> dict:
    lowered = (text or "").lower()
    checks = {
        "invoice_fraud": ["invoice", "payment due", "overdue", "remittance"],
        "bank_account_change": ["bank account change", "change of bank", "new account", "routing number", "swift code"],
        "gift_card_request": ["gift card", "gift cards", "itunes card", "steam card"],
        "executive_impersonation": ["ceo", "cfo", "chief executive", "chief financial", "president"],
        "urgent_wire_transfer": ["urgent wire", "wire transfer", "same day transfer", "send funds"],
        "vendor_payment_update": ["vendor payment", "payment instructions", "ach", "update payment"],
    }
    hits = {
        key: [term for term in terms if term in lowered]
        for key, terms in checks.items()
    }
    hits = {key: terms for key, terms in hits.items() if terms}
    amount_match = re.search(r"(?:\$|usd\s*)\s?([0-9][0-9,]*(?:\.[0-9]{2})?)", text or "", flags=re.IGNORECASE)
    vendor_match = re.search(r"(?:vendor|supplier|from)\s*[:\-]?\s*([A-Z][A-Za-z0-9 &.,'-]{2,80})", text or "")
    from_header = headers.get("from", "")
    return {
        "suspected_bec": bool(hits),
        "financial_risk_type": ", ".join(key.replace("_", " ") for key in hits) or None,
        "requested_amount": amount_match.group(0).strip() if amount_match else None,
        "impersonated_person_or_vendor": vendor_match.group(1).strip() if vendor_match else from_header or None,
        "indicators": [
            {"type": key, "matched_terms": terms, "reason": f"Matched BEC terms: {', '.join(terms)}."}
            for key, terms in hits.items()
        ],
    }


def detect_qr_brand_mismatch(
    qr_payloads: list[dict],
    body: str,
    headers: dict,
    brand_profiles: dict | None = None,
) -> list[dict[str, str]]:
    profiles = normalize_brand_profiles(brand_profiles)
    text = f"{body or ''}\n{headers.get('subject', '')}".lower()
    findings = []
    for payload in qr_payloads:
        domain = payload.get("domain")
        if not domain:
            continue
        payload_text = payload.get("payload", "").lower()
        combined = f"{text}\n{payload_text}"
        for brand, profile in profiles.items():
            keywords = {brand, *profile["keywords"]}
            if not any(keyword and keyword in combined for keyword in keywords):
                continue
            if any(is_legitimate_domain(domain, allowed) for allowed in profile["domains"]):
                continue
            findings.append({"brand": brand, "domain": domain, "payload": payload.get("payload", "")})
    return findings


def calculate_risk_score(
    parsed_email: dict,
    disabled_rules: set[str] | None = None,
    rule_weights: dict[str, int] | None = None,
) -> dict:
    disabled_rules = disabled_rules or set()
    triggered: list[dict] = []
    evidence_items: list[dict] = []
    default_weights = {rule["name"]: rule["severity_weight"] for rule in DEFAULT_RULES}
    descriptions = {rule["name"]: rule["description"] for rule in DEFAULT_RULES}
    if rule_weights:
        default_weights.update(rule_weights)

    def add_rule(
        name: str,
        evidence_type: str,
        matched_value: str,
        reason: str,
        category: str,
        weight: int | None = None,
    ) -> None:
        if name in disabled_rules:
            return
        impact = weight if weight is not None else default_weights.get(name, 0)
        evidence = {
            "type": evidence_type,
            "category": category,
            "matched_value": matched_value,
            "reason": reason,
            "score_impact": impact,
            "rule_name": name,
        }
        evidence_items.append(evidence)
        triggered.append(
            {
                "name": name,
                "rule_name": name,
                "evidence_type": evidence_type,
                "category": category,
                "matched_value": matched_value,
                "reason": reason,
                "score_impact": impact,
                "score_added": impact,
                "evidence": f"{matched_value}: {reason}" if matched_value else reason,
                "explanation": descriptions.get(name, ""),
            }
        )

    from_domain = _domain_from_email(parsed_email.get("from_address"))
    reply_domain = _domain_from_email(parsed_email.get("reply_to"))
    return_path_domain = _domain_from_email(parsed_email.get("return_path"))

    if from_domain and return_path_domain and from_domain != return_path_domain:
        add_rule(
            "Sender domain mismatch",
            "sender_mismatch",
            f"{from_domain} != {return_path_domain}",
            "From domain differs from Return-Path domain.",
            "Sender identity",
        )
    if from_domain and reply_domain and from_domain != reply_domain:
        add_rule(
            "Reply-To mismatch",
            "reply_to_mismatch",
            f"{from_domain} != {reply_domain}",
            "Reply-To domain differs from From domain.",
            "Sender identity",
        )

    domains = parsed_email.get("domains", [])
    shortener = next((domain for domain in domains if domain in URL_SHORTENERS or domain.endswith(tuple(f".{s}" for s in URL_SHORTENERS))), "")
    if shortener:
        add_rule("URL shortener detected", "shortened_url", shortener, "Known shortener domain found in URLs.", "URL risk")

    for url in parsed_email.get("urls", []):
        hostname = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}").hostname
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                add_rule("IP address URL", "ip_address_url", url, f"URL uses IP address host {hostname}.", "URL risk")
                break
            except ValueError:
                pass

    if len(parsed_email.get("urls", [])) >= 6:
        add_rule("Excessive links", "suspicious_url", str(len(parsed_email.get("urls", []))), "Unusually high URL count found.", "URL risk")

    keywords = parsed_email.get("suspicious_keywords", {})
    keyword_rule_map = {
        "urgent_language": "Urgent language",
        "password_reset_language": "Password reset language",
        "payment_invoice_language": "Payment or invoice language",
        "prize_gift_language": "Prize or gift language",
        "credential_otp_request": "Credential or OTP request",
        "oauth_device_code": "OAuth or device-code phishing",
        "bec_payment_fraud": "BEC or payment fraud indicators",
        "generic_greeting": "Generic greeting",
    }
    keyword_evidence_map = {
        "urgent_language": ("urgency_language", "Language risk"),
        "password_reset_language": ("credential_harvesting_keywords", "Credential risk"),
        "payment_invoice_language": ("bec_payment_fraud", "Payment fraud"),
        "prize_gift_language": ("suspicious_url", "Language risk"),
        "credential_otp_request": ("credential_harvesting_keywords", "Credential risk"),
        "oauth_device_code": ("oauth_device_code", "Credential risk"),
        "bec_payment_fraud": ("bec_payment_fraud", "Payment fraud"),
        "generic_greeting": ("urgency_language", "Language risk"),
    }
    for category, rule_name in keyword_rule_map.items():
        if category in keywords:
            evidence_type, evidence_category = keyword_evidence_map[category]
            matched = ", ".join(keywords[category])
            add_rule(rule_name, evidence_type, matched, f"Matched keywords: {matched}.", evidence_category)

    risky_attachments = parsed_email.get("risky_attachments", [])
    if risky_attachments:
        names = ", ".join(item["file_name"] for item in risky_attachments)
        add_rule("Risky attachment", "risky_attachment_extension", names, "Risky attachment extension detected.", "Attachment risk")

    auth_results = parsed_email.get("header_auth_results", {})
    for mechanism, failed_rule, missing_rule in [
        ("spf", "Failed SPF", "Missing SPF"),
        ("dkim", "Failed DKIM", "Missing DKIM"),
        ("dmarc", "Failed DMARC", "Missing DMARC"),
    ]:
        result = auth_results.get(mechanism)
        if result in {"fail", "softfail", "temperror", "permerror"}:
            add_rule(failed_rule, "auth_result", f"{mechanism}={result}", f"{mechanism.upper()} authentication result was {result}.", "Authentication")
        elif result == "not_found":
            add_rule(missing_rule, "auth_result", f"{mechanism}=missing", f"{mechanism.upper()} authentication result was missing.", "Authentication")

    if parsed_email.get("mismatched_visible_urls"):
        finding = parsed_email["mismatched_visible_urls"][0]
        add_rule(
            "Mismatched visible URL",
            "suspicious_url",
            f"{finding['visible']} -> {finding['actual']}",
            "Visible link text domain differs from actual href domain.",
            "URL risk",
        )

    if parsed_email.get("brand_impersonation"):
        brands = ", ".join(sorted({item["brand"] for item in parsed_email.get("brand_impersonation", [])}))
        add_rule("Brand impersonation signal", "brand_impersonation", brands, "Known brand language appears without aligned sender or link domains.", "Brand risk")

    if parsed_email.get("lookalike_domains"):
        finding = parsed_email["lookalike_domains"][0]
        add_rule("Lookalike domain", "lookalike_domain", finding["domain"], finding["reason"], "Brand risk")

    qr_payloads = parsed_email.get("qr_payloads", [])
    qr_urls = parsed_email.get("qr_urls", [])
    qr_domains = parsed_email.get("qr_domains", [])
    if qr_urls:
        add_rule(
            "QR code contains URL",
            "qr_url",
            qr_urls[0],
            "QR payload was decoded locally and contains a URL. The link was not visited.",
            "QR phishing",
        )
    qr_shortener = next((domain for domain in qr_domains if domain in URL_SHORTENERS or domain.endswith(tuple(f".{s}" for s in URL_SHORTENERS))), "")
    if qr_shortener:
        add_rule("QR code shortened URL", "qr_shortened_url", qr_shortener, "QR URL points to a known URL shortener.", "QR phishing")
    qr_text = " ".join(item.get("payload", "") for item in qr_payloads).lower()
    qr_terms = sorted({term for term in ["payment", "login", "password", "credential", "verify", "bank", "wallet"] if term in qr_text})
    if qr_terms:
        add_rule("QR credential or payment terms", "qr_payload_terms", ", ".join(qr_terms), "QR payload contains login, credential, or payment language.", "QR phishing")
    qr_brand_mismatch = parsed_email.get("qr_brand_mismatches", [])
    if qr_brand_mismatch:
        finding = qr_brand_mismatch[0]
        add_rule(
            "QR brand domain mismatch",
            "qr_brand_mismatch",
            f"{finding['brand']} -> {finding['domain']}",
            "QR payload references a known brand but points to an unapproved domain.",
            "QR phishing",
        )

    suspicious_tld_domain = next((domain for domain in domains if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)), "")
    if suspicious_tld_domain:
        add_rule("Suspicious top-level domain", "suspicious_url", suspicious_tld_domain, "Suspicious TLD found in extracted domains.", "URL risk")

    unicode_domain = next((domain for domain in domains if "xn--" in domain or any(ord(char) > 127 for char in domain)), "")
    if unicode_domain:
        add_rule("Unicode or punycode domain", "lookalike_domain", unicode_domain, "Unicode or punycode indicator found in domain.", "Brand risk")

    body = parsed_email.get("body", "")
    words = re.findall(r"\b[A-Za-z]{3,}\b", body)
    uppercase_words = [word for word in words if word.isupper()]
    if len(words) >= 10 and len(uppercase_words) / len(words) > 0.28:
        add_rule("Excessive capitalization", "urgency_language", "uppercase language", "Large share of message words are uppercase.", "Language risk")

    bec_analysis = parsed_email.get("bec_analysis", {})
    for indicator in bec_analysis.get("indicators", []):
        add_rule(
            "BEC or payment fraud indicators",
            "bec_payment_fraud",
            ", ".join(indicator["matched_terms"]),
            indicator["reason"],
            "Payment fraud",
        )

    score = min(100, sum(item["score_added"] for item in triggered))
    severity = severity_from_score(score)
    verdict = verdict_from_score(score)
    breakdown = score_breakdown(triggered)
    explanation_summary = build_explanation_summary(score, severity, triggered)

    return {
        "score": score,
        "risk_score": score,
        "severity": severity,
        "verdict_suggestion": verdict,
        "explanation_summary": explanation_summary,
        "evidence_items": evidence_items,
        "triggered_rules": triggered,
        "score_breakdown": breakdown,
        "bec_analysis": bec_analysis,
        "qr_indicators": qr_payloads,
        "brand_impersonation": parsed_email.get("brand_impersonation", [])
        + parsed_email.get("lookalike_domains", [])
        + parsed_email.get("qr_brand_mismatches", []),
        "recommended_action": recommended_action(score),
    }


def generate_detection_summary(parsed_email: dict) -> dict:
    risk = calculate_risk_score(parsed_email)
    return {"parsed_email": parsed_email, "risk": risk}


def score_breakdown(triggered_rules: list[dict]) -> list[dict]:
    totals: dict[str, int] = {}
    for rule in triggered_rules:
        category = rule.get("category") or "Other"
        totals[category] = totals.get(category, 0) + int(rule.get("score_impact", rule.get("score_added", 0)))
    return [
        {"category": category, "score": score}
        for category, score in sorted(totals.items(), key=lambda item: item[1], reverse=True)
    ]


def build_explanation_summary(score: int, severity: str, triggered_rules: list[dict]) -> str:
    if not triggered_rules:
        return "No high-confidence phishing indicators were detected. Analyst review is still recommended before closure."
    top_rules = sorted(triggered_rules, key=lambda item: item.get("score_impact", item.get("score_added", 0)), reverse=True)[:3]
    rule_text = ", ".join(rule["name"] for rule in top_rules)
    return f"Risk score {score}/100 is {severity}. Main contributors: {rule_text}."


def severity_from_score(score: int) -> str:
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def verdict_from_score(score: int) -> str:
    if score <= 30:
        return "Safe"
    if score <= 60:
        return "Suspicious"
    if score <= 80:
        return "Likely Phishing"
    return "Confirmed Phishing"


def recommended_action(score: int) -> str:
    if score <= 30:
        return "Monitor and close as safe if analyst review confirms no malicious intent."
    if score <= 60:
        return "Review links, sender authenticity, and user impact before closing or escalating."
    if score <= 80:
        return "Quarantine similar messages, block suspicious indicators, and notify affected users."
    return "Escalate immediately, block indicators, preserve evidence, and begin incident response."


def _extension(file_name: str) -> str:
    match = re.search(r"(\.[A-Za-z0-9]+)$", file_name or "")
    return match.group(1).lower() if match else ""
