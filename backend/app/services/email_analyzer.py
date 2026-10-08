import ipaddress
import re
from email import policy
from email.parser import Parser
from html import unescape
from urllib.parse import parse_qs, urlparse


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
    "rb.gy",
    "clck.ru",
    "v.gd",
    "qr.ae",
    "trib.al",
    "bl.ink",
}

SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".top",
    ".xyz",
    ".icu",
    ".click",
    ".country",
    ".gq",
    ".tk",
    ".work",
    ".rest",
    ".cam",
    ".sbs",
    ".cfd",
    ".buzz",
    ".fit",
    ".monster",
    ".quest",
    ".live",
    ".hair",
    ".skin",
}

RISKY_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
    ".iso",
    ".lnk",
    ".hta",
    ".vbe",
    ".wsf",
    ".cpl",
    ".docm",
    ".xlsm",
    ".pptm",
    ".img",
    ".dmg",
    ".dll",
    ".chm",
}

FREEMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "mail.com",
    "proton.me",
    "protonmail.com",
    "zoho.com",
    "yandex.com",
    "icloud.com",
    "live.com",
    "gmx.com",
}

BRAND_KEYWORDS = {
    "paypal",
    "microsoft",
    "office365",
    "google",
    "apple",
    "amazon",
    "netflix",
    "dhl",
    "fedex",
    "ups",
    "chase",
    "bank of america",
    "wellsfargo",
    "docusign",
    "adobe",
    "facebook",
    "meta",
    "instagram",
    "coinbase",
    "binance",
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
        "24 hours",
        "immediate action required",
        "within 48 hours",
        "action required",
        "suspended temporarily",
        "unauthorized activity detected",
    ],
    "password_reset_language": [
        "password reset",
        "reset your password",
        "change your password",
        "account verification",
        "unlock your account",
        "temporary password",
        "password expiration",
        "keep your password",
        "validate your login",
    ],
    "payment_invoice_language": [
        "invoice",
        "payment due",
        "wire transfer",
        "bank details",
        "overdue",
        "purchase order",
        "remittance",
        "payment confirmation",
        "billing statement",
        "funds transfer",
        "unpaid balance",
        "direct deposit",
    ],
    "prize_gift_language": [
        "gift card",
        "winner",
        "you have won",
        "claim your prize",
        "reward",
        "bonus payout",
        "voucher",
        "cash prize",
        "exclusive bonus",
        "sweepstakes",
    ],
    "credential_otp_request": [
        "login credentials",
        "one-time password",
        "otp",
        "security code",
        "enter your password",
        "verify your identity",
        "confirm your pin",
        "passcode",
        "provide credentials",
        "two-factor authentication code",
    ],
    "generic_greeting": [
        "dear user",
        "dear customer",
        "hello user",
        "valued customer",
        "dear member",
        "dear client",
        "undisclosed recipients",
    ],
    "quishing_qr_indicators": [
        "scan the qr code",
        "scan this qr",
        "scan the code",
        "qr code below",
        "scan with your phone",
        "scan with authenticator",
        "scan to authenticate",
        "use camera to scan",
    ],
    "helpdesk_it_lures": [
        "it helpdesk",
        "system administrator",
        "mailbox quota",
        "email storage full",
        "upgrade email service",
        "server migration",
        "it support team",
        "storage exceeded",
        "microsoft 365 support",
        "workspace admin",
    ],
    "legal_threat_lures": [
        "subpoena",
        "court notice",
        "legal action",
        "law enforcement",
        "tax refund",
        "irs notice",
        "copyright infringement",
        "cease and desist",
    ],
}

DEFAULT_RULES = [
    {
        "name": "Sender domain mismatch",
        "description": "From, Reply-To, or Return-Path domains do not align.",
        "severity_weight": 12,
        "category": "sender",
    },
    {
        "name": "Reply-To mismatch",
        "description": "Reply-To domain differs from From domain.",
        "severity_weight": 10,
        "category": "sender",
    },
    {
        "name": "Display name spoofing",
        "description": "Display name impersonates a different email address or known brand from a mismatched domain.",
        "severity_weight": 14,
        "category": "sender",
    },
    {
        "name": "Freemail sender impersonation",
        "description": "Email claims corporate, financial, or IT status but originates from a free consumer webmail provider.",
        "severity_weight": 12,
        "category": "sender",
    },
    {
        "name": "URL shortener detected",
        "description": "Email includes a known URL shortener hiding the destination.",
        "severity_weight": 12,
        "category": "url",
    },
    {
        "name": "IP address URL",
        "description": "A link uses a raw IP address instead of a domain name.",
        "severity_weight": 14,
        "category": "url",
    },
    {
        "name": "Non-standard port URL",
        "description": "A link points to an unusual network port often seen in staging or phishing servers.",
        "severity_weight": 10,
        "category": "url",
    },
    {
        "name": "Open redirect parameter",
        "description": "URL contains redirection parameters that can abuse trusted domains to route to external phishing pages.",
        "severity_weight": 12,
        "category": "url",
    },
    {
        "name": "URL credential abuse",
        "description": "URL contains an '@' character in userinfo syntax used to disguise the real host.",
        "severity_weight": 14,
        "category": "url",
    },
    {
        "name": "Excessive links",
        "description": "Email contains an unusually high number of URLs.",
        "severity_weight": 8,
        "category": "url",
    },
    {
        "name": "Urgent language",
        "description": "Email uses urgency or pressure tactics.",
        "severity_weight": 8,
        "category": "content",
    },
    {
        "name": "Password reset language",
        "description": "Email references password reset or account verification.",
        "severity_weight": 10,
        "category": "content",
    },
    {
        "name": "Payment or invoice language",
        "description": "Email references payment, invoice, or banking action.",
        "severity_weight": 8,
        "category": "content",
    },
    {
        "name": "Prize or gift language",
        "description": "Email references prizes, rewards, or gift cards.",
        "severity_weight": 8,
        "category": "content",
    },
    {
        "name": "Credential or OTP request",
        "description": "Email asks for credentials, codes, or identity verification.",
        "severity_weight": 16,
        "category": "content",
    },
    {
        "name": "Quishing QR code lure",
        "description": "Email prompts the recipient to scan a QR code to bypass desktop security filters.",
        "severity_weight": 14,
        "category": "content",
    },
    {
        "name": "IT helpdesk lure",
        "description": "Email impersonates internal IT support or mailbox quota warnings.",
        "severity_weight": 10,
        "category": "content",
    },
    {
        "name": "Legal or government threat lure",
        "description": "Email attempts to induce panic using legal, tax, or court summons claims.",
        "severity_weight": 10,
        "category": "content",
    },
    {
        "name": "Risky attachment",
        "description": "Attachment has an extension commonly abused in malware delivery.",
        "severity_weight": 18,
        "category": "attachment",
    },
    {
        "name": "Double extension attachment",
        "description": "Attachment utilizes a deceptive double extension to conceal an executable or script format.",
        "severity_weight": 18,
        "category": "attachment",
    },
    {
        "name": "Failed SPF",
        "description": "Headers indicate SPF failed or soft-failed.",
        "severity_weight": 12,
        "category": "authentication",
    },
    {
        "name": "Failed DKIM",
        "description": "Headers indicate DKIM cryptographic signature failed.",
        "severity_weight": 10,
        "category": "authentication",
    },
    {
        "name": "Failed DMARC",
        "description": "Headers indicate DMARC alignment failed.",
        "severity_weight": 12,
        "category": "authentication",
    },
    {
        "name": "Mismatched visible URL",
        "description": "Visible link text appears to point to a different domain than the actual href destination.",
        "severity_weight": 16,
        "category": "url",
    },
    {
        "name": "Suspicious top-level domain",
        "description": "A URL domain uses a TLD commonly seen in suspicious campaigns.",
        "severity_weight": 9,
        "category": "url",
    },
    {
        "name": "Unicode or punycode domain",
        "description": "Domain includes Unicode or punycode indicators that may support homograph impersonation.",
        "severity_weight": 10,
        "category": "url",
    },
    {
        "name": "Excessive capitalization",
        "description": "Body contains a high proportion of uppercase words indicating shouting pressure.",
        "severity_weight": 5,
        "category": "content",
    },
    {
        "name": "Generic greeting",
        "description": "Email uses a generic impersonal greeting typical of mass spray attacks.",
        "severity_weight": 6,
        "category": "content",
    },
]


def _normalize_domain(value: str | None) -> str:
    if not value:
        return ""
    if "@" in value:
        value = value.split("@")[-1]
    value = value.strip().strip("<>\"' \t\r\n").lower()
    return value.rstrip(".")


def _domain_from_email(value: str | None) -> str:
    matches = extract_email_addresses(value or "")
    if matches:
        return _normalize_domain(matches[0])
    return _normalize_domain(value)


def _parse_display_name_and_email(value: str | None) -> tuple[str, str]:
    if not value:
        return ("", "")
    raw = value.strip()
    match = re.search(r"<([^>]+)>", raw)
    if match:
        email_addr = match.group(1).strip()
        display_name = re.sub(r"<[^>]+>", "", raw).strip().strip("\"'")
        return (display_name, email_addr)
    emails = extract_email_addresses(raw)
    if emails:
        return ("", emails[0])
    return (raw, "")


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
            payload = message.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode(errors="ignore"))
    return "\n".join(body_parts)


def parse_email(raw_email_text: str) -> dict:
    """
    Parse email text safely.
    Attachments are enumerated by metadata only and are NEVER opened or executed.
    URLs and hostnames are parsed through regular expressions without socket/HTTP resolution.
    """
    message = Parser(policy=policy.default).parsestr(raw_email_text or "")
    headers = {key.lower(): str(value) for key, value in message.items()}
    received_headers = [str(value) for key, value in message.items() if key.lower() == "received"]
    body = _message_body(message)
    attachment_names = []

    if message.is_multipart():
        for part in message.walk():
            filename = part.get_filename()
            if filename:
                attachment_names.append(filename)

    text_for_iocs = f"{raw_email_text}\n{body}"
    urls = extract_urls(text_for_iocs)
    domains = extract_domains(urls)
    ips = extract_ips(text_for_iocs)
    email_addresses = extract_email_addresses(text_for_iocs)
    attachment_extensions = sorted({_extension(name) for name in attachment_names if _extension(name)})

    from_display, from_addr = _parse_display_name_and_email(headers.get("from", ""))

    return {
        "from_address": headers.get("from", ""),
        "from_display": from_display,
        "from_clean_email": from_addr,
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
        "attachment_extensions": attachment_extensions,
        "header_auth_results": detect_header_auth_results(headers),
        "suspicious_keywords": detect_suspicious_keywords(text_for_iocs),
        "risky_attachments": detect_risky_attachments(attachment_names),
        "mismatched_visible_urls": detect_mismatched_visible_urls(raw_email_text),
        "open_redirect_urls": detect_open_redirects(urls),
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
        double_ext = _detect_double_extension(name)
        if extension in RISKY_EXTENSIONS or double_ext:
            risky.append({
                "file_name": name,
                "extension": extension,
                "double_extension": bool(double_ext),
            })
    return risky


def _detect_double_extension(file_name: str) -> str | None:
    parts = (file_name or "").lower().split(".")
    if len(parts) >= 3:
        second_last = f".{parts[-2]}"
        last = f".{parts[-1]}"
        benign_decoys = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".png", ".jpg"}
        if second_last in benign_decoys and last in RISKY_EXTENSIONS:
            return f"{second_last}{last}"
    return None


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


def detect_open_redirects(urls: list[str]) -> list[dict[str, str]]:
    findings = []
    redirect_params = {"url", "redirect", "next", "dest", "destination", "target", "goto", "link", "r"}
    for url in urls:
        candidate = url if url.lower().startswith(("http://", "https://")) else f"http://{url}"
        parsed = urlparse(candidate)
        query = parse_qs(parsed.query)
        for param, values in query.items():
            if param.lower() in redirect_params:
                for val in values:
                    if val.lower().startswith(("http://", "https://", "//")):
                        findings.append({"url": url, "param": param, "target": val})
    return findings


def detect_display_name_spoofing(from_header: str) -> dict | None:
    display_name, email_addr = _parse_display_name_and_email(from_header)
    if not display_name or not email_addr:
        return None

    actual_domain = _domain_from_email(email_addr)

    # 1. Check if display name contains an email address that doesn't match actual
    embedded_emails = extract_email_addresses(display_name)
    if embedded_emails:
        embedded_domain = _domain_from_email(embedded_emails[0])
        if embedded_domain != actual_domain:
            return {
                "type": "email_in_display_name",
                "display": display_name,
                "actual": email_addr,
                "evidence": f"Display name contains '{embedded_emails[0]}' but actual sender is '{email_addr}'.",
            }

    # 2. Check if display name mentions a high-profile brand while domain does not match
    lower_display = display_name.lower()
    for brand in BRAND_KEYWORDS:
        if brand in lower_display and brand not in actual_domain:
            return {
                "type": "brand_in_display_name",
                "display": display_name,
                "actual": email_addr,
                "evidence": f"Display name refers to '{brand.title()}' but domain '{actual_domain}' is unrelated.",
            }

    return None


def calculate_risk_score(
    parsed_email: dict,
    disabled_rules: set[str] | None = None,
    rule_weights: dict[str, int] | None = None,
) -> dict:
    disabled_rules = disabled_rules or set()
    triggered: list[dict] = []
    rule_meta = {rule["name"]: rule for rule in DEFAULT_RULES}
    default_weights = {rule["name"]: rule["severity_weight"] for rule in DEFAULT_RULES}
    if rule_weights:
        default_weights.update(rule_weights)

    def add_rule(name: str, evidence: str, weight: int | None = None) -> None:
        if name in disabled_rules:
            return
        meta = rule_meta.get(name, {})
        triggered.append(
            {
                "name": name,
                "evidence": evidence,
                "score_added": weight if weight is not None else default_weights.get(name, 0),
                "category": meta.get("category", "general"),
                "explanation": meta.get("description", ""),
            }
        )

    from_domain = _domain_from_email(parsed_email.get("from_address"))
    reply_domain = _domain_from_email(parsed_email.get("reply_to"))
    return_path_domain = _domain_from_email(parsed_email.get("return_path"))

    # 1. Sender Analysis
    if from_domain and return_path_domain and from_domain != return_path_domain:
        add_rule("Sender domain mismatch", f"From domain '{from_domain}' differs from Return-Path '{return_path_domain}'.")

    if from_domain and reply_domain and from_domain != reply_domain:
        add_rule("Reply-To mismatch", f"From domain '{from_domain}' differs from Reply-To '{reply_domain}'.")

    from_header = parsed_email.get("from_address", "")
    display_spoof = detect_display_name_spoofing(from_header)
    if display_spoof:
        add_rule("Display name spoofing", display_spoof["evidence"])

    keywords = parsed_email.get("suspicious_keywords", {})
    body_text = parsed_email.get("body", "")
    if from_domain in FREEMAIL_DOMAINS and (
        "payment_invoice_language" in keywords
        or "credential_otp_request" in keywords
        or "helpdesk_it_lures" in keywords
        or "password_reset_language" in keywords
    ):
        add_rule(
            "Freemail sender impersonation",
            f"Sender uses public freemail domain '{from_domain}' while delivering sensitive IT/financial requests.",
        )

    # 2. URL and Link Analysis
    domains = parsed_email.get("domains", [])
    urls = parsed_email.get("urls", [])

    if any(domain in URL_SHORTENERS or domain.endswith(tuple(f".{s}" for s in URL_SHORTENERS)) for domain in domains):
        add_rule("URL shortener detected", "Known shortener domain found in URLs hiding destination.")

    for url in urls:
        candidate = url if url.startswith(("http://", "https://")) else f"http://{url}"
        parsed_url = urlparse(candidate)
        hostname = parsed_url.hostname
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                add_rule("IP address URL", f"URL uses raw IP address host '{hostname}'.")
                break
            except ValueError:
                pass

        # Check URL port
        if parsed_url.port and parsed_url.port not in {80, 443}:
            add_rule("Non-standard port URL", f"URL '{url}' targets non-standard network port {parsed_url.port}.")
            break

        # Check @ symbol in authority (credential abuse)
        if "@" in parsed_url.netloc:
            add_rule("URL credential abuse", f"URL '{url}' uses '@' syntax to deceive the destination host.")
            break

    open_redirects = parsed_email.get("open_redirect_urls", [])
    if open_redirects:
        add_rule(
            "Open redirect parameter",
            f"URL contains open redirection parameter '{open_redirects[0]['param']}' pointing to external target.",
        )

    if len(urls) >= 6:
        add_rule("Excessive links", f"{len(urls)} URLs were identified in message content.")

    if parsed_email.get("mismatched_visible_urls"):
        add_rule("Mismatched visible URL", "Visible link text domain differs from actual href target.")

    if any(any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) for domain in domains):
        add_rule("Suspicious top-level domain", "Extracted URL domain uses a high-risk or commonly abused TLD.")

    if any("xn--" in domain or any(ord(char) > 127 for char in domain) for domain in domains):
        add_rule("Unicode or punycode domain", "Domain utilizes punycode or internationalized characters capable of homograph spoofing.")

    # 3. Content and Language Analysis
    keyword_rule_map = {
        "urgent_language": "Urgent language",
        "password_reset_language": "Password reset language",
        "payment_invoice_language": "Payment or invoice language",
        "prize_gift_language": "Prize or gift language",
        "credential_otp_request": "Credential or OTP request",
        "generic_greeting": "Generic greeting",
        "quishing_qr_indicators": "Quishing QR code lure",
        "helpdesk_it_lures": "IT helpdesk lure",
        "legal_threat_lures": "Legal or government threat lure",
    }
    for category, rule_name in keyword_rule_map.items():
        if category in keywords:
            add_rule(rule_name, f"Matched keywords: {', '.join(keywords[category])}.")

    words = re.findall(r"\b[A-Za-z]{3,}\b", body_text)
    uppercase_words = [word for word in words if word.isupper()]
    if len(words) >= 10 and len(uppercase_words) / len(words) > 0.28:
        add_rule("Excessive capitalization", "High proportion of message body is uppercase.")

    # 4. Attachment Analysis
    risky_attachments = parsed_email.get("risky_attachments", [])
    if risky_attachments:
        names = ", ".join(item["file_name"] for item in risky_attachments)
        add_rule("Risky attachment", f"Dangerous or executable extension detected: {names}.")
        if any(item.get("double_extension") for item in risky_attachments):
            add_rule("Double extension attachment", f"Deceptive double extension format detected in: {names}.")

    # 5. Header Authentication Analysis
    auth_results = parsed_email.get("header_auth_results", {})
    for mechanism, rule_name in [("spf", "Failed SPF"), ("dkim", "Failed DKIM"), ("dmarc", "Failed DMARC")]:
        if auth_results.get(mechanism) in {"fail", "softfail", "temperror", "permerror"}:
            add_rule(rule_name, f"{mechanism.upper()} verification result was '{auth_results.get(mechanism)}'.")

    # Score calculation & subscores
    score = min(100, sum(item["score_added"] for item in triggered))
    severity = severity_from_score(score)
    verdict = verdict_from_score(score)

    subscores = {
        "sender": sum(item["score_added"] for item in triggered if item.get("category") == "sender"),
        "url": sum(item["score_added"] for item in triggered if item.get("category") == "url"),
        "content": sum(item["score_added"] for item in triggered if item.get("category") == "content"),
        "attachment": sum(item["score_added"] for item in triggered if item.get("category") == "attachment"),
        "authentication": sum(item["score_added"] for item in triggered if item.get("category") == "authentication"),
    }

    triggered_names = {item["name"] for item in triggered}
    action = recommended_action(score, triggered_names)

    # Compute confidence percentage (50-98%)
    confidence = min(98, max(50, 45 + len(triggered) * 10 + (20 if auth_results.get("dmarc") != "not_found" else 0)))

    return {
        "score": score,
        "severity": severity,
        "verdict_suggestion": verdict,
        "triggered_rules": triggered,
        "subscores": subscores,
        "confidence_percentage": confidence,
        "recommended_action": action,
        "summary": _build_summary(score, severity, verdict, triggered),
    }


def _build_summary(score: int, severity: str, verdict: str, triggered: list[dict]) -> str:
    if not triggered:
        return f"Analysis complete. Score: {score}/100 ({severity}). No malicious phishing indicators were detected."
    rule_titles = ", ".join(t["name"] for t in triggered[:3])
    extra = f" and {len(triggered) - 3} other rules" if len(triggered) > 3 else ""
    return (
        f"Assessed as {verdict} (Risk Score: {score}/100, {severity} severity). "
        f"Primary triggers: {rule_titles}{extra}."
    )


def generate_detection_summary(parsed_email: dict) -> dict:
    risk = calculate_risk_score(parsed_email)
    return {"parsed_email": parsed_email, "risk": risk}


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


def recommended_action(score: int, triggered_rules: set[str] | None = None) -> str:
    triggered_rules = triggered_rules or set()
    recommendations = []

    if "Credential or OTP request" in triggered_rules or "Password reset language" in triggered_rules:
        recommendations.append("Immediately revoke active user sessions and mandate an out-of-band password reset.")

    if "Risky attachment" in triggered_rules or "Double extension attachment" in triggered_rules:
        recommendations.append("Isolate recipient endpoint, quarantine attachment file, and submit hash to EDR blocklist.")

    if "Display name spoofing" in triggered_rules or "Freemail sender impersonation" in triggered_rules:
        recommendations.append("Block sender identity at email gateway and issue targeted spear-phishing advisory.")

    if "Failed DMARC" in triggered_rules or "Failed SPF" in triggered_rules:
        recommendations.append("Add sending infrastructure to perimeter firewall blocklist and verify domain spoofing filters.")

    if recommendations:
        return " ".join(recommendations)

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
