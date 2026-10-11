from unittest.mock import patch
from io import BytesIO

import pytest

from app.services.email_analyzer import calculate_risk_score, detect_suspicious_keywords, extract_urls, parse_email, severity_from_score
from app.services.qr_analyzer import extract_qr_payloads_from_bytes


def test_email_url_extraction():
    text = "Please review https://security.example.com/reset and http://192.168.1.10/login."
    urls = extract_urls(text)
    assert "https://security.example.com/reset" in urls
    assert "http://192.168.1.10/login" in urls


def test_suspicious_keyword_detection():
    findings = detect_suspicious_keywords("Dear user, urgent password reset required. Enter your OTP.")
    assert "urgent_language" in findings
    assert "password_reset_language" in findings
    assert "credential_otp_request" in findings


def test_risk_score_calculation():
    raw = """From: Security <security@example.com>
Reply-To: attacker@evil.example
Return-Path: bounce@evil.example
Authentication-Results: mx.example; spf=fail smtp.mailfrom=evil.example; dkim=fail; dmarc=fail
Subject: URGENT password reset

Dear user, reset your password immediately at http://192.168.1.10/login
"""
    parsed = parse_email(raw)
    risk = calculate_risk_score(parsed)
    assert risk["score"] >= 60
    assert risk["severity"] in {"High", "Critical"}
    assert any(rule["name"] == "Reply-To mismatch" for rule in risk["triggered_rules"])


def test_explanation_items_generated_correctly():
    raw = """From: Microsoft Security <security@micros0ft-login.example>
Reply-To: attacker@evil.example
Return-Path: bounce@evil.example
Authentication-Results: mx.example; spf=fail smtp.mailfrom=evil.example; dkim=fail; dmarc=fail
Subject: Urgent Microsoft device code approval

Dear user, approve sign in and enter this code at https://bit.ly/device-login.
Wire transfer payment instructions are attached.
"""
    risk = calculate_risk_score(parse_email(raw))
    evidence_types = {item["type"] for item in risk["evidence_items"]}
    assert "sender_mismatch" in evidence_types
    assert "reply_to_mismatch" in evidence_types
    assert "auth_result" in evidence_types
    assert "shortened_url" in evidence_types
    assert "brand_impersonation" in evidence_types
    assert "oauth_device_code" in evidence_types
    assert "bec_payment_fraud" in evidence_types
    assert risk["explanation_summary"]
    assert risk["score_breakdown"]


def test_triggered_rules_include_score_impact():
    raw = """From: Security <security@example.com>
Subject: Urgent password reset

Dear user, reset your password immediately at http://192.168.1.10/login
"""
    risk = calculate_risk_score(parse_email(raw))
    assert risk["triggered_rules"]
    assert all("score_impact" in rule for rule in risk["triggered_rules"])
    assert all(rule["score_impact"] == rule["score_added"] for rule in risk["triggered_rules"])


def test_severity_mapping_boundaries():
    assert severity_from_score(0) == "Low"
    assert severity_from_score(30) == "Low"
    assert severity_from_score(31) == "Medium"
    assert severity_from_score(61) == "High"
    assert severity_from_score(81) == "Critical"


def test_safe_behavior_does_not_open_external_links():
    raw = """From: Security <security@example.com>
Subject: Link review

Review https://example.com/login immediately.
"""
    with patch("urllib.request.urlopen") as urlopen:
        calculate_risk_score(parse_email(raw))
    urlopen.assert_not_called()


def test_oauth_device_code_indicators_increase_score():
    base = calculate_risk_score(parse_email("From: Security <security@example.com>\nSubject: Notice\n\nReview your account."))
    oauth = calculate_risk_score(
        parse_email(
            "From: Security <security@example.com>\nSubject: Device code\n\nApprove sign in and enter this device code at aka.ms/devicelogin."
        )
    )
    assert oauth["score"] > base["score"]
    assert any(rule["name"] == "OAuth or device-code phishing" for rule in oauth["triggered_rules"])


def test_bec_payment_indicators_increase_score():
    base = calculate_risk_score(parse_email("From: Vendor <vendor@example.com>\nSubject: Hello\n\nChecking in."))
    bec = calculate_risk_score(
        parse_email(
            "From: Vendor <vendor@example.com>\nSubject: Payment change\n\nPlease update ACH routing number and wire transfer payment instructions."
        )
    )
    assert bec["score"] > base["score"]
    assert any(rule["name"] == "BEC or payment fraud indicators" for rule in bec["triggered_rules"])


def test_generated_qr_image_payload_is_extracted_safely():
    qrcode = pytest.importorskip("qrcode")
    pytest.importorskip("cv2")

    image = qrcode.make("https://bit.ly/pay-login")
    buffer = BytesIO()
    image.save(buffer, format="PNG")

    payloads = extract_qr_payloads_from_bytes(buffer.getvalue(), "sample.png", "image/png")
    assert payloads
    assert payloads[0]["payload"] == "https://bit.ly/pay-login"


def test_qr_payload_rules_increase_score():
    qrcode = pytest.importorskip("qrcode")
    pytest.importorskip("cv2")

    image = qrcode.make("https://bit.ly/pay-login")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    qr_payloads = extract_qr_payloads_from_bytes(buffer.getvalue(), "sample.png", "image/png")

    raw = "From: Microsoft Security <security@example.com>\nSubject: Microsoft login\n\nScan the QR to verify payment login."
    risk = calculate_risk_score(parse_email(raw, extra_qr_payloads=qr_payloads))
    rule_names = {rule["name"] for rule in risk["triggered_rules"]}
    assert "QR code contains URL" in rule_names
    assert "QR code shortened URL" in rule_names
    assert "QR credential or payment terms" in rule_names


def test_brand_lookalike_detection_adds_evidence():
    raw = """From: Microsoft Security <security@alert.example>
Subject: Microsoft verification

Review https://micros0ft-login.example/security now.
"""
    risk = calculate_risk_score(parse_email(raw))
    assert any(item["type"] == "lookalike_domain" for item in risk["evidence_items"])


def test_bec_detector_sets_structured_fields():
    raw = """From: CFO <cfo@example.com>
Subject: Urgent wire transfer

Please process urgent wire transfer of $24,500 and update vendor payment instructions with new routing number.
"""
    risk = calculate_risk_score(parse_email(raw))
    assert risk["bec_analysis"]["suspected_bec"] is True
    assert risk["bec_analysis"]["requested_amount"] == "$24,500"
    assert "wire transfer" in risk["bec_analysis"]["financial_risk_type"]
