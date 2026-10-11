SAMPLE_EMAIL = """From: IT Helpdesk <helpdesk@company.example>
Reply-To: verify@secure-reset.example
Return-Path: bounce@mailer.example
Authentication-Results: mx.company.example; spf=fail smtp.mailfrom=mailer.example; dkim=fail; dmarc=fail
Subject: Urgent password reset required

Dear user,
Your account will be suspended. Reset your password immediately:
http://192.168.10.25/login
"""


def test_incident_creation_from_report(client, employee_headers, analyst_headers):
    response = client.post(
        "/reports/submit",
        data={
            "subject": "Urgent password reset required",
            "sender": "helpdesk@company.example",
            "report_reason": "Looks suspicious",
            "raw_email_text": SAMPLE_EMAIL,
        },
        headers=employee_headers,
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["incident_id"]
    assert payload["risk_score"] > 0
    assert payload["triggered_rules"]
    assert payload["explanation_summary"]
    assert payload["evidence_items"]

    detail = client.get(f"/incidents/{payload['incident_id']}", headers=analyst_headers)
    assert detail.status_code == 200, detail.text
    explanation = detail.json()["analysis_explanation"]
    assert explanation["risk_score"] == payload["risk_score"]
    assert explanation["triggered_rules"][0]["score_impact"] > 0


def test_pdf_generation(client, employee_headers, analyst_headers):
    submit = client.post(
        "/reports/submit",
        data={
            "subject": "Urgent password reset required",
            "sender": "helpdesk@company.example",
            "report_reason": "Looks suspicious",
            "raw_email_text": SAMPLE_EMAIL,
        },
        headers=employee_headers,
    )
    incident_id = submit.json()["incident_id"]
    response = client.post(f"/incidents/{incident_id}/generate-report", headers=analyst_headers)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["incident_id"] == incident_id
    assert report["file_path"].endswith(".pdf")


def test_bec_incident_fields_and_checklist(client, employee_headers, analyst_headers):
    response = client.post(
        "/reports/submit",
        data={
            "subject": "Urgent wire transfer",
            "sender": "cfo@company.example",
            "report_reason": "Finance request seems suspicious",
            "raw_email_text": """From: CFO <cfo@company.example>
Subject: Urgent wire transfer

Please process urgent wire transfer of $24,500 and update vendor payment instructions with new routing number.
""",
        },
        headers=employee_headers,
    )
    assert response.status_code == 201, response.text
    incident_id = response.json()["incident_id"]
    detail = client.get(f"/incidents/{incident_id}", headers=analyst_headers)
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert payload["suspected_bec"] is True
    assert payload["requested_amount"] == "$24,500"
    assert payload["bec_checklist"]

    item_key = payload["bec_checklist"][0]["item_key"]
    update = client.patch(f"/incidents/{incident_id}/bec-checklist/{item_key}", json={"completed": True}, headers=analyst_headers)
    assert update.status_code == 200, update.text
    assert update.json()["completed"] is True
