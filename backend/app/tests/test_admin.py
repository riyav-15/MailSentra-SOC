def test_admin_rule_update(client, admin_headers):
    rules = client.get("/admin/rules", headers=admin_headers)
    assert rules.status_code == 200
    rule_id = rules.json()[0]["id"]

    response = client.patch(f"/admin/rules/{rule_id}", json={"enabled": False}, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["enabled"] is False
