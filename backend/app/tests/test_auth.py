def test_user_registration(client):
    response = client.post(
        "/auth/register",
        json={"name": "New Employee", "email": "new.employee@example.com", "password": "StrongPass123!"},
    )
    assert response.status_code == 201
    payload = response.json()
    assert payload["email"] == "new.employee@example.com"
    assert payload["role"] == "employee"


def test_user_login(client):
    response = client.post(
        "/auth/login",
        json={"email": "employee@phishguard.local", "password": "EmployeePass123!"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["access_token"]
    assert payload["user"]["role"] == "employee"


def test_role_based_access_blocks_employee_from_admin(client, employee_headers):
    response = client.get("/admin/users", headers=employee_headers)
    assert response.status_code == 403
