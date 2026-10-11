"""Health endpoint tests."""


def test_health_check_returns_200(client):
    """Test that /healthz returns 200 with service info."""
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "venuedesk-backend"
