"""
Unit Tests for DevSecOps Lab Application

Tests cover health checks, API endpoints, and input validation.
"""

import pytest
from app.main import app


@pytest.fixture
def client():
    """Create a test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_check(client):
    """Test that health endpoint returns 200 with healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_index(client):
    """Test that root endpoint returns application info."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["application"] == "DevSecOps Lab"
    assert "endpoints" in data


def test_scan_endpoint_valid(client):
    """Test scan endpoint with valid input."""
    response = client.post(
        "/api/scan",
        json={"target": "https://example.com"},
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "completed"
    assert "findings" in data


def test_scan_endpoint_missing_target(client):
    """Test scan endpoint rejects requests without target."""
    response = client.post(
        "/api/scan",
        json={"url": "https://example.com"},
        content_type="application/json",
    )
    assert response.status_code == 400


def test_scan_endpoint_empty_body(client):
    """Test scan endpoint rejects empty body."""
    response = client.post("/api/scan", content_type="application/json")
    assert response.status_code == 400


def test_scan_endpoint_invalid_target_type(client):
    """Test scan endpoint rejects non-string target."""
    response = client.post(
        "/api/scan",
        json={"target": 12345},
        content_type="application/json",
    )
    assert response.status_code == 400


def test_scan_endpoint_oversized_target(client):
    """Test scan endpoint rejects oversized target."""
    response = client.post(
        "/api/scan",
        json={"target": "x" * 3000},
        content_type="application/json",
    )
    assert response.status_code == 400
