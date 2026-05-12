import os
import pytest
from fastapi.testclient import TestClient
from main import app

# Mock AEGIS_API_KEY per i test
TEST_API_KEY = "test-secret-key"

@pytest.fixture
def client():
    os.environ["AEGIS_API_KEY"] = TEST_API_KEY
    with TestClient(app) as c:
        yield c

def test_verify_api_key_missing(client):
    response = client.get("/api/v1/alerts")
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]

def test_verify_api_key_invalid(client):
    response = client.get("/api/v1/alerts", headers={"X-Api-Key": "wrong-key"})
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]

def test_verify_api_key_valid(client):
    response = client.get("/api/v1/alerts", headers={"X-Api-Key": TEST_API_KEY})
    # Se il database non è configurato potrebbe dare 500 o altro, 
    # ma qui ci interessa che superi il middleware (quindi non 403)
    assert response.status_code != 403

def test_health_no_auth_required(client):
    # L'endpoint "/" non dovrebbe richiedere auth (configurato in main.py senza dependency)
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_api_key_not_configured(client):
    # Rimuoviamo la chiave dall'env per simulare errore server
    del os.environ["AEGIS_API_KEY"]
    response = client.get("/api/v1/alerts", headers={"X-Api-Key": TEST_API_KEY})
    assert response.status_code == 500
    assert "API Key not configured" in response.json()["detail"]
    # Ripristiniamo per gli altri test
    os.environ["AEGIS_API_KEY"] = TEST_API_KEY
