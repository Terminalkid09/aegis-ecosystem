import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Mock DATABASE_URL per i test prima di caricare il modulo connection
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

from database.connection import Base, get_db
from main import app

# Database di test in memoria
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

# Mock AEGIS_API_KEY per i test
TEST_API_KEY = "test-secret-key"
os.environ["AEGIS_API_KEY"] = TEST_API_KEY

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)
headers = {"X-Api-Key": TEST_API_KEY}

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_get_empty_alerts():
    response = client.get("/api/v1/alerts", headers=headers)
    assert response.status_code == 200
    assert response.json() == []

def test_get_stats_empty():
    response = client.get("/api/v1/stats", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_alerts"] == 0
    assert data["active_agents"] == 0
