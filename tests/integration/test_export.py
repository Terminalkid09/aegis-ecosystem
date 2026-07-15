from httpx import AsyncClient
from app.models.models import AttackEvent
from datetime import datetime, timezone


class TestExport:
    async def test_export_csv(self, client: AsyncClient, auth_headers, db_session):
        for i in range(3):
            db_session.add(AttackEvent(
                session_id=f"export-{i}", attacker_ip=f"10.0.0.{i}",
                attacker_port=12345, sensor_type="ssh", sensor_port=2222,
                timestamp_start=datetime.now(timezone.utc),
                country="US", city="NYC", asn="AS12345", is_known_threat=False,
            ))
        await db_session.flush()

        response = await client.get("/api/v1/export/csv", headers=auth_headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        assert "attachment; filename=kraken_events.csv" in response.headers["content-disposition"]
        content = response.text
        assert "session_id,attacker_ip" in content
        assert "export-0" in content
        assert "export-1" in content
        assert "export-2" in content

    async def test_export_json(self, client: AsyncClient, auth_headers, db_session):
        db_session.add(AttackEvent(
            session_id="json-export", attacker_ip="10.0.0.1",
            attacker_port=12345, sensor_type="http", sensor_port=8080,
            timestamp_start=datetime.now(timezone.utc),
            country="UK", city="London", asn="AS999", is_known_threat=True,
        ))
        await db_session.flush()

        response = await client.get("/api/v1/export/json", headers=auth_headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        assert "attachment; filename=kraken_events.json" in response.headers["content-disposition"]
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["session_id"] == "json-export"
        assert data[0]["is_known_threat"] is True

    async def test_export_pdf(self, client: AsyncClient, auth_headers, db_session):
        for i in range(2):
            db_session.add(AttackEvent(
                session_id=f"pdf-{i}", attacker_ip=f"192.168.1.{i}",
                attacker_port=12345, sensor_type="ftp", sensor_port=2121,
                timestamp_start=datetime.now(timezone.utc),
                country="FR", city="Paris", asn="AS555", is_known_threat=False,
            ))
        await db_session.flush()

        response = await client.get("/api/v1/export/pdf", headers=auth_headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert "attachment; filename=kraken_report.pdf" in response.headers["content-disposition"]
        assert len(response.content) > 1000

    async def test_export_rate_limiting(self, client: AsyncClient, auth_headers):
        for _ in range(32):
            response = await client.get("/api/v1/export/csv", headers=auth_headers)
            if response.status_code == 429:
                break
        assert response.status_code == 429