from httpx import AsyncClient
from app.models.models import AttackEvent, AttackCommand, CredentialAttempt


class TestEvents:
    async def test_get_events_empty(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/events/", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []

    async def test_get_events_with_data(self, client: AsyncClient, auth_headers, db_session):
        event = AttackEvent(
            session_id="test-session-001",
            attacker_ip="192.168.1.100",
            attacker_port=12345,
            sensor_type="ssh",
            sensor_port=2222,
            country="US",
            city="New York",
            is_known_threat=False,
        )
        db_session.add(event)
        await db_session.flush()

        db_session.add(CredentialAttempt(
            event_id=event.id,
            username="admin",
            password="password123",
            success=False,
        ))
        db_session.add(AttackCommand(event_id=event.id, command="whoami"))
        db_session.add(AttackCommand(event_id=event.id, command="ls -la"))
        await db_session.flush()

        response = await client.get("/api/v1/events/", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["session_id"] == "test-session-001"
        assert data[0]["sensor_type"] == "ssh"

    async def test_get_events_pagination(self, client: AsyncClient, auth_headers, db_session):
        for i in range(15):
            db_session.add(AttackEvent(
                session_id=f"test-session-{i:03d}",
                attacker_ip=f"10.0.0.{i}",
                sensor_type="ssh",
                sensor_port=2222,
            ))
        await db_session.flush()

        response = await client.get("/api/v1/events/?limit=10", headers=auth_headers)
        assert response.status_code == 200
        assert len(response.json()) == 10

        response = await client.get("/api/v1/events/?skip=10&limit=10", headers=auth_headers)
        assert response.status_code == 200
        assert len(response.json()) == 5

    async def test_get_events_filter_by_sensor(self, client: AsyncClient, auth_headers, db_session):
        db_session.add(AttackEvent(
            session_id="ssh-001", attacker_ip="1.1.1.1", sensor_type="ssh", sensor_port=2222
        ))
        db_session.add(AttackEvent(
            session_id="http-001", attacker_ip="2.2.2.2", sensor_type="http", sensor_port=8080
        ))
        await db_session.flush()

        response = await client.get("/api/v1/events/?sensor_type=ssh", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["sensor_type"] == "ssh"

    async def test_get_event_by_session(self, client: AsyncClient, auth_headers, db_session):
        event = AttackEvent(
            session_id="detail-session-001",
            attacker_ip="192.168.1.50",
            sensor_type="telnet",
            sensor_port=2323,
            country="DE",
            city="Berlin",
        )
        db_session.add(event)
        await db_session.flush()
        db_session.add(CredentialAttempt(event_id=event.id, username="root", password="toor"))
        await db_session.flush()

        response = await client.get(f"/api/v1/events/{event.session_id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == "detail-session-001"
        assert len(data["credentials"]) == 1
        assert data["credentials"][0]["username"] == "root"

    async def test_get_nonexistent_event(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/events/nonexistent-session", headers=auth_headers)
        assert response.status_code == 404

    async def test_dashboard_stats(self, client: AsyncClient, auth_headers, db_session):
        for i in range(5):
            db_session.add(AttackEvent(
                session_id=f"stats-{i}", attacker_ip=f"10.0.0.{i}",
                sensor_type="ssh" if i % 2 == 0 else "http", sensor_port=2222,
                country="US" if i % 2 == 0 else "DE",
            ))
        await db_session.flush()

        response = await client.get("/api/v1/events/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_attacks"] == 5
        assert data["unique_ips"] == 5
        assert len(data["top_sensors"]) == 2