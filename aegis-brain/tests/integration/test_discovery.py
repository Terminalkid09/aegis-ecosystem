import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.database.models import DiscoveredHost, IPReputation, Agent


class TestDiscoveryScan:
    async def test_scan_localhost(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/scan",
            json={"cidr": "127.0.0.1/32", "ports": [], "timeout_ms": 100},
            headers=admin_auth_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cidr"] == "127.0.0.1/32"
        assert isinstance(data["scanned_hosts"], int)
        assert isinstance(data["live_hosts"], int)
        assert isinstance(data["discovered"], list)

    async def test_scan_invalid_cidr(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/scan",
            json={"cidr": "not-a-cidr"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 400

    async def test_scan_requires_auth(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/discovery/scan",
            json={"cidr": "127.0.0.1/32"}
        )
        assert resp.status_code == 401


class TestDiscoveryScanViaAgent:
    async def test_scan_via_agent_queues_command(self, client: AsyncClient, db_session, admin_auth_headers, test_agent):
        resp = await client.post(
            f"/api/v1/discovery/scan-via-agent/{test_agent.agent_id}",
            json={"cidr": "192.168.1.0/24"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "command_queued"
        assert data["agent_id"] == str(test_agent.agent_id)
        assert data["cidr"] == "192.168.1.0/24"

    async def test_scan_via_agent_fetch_command(self, client: AsyncClient, db_session, admin_auth_headers, test_agent):
        await client.post(
            f"/api/v1/discovery/scan-via-agent/{test_agent.agent_id}",
            json={"cidr": "10.0.0.0/24"},
            headers=admin_auth_headers
        )
        resp = await client.get(
            "/api/v1/commands",
            params={"device_id": str(test_agent.agent_id)},
            headers={"Authorization": "Bearer agent-secret"}
        )
        assert resp.status_code == 200
        cmd = resp.json()
        assert cmd is not None
        assert cmd["command"] == "NETWORK_SCAN"
        assert cmd["cidr"] == "10.0.0.0/24"

    async def test_scan_via_agent_unknown(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/scan-via-agent/00000000-0000-0000-0000-000000000000",
            json={"cidr": "10.0.0.0/24"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 404

    async def test_scan_via_agent_requires_auth(self, client: AsyncClient, test_agent):
        resp = await client.post(
            f"/api/v1/discovery/scan-via-agent/{test_agent.agent_id}",
            json={"cidr": "10.0.0.0/24"}
        )
        assert resp.status_code == 401


class TestDiscoveryAgentScanResult:
    async def test_report_scan_results(self, client: AsyncClient, db_session, agent_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/agent-scan-result",
            json={
                "cidr": "192.168.1.0/24",
                "scan_hosts": [
                    {"ip_address": "192.168.1.1", "hostname": "router.local", "open_ports": [80, 443], "os_guess": "linux"},
                    {"ip_address": "192.168.1.100", "open_ports": [22], "os_guess": "linux"},
                ]
            },
            headers=agent_auth_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["hosts_found"] == 2

    async def test_report_scan_results_persists_hosts(self, client: AsyncClient, db_session, agent_auth_headers):
        await client.post(
            "/api/v1/discovery/agent-scan-result",
            json={
                "cidr": "10.0.0.0/24",
                "scan_hosts": [
                    {"ip_address": "10.0.0.1", "hostname": "gw.local", "open_ports": [443], "os_guess": "linux"},
                ]
            },
            headers=agent_auth_headers
        )
        result = await db_session.execute(select(DiscoveredHost).where(DiscoveredHost.ip_address == "10.0.0.1"))
        host = result.scalars().first()
        assert host is not None
        assert host.hostname == "gw.local"
        assert host.os_guess == "linux"
        assert host.open_ports == [443]

    async def test_report_scan_results_requires_agent_auth(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/agent-scan-result",
            json={"cidr": "10.0.0.0/24", "scan_hosts": []},
            headers=admin_auth_headers
        )
        assert resp.status_code == 422


class TestDiscoveredHosts:
    async def test_list_hosts_empty(self, client: AsyncClient, admin_auth_headers):
        resp = await client.get("/api/v1/discovery/hosts", headers=admin_auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    async def test_list_hosts_after_scan(self, client: AsyncClient, db_session, agent_auth_headers, admin_auth_headers):
        await client.post(
            "/api/v1/discovery/agent-scan-result",
            json={
                "cidr": "10.0.0.0/24",
                "scan_hosts": [{"ip_address": "10.0.0.5", "os_guess": "windows"}]
            },
            headers=agent_auth_headers
        )
        resp = await client.get("/api/v1/discovery/hosts", headers=admin_auth_headers)
        items = resp.json()["items"]
        ips = [h["ip_address"] for h in items]
        assert "10.0.0.5" in ips

    async def test_add_manual_host(self, client: AsyncClient, db_session, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/hosts/manual",
            json={"ip_address": "192.168.50.1", "hostname": "manual-host", "mac_address": "aa:bb:cc:dd:ee:ff"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ip_address"] == "192.168.50.1"
        assert data["hostname"] == "manual-host"

    async def test_list_hosts_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/discovery/hosts")
        assert resp.status_code == 401


class TestDiscoveryReputation:
    async def test_upsert_reputation(self, client: AsyncClient, db_session, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/reputation",
            json={"ip_address": "1.2.3.4", "label": "malicious", "confidence": 90, "source": "test"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ip_address"] == "1.2.3.4"
        assert data["label"] == "malicious"

    async def test_list_reputation(self, client: AsyncClient, db_session, admin_auth_headers):
        await client.post(
            "/api/v1/discovery/reputation",
            json={"ip_address": "5.6.7.8", "label": "suspicious", "confidence": 60, "source": "test"},
            headers=admin_auth_headers
        )
        resp = await client.get("/api/v1/discovery/reputation", headers=admin_auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        ips = [r["ip_address"] for r in data["items"]]
        assert "5.6.7.8" in ips

    async def test_list_reputation_filter_label(self, client: AsyncClient, db_session, admin_auth_headers):
        await client.post("/api/v1/discovery/reputation", json={"ip_address": "9.9.9.9", "label": "known", "confidence": 100, "source": "test"}, headers=admin_auth_headers)
        await client.post("/api/v1/discovery/reputation", json={"ip_address": "8.8.8.8", "label": "malicious", "confidence": 95, "source": "test"}, headers=admin_auth_headers)
        resp = await client.get("/api/v1/discovery/reputation?label=malicious", headers=admin_auth_headers)
        items = resp.json()["items"]
        assert all(r["label"] == "malicious" for r in items)
        assert "8.8.8.8" in [r["ip_address"] for r in items]
        assert "9.9.9.9" not in [r["ip_address"] for r in items]

    async def test_upsert_reputation_invalid_label(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/reputation",
            json={"ip_address": "1.2.3.4", "label": "invalid_label", "confidence": 50},
            headers=admin_auth_headers
        )
        assert resp.status_code == 422

    async def test_reputation_requires_auth(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/discovery/reputation",
            json={"ip_address": "1.2.3.4", "label": "known", "confidence": 50}
        )
        assert resp.status_code == 401


class TestDiscoveryDeployment:
    async def test_deployment_plan_manual(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/deployment/plan",
            json={"ip_address": "192.168.1.100", "os_type": "linux", "agent_type": "nodetrace", "method": "manual"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "planned"
        assert data["method"] == "manual"
        assert data["ip_address"] == "192.168.1.100"
        assert "local_command" in data
        assert "remote_command" in data
        assert "executables" in data

    async def test_deployment_plan_windows(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/deployment/plan",
            json={"ip_address": "192.168.1.200", "os_type": "windows", "agent_type": "aegis-guard", "method": "manual"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["method"] == "manual"
        assert data["agent_type"] == "aegis-guard"

    async def test_deployment_plan_invalid_os(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/deployment/plan",
            json={"ip_address": "10.0.0.1", "os_type": "macos", "agent_type": "nodetrace", "method": "manual"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 422

    async def test_deploy_missing_creds(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/deploy",
            json={"ip_address": "192.168.1.100", "agent_type": "nodetrace"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "credentials" in data["detail"].lower()

    async def test_deploy_with_creds(self, client: AsyncClient, admin_auth_headers):
        resp = await client.post(
            "/api/v1/discovery/deploy",
            json={"ip_address": "192.168.1.100", "agent_type": "nodetrace", "username": "admin", "password": "test123"},
            headers=admin_auth_headers
        )
        assert resp.status_code == 200, f"Deploy failed: {resp.json()}"
        data = resp.json()
        assert data["status"] == "deploy_initiated"
        assert data["ip_address"] == "192.168.1.100"
        assert "command" in data

    async def test_deploy_requires_auth(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/discovery/deploy",
            json={"ip_address": "10.0.0.1", "agent_type": "nodetrace"}
        )
        assert resp.status_code == 401


class TestDiscoverySyncAgentStatus:
    async def test_sync_agent_status(self, client: AsyncClient, db_session, admin_auth_headers, test_agent):
        resp = await client.post("/api/v1/discovery/sync-agent-status", headers=admin_auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "synced"
        assert isinstance(data["count"], int)

    async def test_sync_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/discovery/sync-agent-status")
        assert resp.status_code == 401


class TestCommands:
    async def test_fetch_commands_empty(self, client: AsyncClient, db_session, test_agent):
        resp = await client.get(
            "/api/v1/commands",
            params={"device_id": str(test_agent.agent_id)},
            headers={"Authorization": "Bearer agent-secret"}
        )
        assert resp.status_code == 200
        assert resp.json() is None

    async def test_fetch_commands_after_scan_queued(self, client: AsyncClient, db_session, admin_auth_headers, test_agent):
        await client.post(
            f"/api/v1/discovery/scan-via-agent/{test_agent.agent_id}",
            json={"cidr": "172.16.0.0/24"},
            headers=admin_auth_headers
        )
        resp = await client.get(
            "/api/v1/commands",
            params={"device_id": str(test_agent.agent_id)},
            headers={"Authorization": "Bearer agent-secret"}
        )
        assert resp.status_code == 200
        cmd = resp.json()
        assert cmd is not None
        assert cmd["command"] == "NETWORK_SCAN"
        assert cmd["cidr"] == "172.16.0.0/24"

    async def test_fetch_commands_pop_once(self, client: AsyncClient, db_session, admin_auth_headers, test_agent):
        await client.post(
            f"/api/v1/discovery/scan-via-agent/{test_agent.agent_id}",
            json={"cidr": "10.10.0.0/16"},
            headers=admin_auth_headers
        )
        await client.get(
            "/api/v1/commands",
            params={"device_id": str(test_agent.agent_id)},
            headers={"Authorization": "Bearer agent-secret"}
        )
        second = await client.get(
            "/api/v1/commands",
            params={"device_id": str(test_agent.agent_id)},
            headers={"Authorization": "Bearer agent-secret"}
        )
        assert second.json() is None

    async def test_fetch_commands_invalid_device_id(self, client: AsyncClient, test_agent):
        resp = await client.get(
            "/api/v1/commands",
            params={"device_id": "not-a-uuid"},
            headers={"Authorization": "Bearer agent-secret"}
        )
        assert resp.status_code == 400

    async def test_fetch_commands_wrong_token(self, client: AsyncClient, test_agent):
        resp = await client.get(
            "/api/v1/commands",
            params={"device_id": str(test_agent.agent_id)},
            headers={"Authorization": "Bearer wrong-token"}
        )
        assert resp.status_code == 401

    async def test_telemetry_commands_endpoint(self, client: AsyncClient, db_session, agent_auth_headers, admin_auth_headers, test_agent):
        await client.post(
            f"/api/v1/discovery/scan-via-agent/{test_agent.agent_id}",
            json={"cidr": "10.20.0.0/24"},
            headers=admin_auth_headers
        )
        resp = await client.get(
            "/api/v1/telemetry/commands",
            headers=agent_auth_headers
        )
        assert resp.status_code == 200
        cmd = resp.json()
        assert cmd is not None
        assert cmd["command"] == "NETWORK_SCAN"
        assert cmd["cidr"] == "10.20.0.0/24"

    async def test_telemetry_commands_requires_agent_auth(self, client: AsyncClient, admin_auth_headers):
        resp = await client.get("/api/v1/telemetry/commands", headers=admin_auth_headers)
        assert resp.status_code == 422
