from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.asyncio
async def test_sensor_key_is_returned_once_and_revocation_is_immediate(client, admin_auth_headers):
    created = await client.post(
        "/api/v1/ops/sensors",
        json={"name": "branch-1", "site": "lab", "config": {"smb_port": 445}},
        headers=admin_auth_headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    node_id = body["node_id"]
    key = body["sensor_key"]
    assert key.startswith("ks_")
    assert "key_hash" not in body

    listed = await client.get("/api/v1/ops/sensors", headers=admin_auth_headers)
    assert listed.status_code == 200
    assert all("sensor_key" not in row for row in listed.json())

    heartbeat = await client.post(
        f"/api/v1/ops/sensors/{node_id}/heartbeat",
        json={"applied_version": 1, "health": {"smb": "ok"}},
        headers={**admin_auth_headers, "X-Sensor-Key": key},
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["desired"]["signature"]
    assert heartbeat.json()["status"] == "online"

    wrong = await client.post(
        f"/api/v1/ops/sensors/{node_id}/heartbeat",
        json={"applied_version": 1},
        headers={**admin_auth_headers, "X-Sensor-Key": "ks_wrong"},
    )
    assert wrong.status_code == 401

    revoked = await client.post(
        f"/api/v1/ops/sensors/{node_id}/revoke", headers=admin_auth_headers
    )
    assert revoked.status_code == 200
    after = await client.get(
        f"/api/v1/ops/sensors/{node_id}/config",
        headers={"X-Sensor-Key": key},
    )
    assert after.status_code == 401


@pytest.mark.asyncio
async def test_campaign_topology_and_shadow_lab_run_are_visible(client, admin_auth_headers):
    assert (await client.post(
        "/api/v1/ops/campaigns",
        json={"name": "e2e-campaign", "description": "test"},
        headers=admin_auth_headers,
    )).status_code == 201
    topology = await client.post(
        "/api/v1/ops/topologies",
        json={"name": "e2e-topology", "description": "lab", "spec": {"hosts": 2}},
        headers=admin_auth_headers,
    )
    assert topology.status_code == 201
    topology_id = topology.json()["id"]
    run = await client.post(
        "/api/v1/ops/lab-runs",
        json={"scenario_id": "ssh-bruteforce", "topology_id": topology_id},
        headers=admin_auth_headers,
    )
    assert run.status_code == 201
    assert run.json()["mode"] == "shadow"

    campaigns = (await client.get("/api/v1/ops/campaigns", headers=admin_auth_headers)).json()
    assert any(row["name"] == "e2e-campaign" for row in campaigns)
    runs = (await client.get("/api/v1/ops/lab-runs", headers=admin_auth_headers)).json()
    assert any(row["scenario_id"] == "ssh-bruteforce" for row in runs)


@pytest.mark.asyncio
async def test_lab_run_rejects_non_shadow_mode(client, admin_auth_headers):
    response = await client.post(
        "/api/v1/ops/lab-runs",
        json={"scenario_id": "ssh-bruteforce", "mode": "active"},
        headers=admin_auth_headers,
    )
    assert response.status_code == 422
