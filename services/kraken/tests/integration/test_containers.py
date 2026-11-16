from httpx import AsyncClient
from unittest.mock import AsyncMock, patch


class TestContainers:
    async def test_list_sandboxes_requires_auth(self, client: AsyncClient):
        response = await client.get("/api/v1/containers/active")
        assert response.status_code == 401

    @patch("app.api.v1.endpoints.containers.docker_manager")
    async def test_list_sandboxes(self, mock_docker, client: AsyncClient, auth_headers):
        mock_docker.list_active = AsyncMock(return_value=[
            {"id": "abc123", "name": "kraken_sb_1", "status": "running", "session_id": "sess1"},
            {"id": "def456", "name": "kraken_sb_2", "status": "running", "session_id": "sess2"},
        ])
        response = await client.get("/api/v1/containers/active", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["session_id"] == "sess1"