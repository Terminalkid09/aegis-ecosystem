import pytest

from app.core.config import settings


@pytest.mark.asyncio
async def test_login_uses_public_base_path_and_local_assets(client, monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_BASE_PATH", "/kraken")
    response = await client.get("/login")
    assert response.status_code == 200
    html = response.text
    assert '<base href="/kraken/" />' in html
    assert "static/vendor/tailwind.js" in html
    assert "cdn.tailwindcss.com" not in html
    assert "<script>" not in html
    assert "onclick=" not in html


@pytest.mark.asyncio
async def test_sso_landing_is_served_without_a_session(client, monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_BASE_PATH", "/kraken")
    response = await client.get("/sso")
    assert response.status_code == 200
    assert 'src="static/js/sso.js"' in response.text
    assert "<script>" not in response.text
