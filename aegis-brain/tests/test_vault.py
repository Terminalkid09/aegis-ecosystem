import os
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.models import User, Note
from app.core.security import hash_password, create_access_token
from sqlalchemy import select

@pytest.mark.asyncio
async def test_vault_create_and_decrypt(db_session):
    # 1. Create user
    user = User(username="vault_user", email="vault@test", password_hash=hash_password("pass"), role="user", active=True)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    token, jti, exp = create_access_token(str(user.id), user.role)
    
    # 2. Create encrypted note via API
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {token}"}
        payload = {"title": "Secret Note", "content": "This is a secret", "mood": "happy", "tags": ["personal"]}
        r = await client.post("/api/v1/vault/notes", json=payload, headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert data["title"] == "Secret Note"
        assert data["content"] == "This is a secret" # API should return plaintext
        note_id = data["id"]
        
        # 3. Verify it's encrypted in the database
        # We need to refresh the session or use a new one to be sure
        await db_session.commit()
        stmt = select(Note).where(Note.id == note_id)
        result = await db_session.execute(stmt)
        db_note = result.scalars().first()
        assert db_note.content != "This is a secret"
        assert len(db_note.content) > 30 # Encryption adds nonce and overhead
        
        # 4. Retrieve and decrypt via API
        r = await client.get("/api/v1/vault/notes", headers=headers)
        assert r.status_code == 200
        notes = r.json()
        assert any(n["id"] == note_id and n["content"] == "This is a secret" for n in notes)
