import pytest
from httpx import AsyncClient


class TestVault:
    async def test_create_note(self, client: AsyncClient, user_auth_headers):
        response = await client.post("/api/v1/vault/notes", headers=user_auth_headers, json={
            "title": "Test Note",
            "content": "This is secret content",
            "mood": "neutral",
            "tags": ["test", "security"]
        })
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Test Note"
        assert data["content"] == "This is secret content"
        assert data["tags"] == ["test", "security"]

    async def test_get_notes(self, client: AsyncClient, user_auth_headers, db_session, test_user):
        from app.database.models import Note
        from app.core.crypto import encrypt_for_user, generate_dek, encrypt_dek_with_kek

        dek = generate_dek()
        encrypted_dek = encrypt_dek_with_kek(dek)
        test_user.encrypted_dek = encrypted_dek
        db_session.add(test_user)

        note = Note(
            user_id=test_user.id,
            title="Existing Note",
            content=encrypt_for_user(encrypted_dek, "Existing content"),
            mood="happy",
            tags=["existing"]
        )
        db_session.add(note)
        await db_session.commit()

        response = await client.get("/api/v1/vault/notes", headers=user_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(n["title"] == "Existing Note" for n in data)

    async def test_delete_note(self, client: AsyncClient, user_auth_headers, db_session, test_user):
        from app.database.models import Note
        from app.core.crypto import encrypt_for_user, generate_dek, encrypt_dek_with_kek

        dek = generate_dek()
        encrypted_dek = encrypt_dek_with_kek(dek)
        test_user.encrypted_dek = encrypted_dek

        note = Note(
            user_id=test_user.id,
            title="To Delete",
            content=encrypt_for_user(encrypted_dek, "Delete me"),
        )
        db_session.add(note)
        await db_session.commit()
        await db_session.refresh(note)

        response = await client.delete(f"/api/v1/vault/notes/{note.id}", headers=user_auth_headers)
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

        response = await client.get("/api/v1/vault/notes", headers=user_auth_headers)
        data = response.json()
        assert not any(n["id"] == note.id for n in data)

    async def test_note_content_max_length(self, client: AsyncClient, user_auth_headers):
        long_content = "x" * 10001
        response = await client.post("/api/v1/vault/notes", headers=user_auth_headers, json={
            "title": "Test",
            "content": long_content,
        })
        assert response.status_code == 422

    async def test_note_title_max_length(self, client: AsyncClient, user_auth_headers):
        long_title = "x" * 256
        response = await client.post("/api/v1/vault/notes", headers=user_auth_headers, json={
            "title": long_title,
            "content": "Content",
        })
        assert response.status_code == 422