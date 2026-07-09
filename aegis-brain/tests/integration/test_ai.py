import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock
from app.database.models import AIThread, AIMessage
from datetime import datetime, timezone


class TestAI:
    @patch("app.services.ai_service.generate_ai_response")
    async def test_chat_success(self, mock_generate, client: AsyncClient, user_auth_headers, db_session, test_user):
        mock_generate.return_value = {
            "answer": "AI response about security",
            "model_used": "llama3",
            "model": "llama3"
        }

        response = await client.post("/api/v1/ai/chat", headers=user_auth_headers, json={
            "prompt": "How to secure a Linux server?",
            "model": "llama3"
        })
        assert response.status_code == 200
        data = response.json()
        assert "answer" in data
        assert data["answer"] == "AI response about security"
        assert "thread_id" in data

        mock_generate.assert_called_once()

    @patch("app.services.ai_service.generate_ai_response")
    async def test_chat_creates_thread(self, mock_generate, client: AsyncClient, user_auth_headers, db_session, test_user):
        mock_generate.return_value = {"answer": "Response", "model_used": "llama3"}

        response = await client.post("/api/v1/ai/chat", headers=user_auth_headers, json={
            "prompt": "First message",
            "title": "Security Chat"
        })
        assert response.status_code == 200
        data = response.json()
        thread_id = data["thread_id"]

        from sqlalchemy import select
        result = await db_session.execute(select(AIThread).where(AIThread.id == thread_id))
        thread = result.scalar_one()
        assert thread.title == "Security Chat"
        assert thread.user_id == test_user.id

    async def test_chat_prompt_too_long(self, client: AsyncClient, user_auth_headers):
        long_prompt = "x" * 8001
        response = await client.post("/api/v1/ai/chat", headers=user_auth_headers, json={
            "prompt": long_prompt
        })
        assert response.status_code == 422

    @patch("app.services.ai_service.generate_ai_response")
    async def test_chat_rate_limit(self, mock_generate, client: AsyncClient, user_auth_headers):
        mock_generate.return_value = {"answer": "Response", "model_used": "llama3"}

        for i in range(25):
            response = await client.post("/api/v1/ai/chat", headers=user_auth_headers, json={
                "prompt": f"Question {i}"
            })
            if response.status_code == 429:
                break
        assert response.status_code == 429

    async def test_list_threads_empty(self, client: AsyncClient, user_auth_headers):
        response = await client.get("/api/v1/ai/threads", headers=user_auth_headers)
        assert response.status_code == 200
        assert response.json() == []

    async def test_list_threads(self, client: AsyncClient, user_auth_headers, db_session, test_user):
        thread = AIThread(user_id=test_user.id, title="Test Thread")
        db_session.add(thread)
        await db_session.commit()

        response = await client.get("/api/v1/ai/threads", headers=user_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["title"] == "Test Thread"

    async def test_get_thread_messages(self, client: AsyncClient, user_auth_headers, db_session, test_user):
        thread = AIThread(user_id=test_user.id, title="Thread with messages")
        db_session.add(thread)
        await db_session.flush()

        db_session.add(AIMessage(
            thread_id=thread.id, user_id=test_user.id,
            role="user", content="Hello", model="llama3"
        ))
        db_session.add(AIMessage(
            thread_id=thread.id, user_id=test_user.id,
            role="ai", content="Hi there!", model="llama3"
        ))
        await db_session.commit()

        response = await client.get(f"/api/v1/ai/threads/{thread.id}/messages", headers=user_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["role"] == "user"
        assert data[1]["role"] == "ai"

    async def test_get_nonexistent_thread(self, client: AsyncClient, user_auth_headers):
        response = await client.get("/api/v1/ai/threads/99999/messages", headers=user_auth_headers)
        assert response.status_code == 404