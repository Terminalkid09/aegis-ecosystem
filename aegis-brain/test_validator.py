from api.schemas import AgentResponse
from uuid import UUID
from datetime import datetime, timezone

# Simulate a database row response
test_agent = {
    "agent_id": UUID("550e8400-e29b-41d4-a716-446655440000"),
    "hostname": None,
    "ip_address": None,
    "os_type": "Linux",
    "last_seen": datetime.now(timezone.utc)
}

# Try to create a response
try:
    response = AgentResponse.model_validate(test_agent)
    print(f"Success! agent_id type: {type(response.agent_id)}, value: {response.agent_id}")
    print(f"JSON: {response.model_dump_json()}")
except Exception as e:
    print(f"Error: {e}")
