import random
import time
import uuid
import hashlib
from locust import HttpUser, task, between

class AegisBrainUser(HttpUser):
    """
    Simulates realistic load on Aegis-Brain Modular Monolith.
    - 70% Telemetry (Agents)
    - 20% AI Chat (Users)
    - 10% OSINT History (Analysts)
    """
    wait_time = between(1, 3)
    
    # Pre-calculated token for AI/OSINT (simulating an authenticated session)
    # In a real scenario, this would be fetched via login task
    auth_headers = {
        "Authorization": "Bearer test-token-placeholder"
    }

    def on_start(self):
        """Setup initial data for the user session."""
        self.device_id = str(uuid.uuid4())
        # Simulate a registered agent token
        self.agent_token = "secret-agent-token"
        self.agent_headers = {
            "X-Agent-Id": self.device_id,
            "Authorization": f"Bearer {self.agent_token}"
        }

    @task(7)
    def telemetry_report(self):
        """
        Simulate Agent Telemetry Ingestion (NodeTrace).
        Stress tests Async DB and AnomalyEngine concurrency.
        """
        # Generate random metrics with occasional spikes
        cpu = random.uniform(10.0, 40.0)
        if random.random() > 0.9:  # 10% chance of a spike
            cpu = random.uniform(80.0, 95.0)
            
        payload = {
            "device_id": self.device_id,
            "cpu_usage": cpu,
            "ram_usage": random.uniform(20.0, 60.0),
            "disk_free": random.randint(1000000, 5000000),
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            "processes": [{"pid": 123, "name": "system-worker"}]
        }
        
        with self.client.post(
            "/api/v1/telemetry/report", 
            json=payload, 
            headers=self.agent_headers,
            name="/telemetry/report"
        ) as response:
            if response.status_code != 200:
                response.failure(f"Telemetry failed: {response.status_code}")

    @task(2)
    def ai_chat(self):
        """
        Simulate AI Chat Requests (AI-Suite).
        Stress tests Async Redis Rate-Limiting.
        """
        prompts = [
            "Explain the latest security trends.",
            "Analyze these logs for anomalies.",
            "How do I prevent SQL injection?",
            "What is a Z-Score anomaly?"
        ]
        
        payload = {
            "prompt": random.choice(prompts),
            "model": "aegis-stress-test"
        }
        
        # We use a shared auth header to test rate-limiting thresholds
        with self.client.post(
            "/api/v1/ai/chat", 
            json=payload, 
            headers=self.auth_headers,
            name="/ai/chat"
        ) as response:
            # 429 is expected if rate limit is hit
            if response.status_code == 429:
                response.success()
            elif response.status_code != 200:
                response.failure(f"AI Chat failed: {response.status_code}")

    @task(1)
    def osint_history(self):
        """
        Simulate OSINT History Browsing (SentinelX).
        Stress tests Async DB pagination and large query results.
        """
        params = {
            "limit": random.choice([10, 20, 50]),
            "offset": random.randint(0, 100)
        }
        
        with self.client.get(
            "/api/v1/osint/history", 
            params=params, 
            headers=self.auth_headers,
            name="/osint/history"
        ) as response:
            if response.status_code != 200 and response.status_code != 501: # 501 if not fully implemented in some versions
                 response.failure(f"OSINT History failed: {response.status_code}")
