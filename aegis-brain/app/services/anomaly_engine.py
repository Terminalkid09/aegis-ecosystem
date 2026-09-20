import numpy as np
import json
import uuid
import time
from typing import Dict, List, Optional
from app.core.logging import get_logger
from app.core.config import settings
from app.core.redis_utils import get_redis_url
import redis.asyncio as redis

logger = get_logger(__name__)

class AnomalyEngine:
    # Tuned for 10s heartbeat: 20 samples ≈ 3min to baseline (was 60 ≈ 10min,
    # never reached in practice). Threshold 3.0 sigma + HIGH at 4.5.
    def __init__(self, window_size: int = 60, threshold: float = 3.0, min_samples: int = 20):
        self.window_size = window_size
        self.threshold = threshold
        self.min_samples = min_samples
        self._redis_client = None

    async def _get_redis(self):
        if self._redis_client is None:
            self._redis_client = redis.from_url(get_redis_url(), decode_responses=True)
        return self._redis_client

    async def _load_history(self, agent_id: str, metric_name: str) -> List[float]:
        """Load history from Redis sorted set."""
        rc = await self._get_redis()
        key = f"anomaly:{agent_id}:{metric_name}"
        try:
            # Get all entries (already trimmed by zremrangebyrank)
            members = await rc.zrange(key, 0, -1)
            # member format is "value:uuid"
            return [float(m.split(":")[0]) for m in members]
        except Exception as e:
            logger.warning(f"Failed to load anomaly history: {e}")
            return []

    async def _save_value(self, agent_id: str, metric_name: str, timestamp: float, value: float):
        """Save value to Redis sorted set."""
        rc = await self._get_redis()
        key = f"anomaly:{agent_id}:{metric_name}"
        try:
            # Use timestamp as score for correct chronological ordering and trimming
            member = f"{value}:{uuid.uuid4().hex}"
            await rc.zadd(key, {member: timestamp})
            # Trim to window_size (remove lowest scores/oldest timestamps)
            await rc.zremrangebyrank(key, 0, -self.window_size - 1)
        except Exception as e:
            logger.warning(f"Failed to save anomaly value: {e}")

    async def analyze(self, agent_id: str, metrics: Dict[str, float]) -> List[Dict[str, any]]:
        """
        Analyze metrics for a specific agent and return a list of detected anomalies.
        """
        anomalies = []
        timestamp = time.time()

        for metric_name, value in metrics.items():
            # Load fresh from Redis (removes the buggy in-memory cache)
            history_list = await self._load_history(agent_id, metric_name)
            
            # Check for anomaly if we have enough samples
            if len(history_list) >= self.min_samples:
                mean = np.mean(history_list)
                std = np.std(history_list, ddof=1)
                
                if std > 0:
                    z_score = abs(value - mean) / std
                    if z_score > self.threshold:
                        logger.warning(f"Anomaly detected for agent {agent_id}: {metric_name}={value} (z-score={z_score:.2f})")
                        anomalies.append({
                            "metric": metric_name,
                            "value": value,
                            "z_score": round(z_score, 2),
                            "threshold": self.threshold,
                            "severity": "HIGH" if z_score > self.threshold * 1.5 else "MEDIUM",
                            "summary": f"High {metric_name} detected: {value:.1f} (Z-Score: {z_score:.1f})"
                        })
            
            # Persist to Redis
            await self._save_value(agent_id, metric_name, timestamp, value)
            
        return anomalies

anomaly_engine = AnomalyEngine()
