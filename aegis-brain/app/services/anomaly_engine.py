import numpy as np
import json
from collections import deque
from typing import Dict, List, Optional
from app.core.logging import get_logger
from app.core.config import settings
from app.core.redis_utils import get_redis_url
import redis.asyncio as redis

logger = get_logger(__name__)

class AnomalyEngine:
    def __init__(self, window_size: int = 60, threshold: float = 4.0, min_samples: int = 60):
        self.window_size = window_size
        self.threshold = threshold
        self.min_samples = min_samples
        # In-memory cache for performance
        self._cache: Dict[str, Dict[str, deque]] = {}
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
            # Get last window_size entries
            data = await rc.zrange(key, -self.window_size, -1, withscores=True)
            return [float(score) for _, score in data]
        except Exception as e:
            logger.warning(f"Failed to load anomaly history: {e}")
            return []

    async def _save_value(self, agent_id: str, metric_name: str, timestamp: float, value: float):
        """Save value to Redis sorted set."""
        rc = await self._get_redis()
        key = f"anomaly:{agent_id}:{metric_name}"
        try:
            await rc.zadd(key, {str(timestamp): value})
            # Trim to window_size
            await rc.zremrangebyrank(key, 0, -self.window_size - 1)
        except Exception as e:
            logger.warning(f"Failed to save anomaly value: {e}")

    def _get_cache(self, agent_id: str, metric_name: str) -> deque:
        if agent_id not in self._cache:
            self._cache[agent_id] = {}
        if metric_name not in self._cache[agent_id]:
            self._cache[agent_id][metric_name] = deque(maxlen=self.window_size)
        return self._cache[agent_id][metric_name]

    async def analyze(self, agent_id: str, metrics: Dict[str, float]) -> List[Dict[str, any]]:
        """
        Analyze metrics for a specific agent and return a list of detected anomalies.
        """
        import time
        anomalies = []
        timestamp = time.time()

        for metric_name, value in metrics.items():
            history_deque = self._get_cache(agent_id, metric_name)
            
            # If cache is empty, load from Redis
            if not history_deque:
                history_list = await self._load_history(agent_id, metric_name)
                history_deque.extend(history_list)
            
            # Check for anomaly if we have enough samples
            if len(history_deque) >= self.min_samples:
                mean = np.mean(history_deque)
                std = np.std(history_deque, ddof=1)
                
                if std > 0:
                    z_score = abs(value - mean) / std
                    if z_score > self.threshold:
                        logger.warning(f"Anomaly detected for agent {agent_id}: {metric_name}={value} (z-score={z_score:.2f})")
                        anomalies.append({
                            "metric": metric_name,
                            "value": value,
                            "z_score": round(z_score, 2),
                            "severity": "HIGH" if z_score > self.threshold * 1.5 else "MEDIUM",
                            "summary": f"High {metric_name} detected: {value:.1f} (Z-Score: {z_score:.1f})"
                        })
            
            # Update cache
            history_deque.append(value)
            
            # Persist to Redis
            await self._save_value(agent_id, metric_name, timestamp, value)
            
        return anomalies

anomaly_engine = AnomalyEngine()
