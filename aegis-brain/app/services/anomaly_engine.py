import numpy as np
from collections import deque
from typing import Dict, List, Optional
from app.core.logging import get_logger

logger = get_logger(__name__)

class AnomalyEngine:
    def __init__(self, window_size: int = 60, threshold: float = 3.0, min_samples: int = 30):
        self.window_size = window_size
        self.threshold = threshold
        self.min_samples = min_samples
        # Store historical data for each agent and metric
        # Format: {agent_id: {metric_name: deque([val1, val2, ...])}}
        self.history: Dict[str, Dict[str, deque]] = {}

    def analyze(self, agent_id: str, metrics: Dict[str, float]) -> List[Dict[str, any]]:
        """
        Analyze metrics for a specific agent and return a list of detected anomalies.
        """
        anomalies = []
        if agent_id not in self.history:
            self.history[agent_id] = {}

        for metric_name, value in metrics.items():
            if metric_name not in self.history[agent_id]:
                self.history[agent_id][metric_name] = deque(maxlen=self.window_size)
            
            history = self.history[agent_id][metric_name]
            
            # Check for anomaly if we have enough samples
            if len(history) >= self.min_samples:
                mean = np.mean(history)
                std = np.std(history)
                
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
            
            # Update history
            history.append(value)
            
        return anomalies

anomaly_engine = AnomalyEngine()
