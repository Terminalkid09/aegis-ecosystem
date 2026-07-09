import pybreaker
import logging
from typing import Callable, Any
from functools import wraps

logger = logging.getLogger(__name__)

class CircuitBreakerConfig:
    FAIL_MAX = 5
    RESET_TIMEOUT = 30
    EXCLUDE = ()

class AegisCircuitBreakerListener(pybreaker.CircuitBreakerListener):
    def state_change(self, cb: pybreaker.CircuitBreaker, old_state: str, new_state: str) -> None:
        logger.warning(
            "Circuit breaker state change",
            extra={"circuit_breaker": cb.name, "old_state": old_state, "new_state": new_state},
        )

    def failure(self, cb: pybreaker.CircuitBreaker, exc: Exception) -> None:
        logger.warning(
            "Circuit breaker failure",
            extra={"circuit_breaker": cb.name, "error": str(exc)},
        )

_listener = AegisCircuitBreakerListener()

ollama_breaker = pybreaker.CircuitBreaker(
    fail_max=CircuitBreakerConfig.FAIL_MAX,
    reset_timeout=CircuitBreakerConfig.RESET_TIMEOUT,
    exclude=CircuitBreakerConfig.EXCLUDE,
    listeners=[_listener],
    name="ollama",
)

redis_breaker = pybreaker.CircuitBreaker(
    fail_max=CircuitBreakerConfig.FAIL_MAX,
    reset_timeout=CircuitBreakerConfig.RESET_TIMEOUT,
    exclude=CircuitBreakerConfig.EXCLUDE,
    listeners=[_listener],
    name="redis",
)

postgres_breaker = pybreaker.CircuitBreaker(
    fail_max=CircuitBreakerConfig.FAIL_MAX,
    reset_timeout=CircuitBreakerConfig.RESET_TIMEOUT,
    exclude=CircuitBreakerConfig.EXCLUDE,
    listeners=[_listener],
    name="postgres",
)

def with_circuit_breaker(breaker: pybreaker.CircuitBreaker):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            return breaker.call(func, *args, **kwargs)
        return wrapper
    return decorator

async def with_async_circuit_breaker(breaker: pybreaker.CircuitBreaker):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            return await breaker.call_async(func, *args, **kwargs)
        return wrapper
    return decorator

def get_breaker_status() -> dict:
    return {
        "ollama": {"state": ollama_breaker.current_state, "fail_count": ollama_breaker.fail_counter},
        "redis": {"state": redis_breaker.current_state, "fail_count": redis_breaker.fail_counter},
        "postgres": {"state": postgres_breaker.current_state, "fail_count": postgres_breaker.fail_counter},
    }
