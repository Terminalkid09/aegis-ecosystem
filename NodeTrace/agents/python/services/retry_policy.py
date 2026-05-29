import time
from utils.logger import Logger

def retry(max_attempts, base_delay):
    def decorator(func):
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    Logger.error(f"Error: {e} (attempt {attempts}/{max_attempts})")
                    time.sleep(base_delay * attempts)
            raise Exception("Max retry attempts reached")
        return wrapper
    return decorator