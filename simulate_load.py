import time
import math
import sys

print("[TEST] Simulating NodeTrace CPU Load Spike...")
print("[INFO] Generating heavy load for 60 seconds...")

# Anomaly engine needs min_samples=30. NodeTrace sends every 60s now.
# To see it quickly, I'll recommend the user to check the graph first.
duration = 60
end_time = time.time() + duration

try:
    while time.time() < end_time:
        # Intense math
        [math.exp(math.sqrt(i)) for i in range(50000)]
        # Small sleep to allow telemetry to actually be sent
        time.sleep(0.01)
    print("\n[SUCCESS] Load generation finished.")
except KeyboardInterrupt:
    print("\n[INFO] Test stopped by user.")
