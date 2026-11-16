"""Fixed policy for containers created by the sandbox broker.

The application never sends a Docker HostConfig: the broker owns these values.
"""

SANDBOX_RUN_KWARGS = {
    "network_mode": "none",
    "security_opt": ["no-new-privileges:true"],
    "cap_drop": ["ALL"],
    "mem_limit": "128m",
    "pids_limit": 64,
    "cpu_period": 100000,
    "cpu_quota": 25000,
    "read_only": True,
    "tmpfs": {
        "/tmp": "rw,noexec,nosuid,size=64m",
        "/home/sandbox": "rw,noexec,nosuid,size=64m",
    },
}
