from loguru import logger
from app.core.config import settings

KNOWN_BAD_IPS = {
    "10.0.0.1",
    "192.168.1.100",
    "203.0.113.0",
    "198.51.100.0",
}

KNOWN_BAD_NETWORKS = ["10.0.0.0/8", "192.168.0.0/16"]


async def on_attack_ingested(attack_event: dict, **kwargs) -> dict | None:
    ip = attack_event.get("attacker_ip", "")
    tags = []

    if ip in KNOWN_BAD_IPS:
        tags.append("known_threat")
        logger.info(f"[ThreatEnricher] Known bad IP: {ip}")

    for net in KNOWN_BAD_NETWORKS:
        if ip.startswith(net.split(".")[0]):
            tags.append("suspicious_network")
            break

    if attack_event.get("username") == "admin":
        tags.append("admin_brute_force")

    if len(attack_event.get("commands") or []) > 5:
        tags.append("high_activity")

    if tags:
        attack_event["threat_tags"] = ",".join(tags) if attack_event.get("threat_tags") else ",".join(tags)
        attack_event["is_known_threat"] = True
        logger.info(f"[ThreatEnricher] Tags added for {ip}: {tags}")

    return attack_event


async def on_system_startup(**kwargs) -> None:
    logger.info("[ThreatEnricher] Plugin initialized — {len(KNOWN_BAD_IPS)} known bad IPs loaded")
