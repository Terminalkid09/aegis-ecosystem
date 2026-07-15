from loguru import logger

WEBHOOK_URL = None


async def on_attack_ingested(attack_event: dict, **kwargs) -> None:
    global WEBHOOK_URL
    if not WEBHOOK_URL:
        return

    ip = attack_event.get("attacker_ip", "?")
    sensor = (attack_event.get("sensor_type") or "?").upper()
    country = attack_event.get("country") or "Unknown"

    message = (
        f":warning: *New Attack Detected*\n"
        f"• IP: `{ip}`\n"
        f"• Sensor: `{sensor}`\n"
        f"• Country: {country}\n"
        f"• Commands: {len(attack_event.get('commands') or [])}"
    )

    try:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(WEBHOOK_URL, json={"text": message})
            resp.raise_for_status()
        logger.info(f"[SlackNotifier] Alert sent for {ip}")
    except Exception as e:
        logger.error(f"[SlackNotifier] Failed to send alert: {e}")


async def on_system_startup(**kwargs) -> None:
    logger.info("[SlackNotifier] Plugin initialized (webhook: {})".format(
        "configured" if WEBHOOK_URL else "NOT configured — set config.webhook_url"
    ))
