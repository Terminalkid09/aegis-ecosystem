from loguru import logger
from app.core.config import settings


class TelegramService:
    def __init__(self):
        self._bot = None

    def _get_bot(self):
        if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
            return None
        if self._bot is None:
            try:
                from telegram import Bot
                self._bot = Bot(token=settings.TELEGRAM_BOT_TOKEN)
            except Exception as e:
                logger.error(f"Telegram bot init error: {e}")
        return self._bot

    async def send_alert(self, event_data: dict):
        bot = self._get_bot()
        if not bot:
            logger.debug("Telegram not configured, skipping alert.")
            return

        sensor  = event_data.get("sensor_type", "unknown").upper()
        ip      = event_data.get("attacker_ip", "?")
        country = event_data.get("country") or "Unknown"
        city    = event_data.get("city") or "Unknown"
        sid     = event_data.get("session_id", "?")
        user    = event_data.get("username") or "—"

        message = (
            f"*KRAKEN ALERT*\n"
            f"━━━━━━━━━━━━━━━\n"
            f"Sensor: {sensor}\n"
            f"IP: {ip}\n"
            f"Location: {city}, {country}\n"
            f"User: {user}\n"
            f"Session: {sid}\n"
            f"━━━━━━━━━━━━━━━\n"
            f"_Kraken Honeypot_"
        )

        try:
            await bot.send_message(
                chat_id=settings.TELEGRAM_CHAT_ID,
                text=message,
                parse_mode="Markdown",
            )
        except Exception as e:
            logger.error(f"Telegram send_message error: {e}")


telegram_service = TelegramService()
