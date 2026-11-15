"""
Seed the database with realistic demo attack data.
Usage:
    python scripts/seed_demo.py
"""
import asyncio
import sys
import os
import uuid
import random
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import AsyncSessionLocal, init_db
from app.models.models import AttackEvent, CredentialAttempt, AttackCommand

SENSOR_TYPES = ["ssh", "http", "ftp", "telnet"]
COUNTRIES = [
    ("China", "Beijing", 39.9, 116.4),
    ("Russia", "Moscow", 55.7, 37.6),
    ("United States", "New York", 40.7, -74.0),
    ("Brazil", "São Paulo", -23.5, -46.6),
    ("Germany", "Frankfurt", 50.1, 8.7),
    ("India", "Mumbai", 19.1, 72.9),
    ("Netherlands", "Amsterdam", 52.4, 4.9),
    ("Ukraine", "Kyiv", 50.5, 30.5),
    ("Iran", "Tehran", 35.7, 51.4),
    ("Romania", "Bucharest", 44.4, 26.1),
]
SSH_USERS = ["root", "admin", "ubuntu", "user", "pi", "oracle", "postgres", "test"]
SSH_PASSES = ["root", "admin", "123456", "password", "toor", "raspberry", "letmein"]
HTTP_PATHS = [
    "GET /.env", "GET /wp-login.php", "GET /admin",
    "GET /phpmyadmin", "POST /xmlrpc.php", "GET /.git/config",
    "GET /config.php", "GET /backup.zip",
]
FTP_USERS = ["anonymous", "ftp", "admin", "user"]


async def seed():
    await init_db()
    async with AsyncSessionLocal() as db:
        events_created = 0
        now = datetime.now(timezone.utc)

        for day_offset in range(30):
            day = now - timedelta(days=day_offset)
            daily_count = random.randint(5, 40)

            for _ in range(daily_count):
                sensor = random.choice(SENSOR_TYPES)
                country, city, lat, lng = random.choice(COUNTRIES)
                ts = day - timedelta(
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59),
                )
                ip = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

                event = AttackEvent(
                    session_id=str(uuid.uuid4()),
                    attacker_ip=ip,
                    attacker_port=random.randint(1024, 65535),
                    sensor_type=sensor,
                    sensor_port={"ssh": 2222, "http": 8080, "ftp": 2121, "telnet": 2323}[sensor],
                    timestamp_start=ts,
                    country=country,
                    city=city,
                    latitude=lat + random.uniform(-2, 2),
                    longitude=lng + random.uniform(-2, 2),
                    is_known_threat=random.random() < 0.1,
                )
                db.add(event)
                await db.flush()

                if sensor in ("ssh", "ftp", "telnet"):
                    db.add(CredentialAttempt(
                        event_id=event.id,
                        username=random.choice(SSH_USERS),
                        password=random.choice(SSH_PASSES),
                    ))

                if sensor == "http":
                    for path in random.sample(HTTP_PATHS, k=random.randint(1, 3)):
                        db.add(AttackCommand(event_id=event.id, command=path))

                events_created += 1

        await db.commit()
        print(f"✅ Seeded {events_created} demo attack events across 30 days.")


if __name__ == "__main__":
    asyncio.run(seed())
