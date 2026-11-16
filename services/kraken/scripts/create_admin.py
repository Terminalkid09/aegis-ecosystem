"""
Create the first admin user.
Usage:
    python scripts/create_admin.py <username> <password>
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from app.db.session import AsyncSessionLocal, init_db
from app.models.models import User
from app.core.security import hash_password


async def create_admin(username: str, password: str):
    if len(password) < 8:
        print("❌ Password must be at least 8 characters.")
        sys.exit(1)
    await init_db()
    async with AsyncSessionLocal() as db:
        exists = await db.scalar(select(User).where(User.username == username))
        if exists:
            print(f"❌ User '{username}' already exists.")
            return
        user = User(
            username=username,
            hashed_password=hash_password(password),
            is_active=True,
            is_admin=True,
        )
        db.add(user)
        await db.commit()
        print(f"✅ Admin user '{username}' created successfully.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/create_admin.py <username> <password>")
        sys.exit(1)
    asyncio.run(create_admin(sys.argv[1], sys.argv[2]))
