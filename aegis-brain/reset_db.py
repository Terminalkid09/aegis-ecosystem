"""Reset the database: drop everything, stamp base, and migrate fresh."""
from app.database.connection import engine, Base
from sqlalchemy import text
import asyncio

async def reset():
    async with engine.begin() as conn:
        # Drop all tables
        await conn.run_sync(Base.metadata.drop_all)
        # Drop alembic_version
        await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
        print("Database reset complete. Run 'alembic upgrade head' now.")

asyncio.run(reset())
