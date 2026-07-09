from app.database.connection import engine
from sqlalchemy import text
import asyncio

async def check():
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name"))
        tables = result.fetchall()
        print('Tables in DB:', [r[0] for r in tables])
        
        result = await conn.execute(text("SELECT version_num FROM alembic_version"))
        row = result.fetchone()
        print('Alembic version:', row[0] if row else 'NONE')

asyncio.run(check())
