import os
from typing import AsyncGenerator
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.ext.asyncio import (AsyncSession,
                                    async_sessionmaker,
                                    create_async_engine,
                                    AsyncAttrs)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ..core.config import settings

database_url = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASS}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/database"
engine = create_async_engine(url=database_url)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession)

class Base(AsyncAttrs, DeclarativeBase):
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Make the async session db"""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """Initialize the database by creating all tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def drop_db():
    """Drop all tables in the database"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
