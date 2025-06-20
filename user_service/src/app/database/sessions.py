from datetime import datetime
import enum
from typing import AsyncGenerator
import uuid

from sqlalchemy import func
from sqlalchemy.ext.asyncio import (AsyncSession,
                                    async_sessionmaker,
                                    create_async_engine,
                                    AsyncAttrs)
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ..core.config import database_url


engine = create_async_engine(url=database_url)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession)

class Base(AsyncAttrs, DeclarativeBase):
    def to_dict(self):
        result = {}
        for column in inspect(self).mapper.column_attrs:
            value = getattr(self, column.key)
            if isinstance(value, enum.Enum):
                result[column.key] = value.value
            elif isinstance(value, uuid.UUID):
                result[column.key] = str(value)
            elif isinstance(value, datetime):
                result[column.key] = value.isoformat()
            else:
                result[column.key] = value
        return result

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
