from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException

from .api.auth import router_auth
from .database.crud import UserCRUD
from .database.sessions import init_db, drop_db, get_async_session, AsyncSession
from .database.models import GenderEnum, RelationshipPriorityEnum  # Импортируй свои Enum'ы

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await drop_db()

app = FastAPI(lifespan=lifespan)

app.include_router(router=router_auth)


@app.get("/health")
async def health_check(session: Annotated[AsyncSession, Depends(get_async_session)]):
    sample_data = {
        "id": "a3b5c7d8-e9f0-4a1b-91c2-3d4e5f678901",
        "gender": GenderEnum.MALE,
        "name": "Ivan Petrov",
        "date_of_birth": datetime(1995, 5, 15),
        "relationship_priority": RelationshipPriorityEnum.FAMILY,
        "email": "ivan.petrov@example.com",
        "is_active": True
    }
    try:
        await UserCRUD.create(db=session, obj_in=sample_data)
        user = await UserCRUD.get(db=session, id="a3b5c7d8-e9f0-4a1b-91c2-3d4e5f678901")
        return {"status": "healthy", "user": user.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {e}")


"""
Добавить докерфайлы и докеркомпос
Настроить api/auth.py так, чтобы была интегрирована базаданных и
Понять что к чему т.к. надо заменить алгоритм, и решить как это в куках хранить.
"""