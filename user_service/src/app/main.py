from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException

from .api.auth import router_auth
from .database.crud import UserCRUD
from .database.sessions import init_db, drop_db, get_async_session, AsyncSession

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     await init_db()
#     yield
#     await drop_db()

app = FastAPI() # lifespan=lifespan

app.include_router(router=router_auth)


@app.get("/health")
async def health_check(session: Annotated[AsyncSession, Depends(get_async_session)]):
    try:
        # user = UserCRUD.get_all(db=session)
        return {"status": "healthy"}
    except Exception:
        raise HTTPException(status_code=500, detail="Database connection failed")


"""
Добавить докерфайлы и докеркомпос
Настроить api/auth.py так, чтобы была интегрирована базаданных и
Понять что к чему т.к. надо заменить алгоритм, и решить как это в куках хранить.
"""