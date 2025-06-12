from typing import TypeVar, Generic, Type, Optional, List, Union
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from .models import User

ModelType = TypeVar("ModelType")
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)

class CRUDBase(Generic[ModelType]):
    def __init__(self, model: Type[ModelType]):
        self.model = model

    async def create(
        self,
        db: AsyncSession,
        obj_in: Union[dict, CreateSchemaType]
    ) -> ModelType:
        if isinstance(obj_in, BaseModel):
            obj_in_data = obj_in.dict(exclude_unset=True)
        else:
            obj_in_data = obj_in

        db_obj = self.model(**obj_in_data)
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def get(self, db: AsyncSession, id: UUID) -> Optional[ModelType]:
        query = select(self.model).where(self.model.id == id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_all(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100
    ) -> List[ModelType]:
        query = select(self.model).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

    async def update(
        self,
        db: AsyncSession,
        id: UUID,
        obj_in: Union[dict, UpdateSchemaType]
    ) -> Optional[ModelType]:
        db_obj = await self.get(db, id)
        if not db_obj:
            return None

        if isinstance(obj_in, BaseModel):
            obj_in_data = obj_in.dict(exclude_unset=True)
        else:
            obj_in_data = obj_in

        for key, value in obj_in_data.items():
            setattr(db_obj, key, value)

        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def delete(self, db: AsyncSession, id: UUID) -> Optional[ModelType]:
        db_obj = await self.get(db, id)
        if not db_obj:
            return None

        await db.delete(db_obj)
        await db.commit()
        return db_obj

UserCRUD = CRUDBase(model=User)