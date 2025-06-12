from datetime import datetime
from enum import Enum
from uuid import UUID as UUID_type, uuid4

from sqlalchemy import Enum as PgEnum
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from .sessions import Base

class GenderEnum(Enum):
    MALE = "male"
    FEMALE = "female"

class RelationshipPriorityEnum(Enum):
    FAMILY = "family"
    FRIENDSHIP = "friendship"
    LOVE = "love"


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID_type] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4)

    gender: Mapped[GenderEnum] = mapped_column(
        PgEnum(GenderEnum, name="gender_enum"), nullable=False)
    name: Mapped[str] = mapped_column(
        String(length=32), nullable=False, index=True)
    date_of_birth: Mapped[datetime] = mapped_column(
        DateTime, nullable=False)
    relationship_priority: Mapped[RelationshipPriorityEnum] = mapped_column(
        PgEnum(RelationshipPriorityEnum, name="relationship_priority_enum"), nullable=False)
    email: Mapped[str] = mapped_column(
        String(length=320), unique=True, index=True, nullable=False)

    is_active: Mapped[bool] = mapped_column(default=True)

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"
