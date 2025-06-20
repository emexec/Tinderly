from datetime import date
from ..schemas.enums import GenderEnum, RelationshipPriorityEnum, RoleEnum
from uuid import UUID as UUID_type, uuid4

from sqlalchemy import Enum as PgEnum
from sqlalchemy import Date, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from .sessions import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID_type] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4)

    gender: Mapped[GenderEnum] = mapped_column(
        PgEnum(GenderEnum, name="gender_enum"), nullable=False)
    name: Mapped[str] = mapped_column(
        String(length=32), nullable=False, index=True)
    date_of_birth: Mapped[date] = mapped_column(
        Date, nullable=False)
    relationship_priority: Mapped[RelationshipPriorityEnum] = mapped_column(
        PgEnum(RelationshipPriorityEnum, name="relationship_priority_enum"), nullable=False)
    role: Mapped[RoleEnum] = mapped_column(
        PgEnum(RoleEnum, name="role_enum"), nullable=False, default=RoleEnum.USER)
    email: Mapped[str] = mapped_column(
        String(length=320), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    subscription: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    is_verified: Mapped[bool] = mapped_column(default=False)

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"