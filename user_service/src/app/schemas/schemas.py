from datetime import datetime
from pydantic import BaseModel, EmailStr, UUID4

class UserBase(BaseModel):
    gender: str
    name: str
    date_of_birth: datetime
    relationship_priority: str
    email: EmailStr
    subscription: bool

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    id: UUID4
    hashed_password: str

class UserPublic(UserBase):
    id: UUID4

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None
