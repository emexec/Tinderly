from datetime import date
from pydantic import BaseModel, EmailStr, UUID4, ConfigDict

class User(BaseModel):
    gender: str
    name: str
    date_of_birth: date
    relationship_priority: str
    email: EmailStr
    role: str
    subscription: bool
    is_active: bool

class UserCreate(User):
    password: str

class UserInDB(User):
    id: UUID4
    hashed_password: str

class UserPublic(User):
    id: UUID4

class Token(BaseModel):
    access_token: str
    token_type: str

class UserOut(BaseModel):
    id: UUID4
    email: EmailStr
    name: str

    model_config = ConfigDict(from_attributes=True)

class TokenData(BaseModel):
    username: str | None = None
