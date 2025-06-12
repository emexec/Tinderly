from datetime import datetime
from pydantic import BaseModel, EmailStr, UUID4

class User(BaseModel):
    gender: str
    name: str
    date_of_birth: datetime
    relationship_priority: str
    email: EmailStr
    subscription: bool

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


class TokenData(BaseModel):
    username: str | None = None
