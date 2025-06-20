from datetime import date
from pydantic import BaseModel, EmailStr, UUID4

class User(BaseModel):
    gender: str
    name: str
    date_of_birth: date
    relationship_priority: str
    email: EmailStr
    role: str
    subscription: bool
    is_active: bool
    hashed_password: str
    is_verified: bool

class UserCreate(User):
    password: str

class UserInDB(User):
    id: UUID4

class Token(BaseModel):
    access_token: str
    token_type: str

class UserOut(BaseModel):
    id: UUID4
    email: EmailStr
    name: str

class TokenData(BaseModel):
    email: EmailStr

class EmailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str
