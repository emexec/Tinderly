from datetime import date

from pydantic import BaseModel, EmailStr, constr
from .enums import GenderEnum, RelationshipPriorityEnum

class FormEmailUpdate(BaseModel):
    password: str
    new_email: EmailStr

class FormPasswordUpdate(BaseModel):
    password: str
    new_password: constr(min_length=8)

class FormUserCreate(BaseModel):
    gender: GenderEnum
    name: constr(min_length=3, max_length=30)
    date_of_birth: date
    relationship_priority: RelationshipPriorityEnum
    email: EmailStr
    password: constr(min_length=8)




