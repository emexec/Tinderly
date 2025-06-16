from enum import Enum

class GenderEnum(Enum):
    MALE = "male"
    FEMALE = "female"

class RelationshipPriorityEnum(Enum):
    FAMILY = "family"
    FRIENDSHIP = "friendship"
    LOVE = "love"

class RoleEnum(Enum):
    ADMIN = "admin"
    USER = "user"
    SUPER_USER = "super_user"
    