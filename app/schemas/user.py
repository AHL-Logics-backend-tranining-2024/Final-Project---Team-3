from pydantic import BaseModel, EmailStr, Field
from uuid import UUID
from datetime import datetime
from typing import Optional


class UserCreateRequest(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    password: Optional[str]


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: EmailStr
    is_admin: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        orm_mode = True
        arbitrary_types_allowed = True


class UserUpdateRequest(BaseModel):
    username: Optional[str] = Field(None)
    password: Optional[str] = Field(None)
    email: Optional[EmailStr] = Field(None)

    class Config:
        from_attributes = True
        orm_mode = True
        arbitrary_types_allowed = True
