"""
Pydantic schemas for user operations.
Defines data structures for user creation, updates, and password changes.
"""

from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional

class PasswordChangeRequest(BaseModel):
    """
    Request schema for password change.

    Attributes:
        current_password: Current password
        new_password: New password
        confirm_password: Password confirmation
    """
    current_password: str
    new_password: str
    confirm_password: str

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('New password must be at least 8 characters long')
        return v

    @field_validator('confirm_password')
    @classmethod
    def validate_confirm_password(cls, v, info):
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v

class UserCreate(BaseModel):
    """
    Schema for creating a new user.

    Attributes:
        username: Username
        email: Email address
        password: Plain text password
        full_name: User's full name (optional)
    """
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Username cannot be empty')
        if len(v.strip()) < 3:
            raise ValueError('Username must be at least 3 characters long')
        return v.strip()

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v or len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserUpdate(BaseModel):
    """
    Schema for updating user information.

    Attributes:
        username: Username (optional)
        email: Email address (optional)
        full_name: User's full name (optional)
        is_active: Account status (optional)
    """
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is not None and (not v or len(v.strip()) == 0):
            raise ValueError('Username cannot be empty')
        if v is not None and len(v.strip()) < 3:
            raise ValueError('Username must be at least 3 characters long')
        return v.strip() if v else v

class UserResponse(BaseModel):
    """
    Schema for returning user details in API responses.
    """
    id: int
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True
