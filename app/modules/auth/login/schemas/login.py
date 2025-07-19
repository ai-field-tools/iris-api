"""
Pydantic schemas for request/response validation in the login module.
Defines data structures for login requests, responses, and user information.
"""

from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime

class LoginRequest(BaseModel):
    """
    Request schema for user login.

    Attributes:
        username: Username or email address
        password: Plain text password
    """
    username: str
    password: str

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Username cannot be empty')
        return v.strip()

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v or len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

class UserInfo(BaseModel):
    """
    User information schema for responses.

    Attributes:
        id: User ID
        username: Username
        email: Email address
        full_name: User's full name
        is_active: Account status
        created_at: Account creation timestamp
        last_login: Last login timestamp
    """
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}

class LoginResponse(BaseModel):
    """
    Response schema for successful login.

    Attributes:
        access_token: JWT access token
        refresh_token: JWT refresh token
        token_type: Token type (always "bearer")
        expires_in: Token expiration time in seconds
        user: User information
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserInfo

class LoginError(BaseModel):
    """
    Error response schema for login failures.

    Attributes:
        detail: Error message
        error_code: Specific error code
        timestamp: Error timestamp
    """
    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = datetime.utcnow()

class LoginHistorySchema(BaseModel):
    """
    Schema for login history records.

    Attributes:
        id: History record ID
        user_id: User ID
        login_at: Login timestamp
        ip_address: Client IP address
        user_agent: User agent string
        success: Whether login was successful
        failure_reason: Reason for failure (if applicable)
    """
    id: int
    user_id: int
    login_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool
    failure_reason: Optional[str] = None

    model_config = {"from_attributes": True}