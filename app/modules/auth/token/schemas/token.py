"""
Pydantic schemas for token operations.
Defines data structures for token refresh requests and responses.
"""

from pydantic import BaseModel, field_validator

class TokenRefreshRequest(BaseModel):
    """
    Request schema for token refresh.

    Attributes:
        refresh_token: JWT refresh token
    """
    refresh_token: str

    @field_validator('refresh_token')
    @classmethod
    def validate_refresh_token(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Refresh token cannot be empty')
        return v.strip()

class TokenRefreshResponse(BaseModel):
    """
    Response schema for token refresh.

    Attributes:
        access_token: New JWT access token
        token_type: Token type (always "bearer")
        expires_in: Token expiration time in seconds
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int