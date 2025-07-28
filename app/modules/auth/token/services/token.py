"""
Token service for handling JWT token operations.
Provides functionality for token refresh and validation.
"""

from datetime import timedelta
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from app.modules.auth.token.schemas.token import TokenRefreshResponse
from app.modules.core.config import settings
from app.modules.core.security import create_access_token

class TokenService:
    """Service class for token operations."""

    def __init__(self, db: Session):
        self.db = db

    def verify_refresh_token(self, refresh_token: str):
        """
        Verify refresh token and return associated user.

        Args:
            refresh_token: JWT refresh token

        Returns:
            User object if token is valid, None otherwise
        """
        try:
            payload = jwt.decode(
                refresh_token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            username: str = payload.get("sub")
            if username is None:
                return None

            # Get user from database
            from ...user.models.user import User
            user = self.db.query(User).filter(User.username == username).first()
            return user

        except JWTError:
            return None

    def create_token_refresh_response(self, user) -> TokenRefreshResponse:
        """
        Create token refresh response with new access token.

        Args:
            user: User object

        Returns:
            TokenRefreshResponse with new access token
        """
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires
        )

        return TokenRefreshResponse(
            access_token=new_access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )