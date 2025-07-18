"""
This module contains the business logic for user authentication and login operations.
It handles password verification, JWT token generation, login attempt validation,
and security features like rate limiting and account lockout.

Dependencies: SQLAlchemy, passlib, python-jose
"""

from typing import Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from ..schemas.login import LoginResponse, UserInfo
from passlib.context import CryptContext
from jose import jwt

from ...user.models.user import User
from ....core.config import settings
from ....core.security import create_access_token, create_refresh_token, verify_password

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginService:
    """Service class for login operations."""

    def __init__(self, db: Session):
        self.db = db

    def authenticate_user(self, username: str, password: str):
        """
        Authenticate user with username/email and password.

        Args:
            username: Username or email
            password: Plain text password

        Returns:
            User object if authentication successful, None otherwise
        """
        # find user by username or email
        user = (
            self.db.query(User)
            .filter((User.username == username) | (User.email == username))
            .first()
        )

        if not user or not verify_password(password, user.hashed_password):
            return None

        return user

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify plain text password against hashed password.
        """
        return pwd_context.verify(plain_password, hashed_password)

    def create_access_token(
        self, user: User, expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token for authenticated user.
        """
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "iat": datetime.now(timezone.utc),
        }

        expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        token_data["exp"] = expire

        encoded_jwt = jwt.encode(
            token_data, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )
        return encoded_jwt

    def validate_login_attempt(self, username: str, ip_address: str) -> bool:
        """
        Validate if login attempt is allowed (rate limiting, account lockout).
        """
        fifteen_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
        recent_attempts = (
            self.db.query(User)
            .filter(User.username == username)
            .filter(User.failed_login_attempts >= 5)
            .filter(User.last_failed_login > fifteen_minutes_ago)
            .first()
        )

        return recent_attempts is None

    def record_failed_login(self, username: str, ip_address: str):
        """
        Record failed login attempt for security monitoring.
        """
        user = self.db.query(User).filter(User.username == username).first()

        if user:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now(timezone.utc)
            self.db.commit()

    def reset_failed_login_attempts(self, user: User):
        """
        Reset failed login attempts counter after successful login.
        """
        user.failed_login_attempts = 0
        user.last_failed_login = None
        self.db.commit()

    def get_user_info(self, user) -> UserInfo:
        """
        Get user information for response.

        Args:
            user: User object

        Returns:
            UserInfo schema
        """
        return UserInfo(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login=user.last_login,
        )

    def create_login_response(self, user) -> LoginResponse:
        """
        Create complete login response with tokens and user info.

        Args:
            user: User object

        Returns:
            LoginResponse with tokens and user info
        """
        # Generate JWT tokens
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(data={"sub": user.username})

        user_info = self.get_user_info(user)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user_info,
        )
