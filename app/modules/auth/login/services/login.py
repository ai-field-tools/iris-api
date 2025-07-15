"""
This module contains the business logic for user authentication and login operations.
It handles password verification, JWT token generation, login attempt validation,
and security features like rate limiting and account lockout.

Module: app.modules.login.services.login
Dependencies: SQLAlchemy, passlib, python-jose
"""

from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt

from ..models.login import User
from ....core.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginService:
    """
    Business logic for user authentication and login operations.
    Handles password verification, token generation, and login logging.
    """

    def __init__(self, db: Session):
        self.db = db

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user credentials against database.
        """
        user = (
            self.db.query(User)
            .filter((User.username == username) | (User.email == username))
            .first()
        )

        if not user or not user.is_active:
            return None

        if not self.verify_password(password, user.hashed_password):
            return None

        user.last_login = datetime.now(timezone.utc)
        self.db.commit()

        return user

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify plain text password against hashed password.
        """
        return pwd_context.verify(plain_password, hashed_password)

    def create_access_token(self, user: User, expires_delta: Optional[timedelta] = None) -> str:
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
            token_data,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
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

    def get_user_info(self, user: User) -> Dict[str, Any]:
        """
        Get user information for login response.
        """
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "last_login": user.last_login
        }

    def create_refresh_token(self, user: User) -> str:
        """
        Create refresh token for token renewal.
        """
        token_data = {
            "sub": str(user.id),
            "type": "refresh",
            "exp": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": datetime.now(timezone.utc)
        }

        return jwt.encode(
            token_data,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )

    def verify_refresh_token(self, refresh_token: str) -> Optional[User]:
        """
        Verify refresh token and return user.
        """
        try:
            payload = jwt.decode(
                refresh_token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )

            user_id = payload.get("sub")
            token_type = payload.get("type")

            if user_id is None or token_type != "refresh":
                return None

            user = self.db.query(User).filter(User.id == int(user_id)).first()
            return user if user and user.is_active else None

        except JWTError:
            return None
