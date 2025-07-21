"""
This module handles user logout functionality and token blacklisting logic.
It ensures tokens are invalidated upon logout for enhanced session security.
"""

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.modules.auth.logout.models.logout import TokenBlacklist
from ....core.security import verify_token


class LogoutService:
    """Service class for logout operations."""

    def __init__(self, db: Session):
        self.db = db

    def logout_user(self, token: str) -> bool:
        """
        Logout user by blacklisting their JWT token.

        Args:
            token: JWT access token to be blacklisted.

        Returns:
            True if logout successful (token blacklisted), False otherwise.
        """
        try:
            payload = verify_token(token)
            jti = payload.get("jti") or payload.get("sub")
            if not jti:
                return False

            # Check if token already blacklisted
            existing = (
                self.db.query(TokenBlacklist)
                .filter(TokenBlacklist.token == token)
                .first()
            )
            if existing:
                return True  # already blacklisted

            blacklisted_token = TokenBlacklist(
                token=token,
                jti=jti,
                blacklisted_at=datetime.now(timezone.utc),
            )
            self.db.add(blacklisted_token)
            self.db.commit()
            return True

        except Exception:
            self.db.rollback()
            return False
