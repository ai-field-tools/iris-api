"""
This module defines the SQLAlchemy models for logout-related operations:
1. LogoutHistory: Tracks logout events and metadata.
2. TokenBlacklist: Stores blacklisted JWT tokens to prevent reuse.

Module: app.modules.auth.logout.models.logout
Dependencies: SQLAlchemy, func (SQL expressions), Base
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ....database.base import Base


class LogoutHistory(Base):
    __tablename__ = "logout_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    logout_at = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(45))  # supports IPv6
    user_agent = Column(Text)
    session_ended_cleanly = Column(Boolean, default=True)

    user = relationship("User", back_populates="logout_history")

    def __repr__(self) -> str:
        return (
            f"<LogoutHistory(id={self.id}, user_id={self.user_id}, "
            f"logout_at={self.logout_at}, clean={self.session_ended_cleanly})>"
        )


class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(Text, nullable=False, unique=True)
    jti = Column(String(255), nullable=False)
    blacklisted_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<TokenBlacklist(id={self.id}, jti={self.jti})>"
