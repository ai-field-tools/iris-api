from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime, timezone
from app.modules.database.database import Base

class PasswordReset(Base):
    __tablename__ = "password_resets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    used_at = Column(DateTime(timezone=True))
    is_used = Column(Boolean, default=False, nullable=False)

    user = relationship("User")

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        return not self.is_used and not self.is_expired()

    def mark_as_used(self) -> None:
        self.is_used = True
        self.used_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<PasswordReset(id={self.id}, user_id={self.user_id}, is_used={self.is_used})>"
