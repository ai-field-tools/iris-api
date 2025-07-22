from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database.base import Base


class LoginHistory(Base):
    __tablename__ = "login_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    login_at = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(45))  # supports IPv6
    user_agent = Column(Text)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String(255))

    user = relationship("User", back_populates="login_history")

    def __repr__(self) -> str:
        return f"<LoginHistory(id={self.id}, user_id={self.user_id}, success={self.success})>"
