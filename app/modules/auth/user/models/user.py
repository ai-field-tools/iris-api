from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime, timedelta, timezone
import bcrypt
from app.modules.database.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )
    login_history = relationship(
        "LoginHistory", back_populates="user", cascade="all, delete-orphan"
    )

    def set_password(self, password: str) -> None:
        salt = bcrypt.gensalt()
        self.hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
            "utf-8"
        )

    def verify_password(self, password: str) -> bool:
        return bcrypt.checkpw(
            password.encode("utf-8"), self.hashed_password.encode("utf-8")
        )

    def is_locked(self) -> bool:
        return self.locked_until and datetime.now(timezone.utc) < self.locked_until

    def lock_account(self, duration_minutes: int = 30) -> None:
        self.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=duration_minutes
        )
        self.failed_login_attempts = 0

    def unlock_account(self) -> None:
        self.locked_until = None
        self.failed_login_attempts = 0

    def increment_failed_attempts(self) -> None:
        self.failed_login_attempts += 1

    def reset_failed_attempts(self) -> None:
        self.failed_login_attempts = 0

    def update_last_login(self) -> None:
        self.last_login = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"
