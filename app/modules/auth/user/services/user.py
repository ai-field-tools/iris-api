from typing import Optional, Callable
from datetime import datetime, timezone

from app.modules.auth.user.models.user import User
from app.modules.auth.user.schemas.user import UserCreate, UserUpdate
from app.modules.core.security import get_password_hash, verify_password
from app.modules.database.database import get_database_session


class UserService:
    def __init__(self):
        self.db = get_database_session()

    def with_session(self, fn: Callable):
        with self.db as session:
            return fn(session)

    async def find_user(self, user_id: int) -> Optional[User]:
        return self.with_session(lambda s: s.query(User).filter_by(id=user_id).first())

    async def find_by_email(self, email: str) -> Optional[User]:
        return self.with_session(lambda s: s.query(User).filter_by(email=email).first())

    async def register_user(self, data: UserCreate) -> User:
        if await self.find_by_email(data.email):
            raise ValueError("User with this email already exists")

        def create(session):
            user = User(
                **data.model_dump(exclude={"password"}),
                password=get_password_hash(data.password),
                created_at=datetime.now(timezone.utc),
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            return user

        return self.with_session(create)

    async def update_user_profile(self, user_id: int, updates: UserUpdate) -> User:
        def update(session):
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                raise LookupError("User not found")

            for field, value in updates.model_dump(exclude_unset=True).items():
                if field == "password":
                    value = get_password_hash(value)
                setattr(user, field, value)

            user.updated_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(user)
            return user

        return self.with_session(update)

    async def remove_user(self, user_id: int) -> None:
        def delete(session):
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                raise LookupError("User not found")
            session.delete(user)
            session.commit()

        self.with_session(delete)

    async def authenticate(self, email: str, password: str) -> Optional[User]:
        user = await self.find_by_email(email)
        if user and verify_password(password, user.password):
            return user
        return None

    async def list_users(self, active_only: bool = False, skip: int = 0, limit: int = 100) -> list[User]:
        def fetch(session):
            query = session.query(User)
            if active_only:
                query = query.filter_by(is_active=True)
            return query.offset(skip).limit(limit).all()

        return self.with_session(fetch)

    async def toggle_user_status(self, user_id: int, activate: bool) -> User:
        def toggle(session):
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                raise LookupError("User not found")

            user.is_active = activate
            user.updated_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(user)
            return user

        return self.with_session(toggle)
