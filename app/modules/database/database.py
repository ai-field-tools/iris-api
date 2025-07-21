from sqlalchemy.orm import Session
from contextlib import contextmanager
from app.modules.database.base import SessionLocal

def get_database_session() -> Session:
    return SessionLocal()

@contextmanager
def get_db_session():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
