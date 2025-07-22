"""App settings module.

TODO: Replace default test DB with production-ready database via environment variables.
"""

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "sqlite:///./test.db"

    class Config:
        env_file = ".env"

settings = Settings()
