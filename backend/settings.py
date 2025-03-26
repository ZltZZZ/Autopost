import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    class Config:
        env_file = ".env"

    KEYCLOAK_URL: str = os.getenv("KEYCLOAK_URL")
    REALM: str = os.getenv("REALM")
    CLIENT_ID: str = os.getenv("CLIENT_ID")
    CLIENT_SECRET_KEY: str = os.getenv("CLIENT_SECRET_KEY")
    REDIRECT_URL: str = os.getenv("REDIRECT_URL")

    POSTGRES_USER: str = os.getenv("DB_USER")
    POSTGRES_PASSWORD: str = os.getenv("DB_PASSWORD")
    POSTGRES_DB: str = os.getenv("DB_NAME")
    POSTGRES_URL: str = f"postgresql+asyncpg://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@db:5432/{os.getenv('DB_NAME')}"
    BASE_URL: str = os.getenv("BASE_URL")

settings = Settings()