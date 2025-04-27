import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    class Config:
        env_file = ".env"

    KEYCLOAK_ADMIN: str = os.getenv("KEYCLOAK_ADMIN")
    KEYCLOAK_ADMIN_PASSWORD: str = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
    CLIENT_ADMIN_ID: str = os.getenv("CLIENT_ADMIN_ID")
    CLIENT_ADMIN_SECRET_KEY: str = os.getenv("CLIENT_ADMIN_SECRET_KEY")

    KEYCLOAK_URL: str = os.getenv("KEYCLOAK_URL")
    REALM: str = os.getenv("REALM")
    CLIENT_ID: str = os.getenv("CLIENT_ID")
    CLIENT_SECRET_KEY: str = os.getenv("CLIENT_SECRET_KEY")
    REDIRECT_URL: str = os.getenv("REDIRECT_URL")

    POSTGRES_USER: str = os.getenv("DB_USER")
    POSTGRES_PASSWORD: str = os.getenv("DB_PASSWORD")
    POSTGRES_DB: str = os.getenv("DB_NAME")
    BASE_URL: str = os.getenv("BASE_URL")

    YC_API_KEY: str = os.getenv("YC_API_KEY")
    YC_FOLDER_ID: str = os.getenv("YC_FOLDER_ID")
    
settings = Settings()