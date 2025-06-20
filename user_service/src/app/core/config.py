import os
# import ssl
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

class Config(BaseSettings):
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int
    ALGORITHM: str

    POSTGRES_USER: str
    POSTGRES_PASS: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_DB: str

    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_PASSWORD: str

    SMTP_SERVER: str
    SMTP_PORT: int
    SMTP_USER: str
    
    model_config = SettingsConfigDict(
        env_file=os.path.join(
                    os.path.dirname(
                        os.path.abspath(__file__)), '..', '..', '..', '..', '.env')
    )


settings = Config()

PRIVATE_KEY = Path(os.getenv("PRIVATE_KEY_PATH", "/app/keys/private.pem")).read_text()
PUBLIC_KEY = Path(os.getenv("PUBLIC_KEY_PATH", "/app/keys/public.pem")).read_text()

database_url = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASS}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"

redis_url = f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}/0"

# smtp_url = "user_service:8000/smtp/send-email/2-fa"

SMTP_PATH = "/smtp/send-email/2-fa"
smtp_url = f"http://user_service:8000{SMTP_PATH}"