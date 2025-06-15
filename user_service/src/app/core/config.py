import os
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
    
    model_config = SettingsConfigDict(
        env_file=os.path.join(
                    os.path.dirname(
                        os.path.abspath(__file__)), '..', '..', '..', '.env')
    )

settings = Config()

PRIVATE_KEY = Path(os.getenv("PRIVATE_KEY_PATH", "/app/keys/private.pem")).read_text()
PUBLIC_KEY = Path(os.getenv("PUBLIC_KEY_PATH", "/app/keys/public.pem")).read_text()