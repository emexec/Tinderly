import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Config(BaseSettings):
    SECRET_KEY: str
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