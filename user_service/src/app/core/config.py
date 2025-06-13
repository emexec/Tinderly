import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Config(BaseSettings):
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    ALGORITHM: str
    SECRET_KEY_PUBLICK: bytes
    SECRET_KEY_PRIVATE: bytes
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
