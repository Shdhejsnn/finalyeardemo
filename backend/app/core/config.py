from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "ShieldX"
    API_VERSION: str = "1.0"
    DATABASE_URL: str = "sqlite:///./shieldx.db"
    DEBUG: bool = False

    class Config:
        env_file = ".env"


settings = Settings()