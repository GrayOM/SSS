try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ModuleNotFoundError:  # fallback for limited test environments
    class BaseSettings:  # type: ignore
        def __init__(self, **kwargs):
            for key, value in self.__class__.__dict__.items():
                if key.isupper():
                    setattr(self, key, value)

    class SettingsConfigDict(dict):
        pass
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = 'AI Source Vulnerability Analyzer'
    MAX_UPLOAD_SIZE_MB: int = 20
    TMP_DIR: str = '/tmp/ai_code_analyzer'
    MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024
    MAX_ZIP_MEMBERS: int = 5000
    MAX_UNCOMPRESSED_SIZE_MB: int = 200

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8')


settings = Settings()
