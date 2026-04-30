from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = 'AI Source Vulnerability Analyzer'
    MAX_UPLOAD_SIZE_MB: int = 20
    TMP_DIR: str = '/tmp/ai_code_analyzer'
    MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8')


settings = Settings()
