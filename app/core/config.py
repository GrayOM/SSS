from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = 'AI Source Vulnerability Analyzer'
    MAX_UPLOAD_SIZE_MB: int = 20
    TMP_DIR: str = '/tmp/ai_code_analyzer'
    MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024
    MAX_ZIP_MEMBERS: int = 5000
    MAX_UNCOMPRESSED_SIZE_MB: int = 200
    MAX_CHUNK_LINES: int = 200
    CHUNK_OVERLAP_LINES: int = 20

    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = 'gemini-2.5-flash-lite'
    ANALYZER_BACKEND: str = 'mock'
    POC_BACKEND: str = 'mock'

    OPENAI_API_KEY: str | None = None
    ANTHROPIC_API_KEY: str | None = None
    OPENAI_MODEL: str = 'gpt-5-mini'
    CLAUDE_MODEL: str = 'claude-3-5-sonnet-latest'

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8')


settings = Settings()
