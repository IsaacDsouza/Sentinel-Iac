from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    anthropic_api_key: str = ""
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_api_key: str = ""
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    log_level: str = "INFO"
    api_key: str = ""
    enrichment_batch_token_budget: int = 40_000
    remediation_max_iterations: int = 5
    remediation_max_tokens_per_run: int = 100_000

    llm_provider: str = "anthropic"
    huggingface_api_key: str = ""
    huggingface_model: str = "Qwen/Qwen2.5-7B-Instruct"
    openai_api_key: str = ""
    openai_base_url: str = ""
    openai_model: str = ""


_config: Settings | None = None


def get_config() -> Settings:
    global _config
    if _config is None:
        _config = Settings()
    return _config
