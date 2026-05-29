# ascp/common/config.py

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Extractor mode: "llm_local" | "llm_api" | "regex"
    extractor_mode: str = "regex"

    # Ollama settings
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout: float = 30.0

    # Semantic checker settings
    use_semantic_checker: bool = True
    semantic_weight: float = 0.50
    token_weight: float = 0.50
    bge_model: str = "hf.co/CompendiumLabs/bge-base-en-v1.5-gguf:latest"
    bge_timeout: float = 10.0

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()