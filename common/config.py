# ascp/common/config.py

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Extractor mode: "llm_local" | "llm_api" | "regex"
    extractor_mode: str = "regex"

    # Ollama settings
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout: float = 30.0

    class Config:
        env_file = ".env"

settings = Settings()