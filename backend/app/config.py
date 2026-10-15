"""Application configuration loaded from .env / environment variables."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


class Settings:
    HOST: str = _env("HOST", "0.0.0.0")
    PORT: int = int(_env("PORT", "8000"))

    DATABASE_URL: str = _env(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'socanalyst.db'}"
    )

    INGESTION_MODE: str = _env("INGESTION_MODE", "mock")
    MOCK_ALERT_INTERVAL_SECONDS: int = int(_env("MOCK_ALERT_INTERVAL_SECONDS", "30"))
    SYSTEM_LOG_INTERVAL_SECONDS: int = int(_env("SYSTEM_LOG_INTERVAL_SECONDS", "10"))

    WAZUH_VERIFY_SSL: bool = _env("WAZUH_VERIFY_SSL", "false").lower() == "true"
    WAZUH_POLL_INTERVAL_SECONDS: int = int(_env("WAZUH_POLL_INTERVAL_SECONDS", "30"))
    WAZUH_INDEXER_URL: str = _env("WAZUH_INDEXER_URL", "https://localhost:9200")
    WAZUH_INDEXER_USER: str = _env("WAZUH_INDEXER_USER", "admin")
    WAZUH_INDEXER_PASSWORD: str = _env("WAZUH_INDEXER_PASSWORD", "admin")

    SIGMA_RULES_DIR: str = _env("SIGMA_RULES_DIR", str(BASE_DIR / "backend" / "sigma_rules"))

    MODEL_PATH: str = _env("MODEL_PATH", str(BASE_DIR / "backend" / "models" / "severity_model.pkl"))
    MODEL_TYPE: str = _env("MODEL_TYPE", "random_forest")
    MIN_SAMPLES_FOR_TRAIN: int = int(_env("MIN_SAMPLES_FOR_TRAIN", "100"))

    LLM_MODE: str = _env("LLM_MODE", "offline")
    OLLAMA_BASE_URL: str = _env("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = _env("OLLAMA_MODEL", "tinyllama")

    CHROMA_DIR: str = _env("CHROMA_DIR", str(BASE_DIR / "data" / "vector_store"))
    EMBEDDING_MODEL: str = _env("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    RAG_TOP_K: int = int(_env("RAG_TOP_K", "3"))

    BACKEND_URL: str = _env("BACKEND_URL", "http://localhost:8000")
    LOG_LEVEL: str = _env("LOG_LEVEL", "INFO")

    # --- Notifications ---
    EMAIL_ENABLED: bool = _env("EMAIL_ENABLED", "false").lower() == "true"
    EMAIL_SMTP_HOST: str = _env("EMAIL_SMTP_HOST", "smtp.gmail.com")
    EMAIL_SMTP_PORT: int = int(_env("EMAIL_SMTP_PORT", "587"))
    EMAIL_USERNAME: str = _env("EMAIL_USERNAME", "")
    EMAIL_PASSWORD: str = _env("EMAIL_PASSWORD", "")
    EMAIL_RECIPIENTS: str = _env("EMAIL_RECIPIENTS", "")

    TELEGRAM_ENABLED: bool = _env("TELEGRAM_ENABLED", "false").lower() == "true"
    TELEGRAM_BOT_TOKEN: str = _env("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = _env("TELEGRAM_CHAT_ID", "")

    NOTIFICATION_MIN_SEVERITY: str = _env("NOTIFICATION_MIN_SEVERITY", "critical")
    DESKTOP_NOTIFICATIONS: bool = _env("DESKTOP_NOTIFICATIONS", "false").lower() == "true"

    BASE_DIR: Path = BASE_DIR


settings = Settings()
