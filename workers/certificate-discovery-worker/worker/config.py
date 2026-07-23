from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_base_url: str = Field("http://localhost:8080", alias="WORKER_API_BASE_URL")
    api_key: str = Field("dev-worker-key-change-me", alias="WORKER_API_KEY")
    worker_name: str = Field("certificate-worker-local", alias="WORKER_NAME")
    max_concurrency: int = Field(5, alias="WORKER_MAX_CONCURRENCY")
    poll_interval_seconds: int = Field(15, alias="WORKER_POLL_INTERVAL_SECONDS")
    request_timeout_seconds: int = Field(30, alias="WORKER_REQUEST_TIMEOUT_SECONDS")
    version: str = "0.1.0"

    class Config:
        extra = "ignore"
