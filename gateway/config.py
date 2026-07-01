"""
Central configuration for the Secure Enterprise MCP Gateway.
Loads from environment variables (with sane local-dev defaults) so the same
image can be promoted from docker-compose -> Kubernetes without code changes.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings:
    # --- Auth ---
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "dev-secret-change-me-in-prod")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

    # --- Upstream MCP-style tool server(s) ---
    # Maps a logical upstream name -> base URL. In k8s this is a Service DNS name,
    # e.g. http://mcp-finance-server.mcp-servers.svc.cluster.local:9000
    UPSTREAM_SERVERS: dict = {
        "demo": os.getenv("UPSTREAM_DEMO_URL", "http://localhost:9000"),
    }

    # --- Policy ---
    POLICY_FILE: str = os.getenv(
        "POLICY_FILE", str(BASE_DIR / "policies" / "roles.yaml")
    )

    # --- Security thresholds ---
    INJECTION_BLOCK_THRESHOLD: float = float(os.getenv("INJECTION_BLOCK_THRESHOLD", "0.6"))
    PII_ACTION_DEFAULT: str = os.getenv("PII_ACTION_DEFAULT", "block")  # block | redact | allow

    # --- Audit ---
    AUDIT_LOG_PATH: str = os.getenv("AUDIT_LOG_PATH", str(BASE_DIR / "logs" / "audit.log"))

settings = Settings()
