"""
Backend Configuration for Agentic SOC Assistant (M2 Lead).
Handles database paths, security tokens, CORS origins, and system safety defaults.
"""

import os
from pathlib import Path
from typing import List

# Base directory of the SOC-Assistant- repository
BASE_DIR = Path(__file__).resolve().parent.parent

# Database configuration
# Default SQLite path inside data/ directory
DEFAULT_DB_PATH = str(BASE_DIR / "data" / "soc_backend.sqlite")
DATABASE_PATH = os.getenv("SOC_DATABASE_PATH", DEFAULT_DB_PATH)

# Server network settings
SERVER_HOST = os.getenv("SOC_SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SOC_SERVER_PORT", "8000"))

# Cryptographic secrets (In production/demo, provide via environment variables)
# HMAC secret used by Backend to sign approval tokens, verified by the Executor script
HMAC_SECRET_KEY = os.getenv("SOC_HMAC_SECRET", "soc-insecure-dev-hmac-key-change-in-production")
# JWT secret for Analyst session tokens issued to the Chrome/Edge extension
JWT_SECRET_KEY = os.getenv("SOC_JWT_SECRET", "soc-insecure-dev-jwt-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = int(os.getenv("SOC_JWT_EXPIRATION_MINUTES", "120"))

# Allowed CORS Origins (Manifest V3 extension and local dev servers)
CORS_ALLOWED_ORIGINS: List[str] = [
    "http://localhost:3000",
    "http://localhost:5173",  # Vite default dev server
    "http://127.0.0.1:5173",
    "https://soc-backend.lab.local",
]

# Starlette matches origins by exact string, so extension origins need a regex.
CORS_ALLOWED_ORIGIN_REGEX = r"chrome-extension://[a-p]{32}"

# Safety & Timeout Defaults
PROPOSAL_TIMEOUT_SECONDS = int(os.getenv("SOC_PROPOSAL_TIMEOUT_SECONDS", "300"))  # 5 min default expiry
FIREWALL_DEFAULT_TTL_SECONDS = int(os.getenv("SOC_FIREWALL_TTL_SECONDS", "3600")) # 1 hour default block

# Allowlist of protected IP addresses that can NEVER be blocked by the executor
# Matches config.py from M1
PROTECTED_ALLOWLIST = [
    "10.0.0.1",      # Internal management host / primary DNS
    "127.0.0.1",     # Localhost loopback
    "10.0.0.254",    # Default gateway / router
]
