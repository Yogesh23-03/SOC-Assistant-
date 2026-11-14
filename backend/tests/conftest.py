"""Test-only random secrets."""
import os
import secrets
os.environ.setdefault("SOC_HMAC_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("SOC_JWT_SECRET", secrets.token_urlsafe(48))
