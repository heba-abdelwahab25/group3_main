"""
Configuration and security defaults for the proxy server.

All settings can be overridden with environment variables so the same build
can be promoted across environments without editing source code.
"""

from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def _env(key: str, default: str | None = None) -> str | None:
    return os.getenv(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, default))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "t", "yes", "on"}


def _read_secret_file(key: str) -> str | None:
    """
    Some orchestrators mount secrets as files. If <KEY>_FILE is provided,
    read its content. The value takes precedence over process env vars.
    """
    path = os.getenv(f"{key}_FILE")
    if not path:
        return None
    candidate = Path(path)
    if not candidate.exists():
        return None
    return candidate.read_text(encoding="utf-8").strip()


# Proxy server configuration
PROXY_HOST = _env("PROXY_HOST", "0.0.0.0")
PROXY_PORT = _env_int("PROXY_PORT", 7000)

# Backend server configuration
SERVER_HOST = _env("SERVER_HOST", "127.0.0.1")
SERVER_PORT = _env_int("SERVER_PORT", 5000)

# Session configuration
SESSION_TIMEOUT = _env_int("SESSION_TIMEOUT", 300)  # seconds
HEALTH_CHECK_INTERVAL = _env_int("HEALTH_CHECK_INTERVAL", 60)  # seconds

# Crypto configuration
PREFERRED_CRYPTO = _env("PREFERRED_CRYPTO", "Kyber")
FALLBACK_CRYPTO = _env("FALLBACK_CRYPTO", "RSA")

# SSL/TLS configuration
USE_SSL = _env_bool("PROXY_USE_SSL", True)
CERT_STORAGE_BACKEND = _env("CERT_STORAGE_BACKEND", "file").lower()
CERT_FILE_PATH = _env("PROXY_CERT_FILE", str(BASE_DIR / "certs" / "server.crt"))
KEY_FILE_PATH = _env("PROXY_KEY_FILE", str(BASE_DIR / "certs" / "server.key"))
CA_FILE_PATH = _env("PROXY_CA_FILE", str(BASE_DIR / "ca" / "ca.crt"))
CLIENT_CA_FILE = _env("PROXY_CLIENT_CA_FILE", CA_FILE_PATH)
REQUIRE_CLIENT_CERT = _env_bool("PROXY_REQUIRE_CLIENT_CERT", False)
TLS_MIN_VERSION = _env("TLS_MIN_VERSION", "1.2")
TLS_CIPHER_SUITES = _env(
    "TLS_CIPHER_SUITES",
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384",
)
CERT_REFRESH_SECONDS = _env_int("CERT_REFRESH_SECONDS", 300)
CERT_BACKUP_DIR = _env("CERT_BACKUP_DIR", str(BASE_DIR / "cert_backups"))
CERT_FORCE_ROTATION_SECONDS = _env_int("CERT_FORCE_ROTATION_SECONDS", 0)
OCSP_STAPLING_ENABLED = _env_bool("PROXY_ENABLE_OCSP_STAPLING", False)

# Vault / SDS configuration
VAULT_ADDR = _env("VAULT_ADDR")
VAULT_TOKEN = _read_secret_file("VAULT_TOKEN") or _env("VAULT_TOKEN")
VAULT_PKI_ROLE = _env("VAULT_PKI_ROLE", "proxy")
VAULT_COMMON_NAME = _env("VAULT_COMMON_NAME", "proxy.local")
VAULT_ALT_NAMES = _env("VAULT_ALT_NAMES", "")
VAULT_MOUNT_POINT = _env("VAULT_MOUNT_POINT", "pki")
VAULT_TTL = _env("VAULT_TTL", "24h")

SDS_ENDPOINT = _env("SDS_ENDPOINT")
SDS_TOKEN = _read_secret_file("SDS_TOKEN") or _env("SDS_TOKEN")
SDS_VERIFY_TLS = _env_bool("SDS_VERIFY_TLS", True)

# Runtime hardening
PROXY_SERVICE_USER = _env("PROXY_SERVICE_USER")
PROXY_SERVICE_GROUP = _env("PROXY_SERVICE_GROUP")
PROXY_CHROOT_PATH = _env("PROXY_CHROOT_PATH")

# Logging / auditing
LOG_LEVEL = _env("PROXY_LOG_LEVEL", "INFO").upper()
AUDIT_LOG_PATH = _env("PROXY_AUDIT_LOG_PATH", str(BASE_DIR / "logs" / "proxy_audit.log"))
LOG_SENSITIVE_DATA = _env_bool("PROXY_LOG_SENSITIVE_DATA", False)

# Network configuration
SOCKET_TIMEOUT = _env_int("SOCKET_TIMEOUT", 10)  # seconds
MAX_MESSAGE_SIZE = _env_int("MAX_MESSAGE_SIZE", 1024 * 1024)  # 1MB
BUFFER_SIZE = _env_int("BUFFER_SIZE", 4096)

