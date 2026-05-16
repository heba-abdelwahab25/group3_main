"""
Banking Service
Hybrid PQC Microservice.
Emits CBOM telemetry matching the observer schema.
"""
import os
import uuid
import time
import json
import requests
import sys
from pathlib import Path
from flask import Flask, g, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Ensure project root is in path for 'core' imports
project_root = str(Path(__file__).resolve().parent.parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from core.logging.logger import setup_logger

db = SQLAlchemy()
login_manager = LoginManager()

_CBOM_ENDPOINT = os.environ.get("SERVER_CBOM_URL", "http://127.0.0.1:5600/api/cboom/events").strip()
_CBOM_TOKEN    = (os.environ.get("CBOM_INGEST_TOKEN") or os.environ.get("TELEMETRY_INGEST_TOKEN") or "").strip()

APP_NAME = "banking_service"
logger = setup_logger(APP_NAME)
CRYPTO_ALGORITHM = os.environ.get("BANKING_CRYPTO_ALG", "Kyber-ML_KEM_768+AES-256-GCM")
KEY_LENGTH       = int(os.environ.get("BANKING_KEY_LENGTH", "256"))


def _send_cbom_event(payload: dict) -> None:
    if not _CBOM_ENDPOINT:
        return
    try:
        headers = {"Content-Type": "application/json"}
        if _CBOM_TOKEN:
            headers["Authorization"] = f"Bearer {_CBOM_TOKEN}"
            headers["X-Observer-Token"] = _CBOM_TOKEN
        verify = os.getenv("SERVER_CBOM_VERIFY_TLS", "0").lower() in {"1", "true", "yes"}
        requests.post(_CBOM_ENDPOINT, json=payload, headers=headers, timeout=2, verify=verify)
    except Exception:
        pass


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "banking-dev-secret"),
        SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(app.instance_path, "banking.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        APP_NAME=APP_NAME,
    )
    if test_config:
        app.config.update(test_config)

    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return User.query.get(int(user_id))

    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    # ---- CBOM request telemetry hook ----
    @app.before_request
    def _before():
        g.request_id = str(uuid.uuid4())
        g.request_start = time.time()
        if request.path == "/auth/login":
             logger.info("[Banking] processing login request")
        else:
             logger.info(f"[{APP_NAME}] processing request {request.path}")

    @app.after_request
    def _after(response):
        latency_ms = round((time.time() - g.request_start) * 1000, 2)
        crypto_meta = getattr(g, "cbom_crypto", {
            "crypto_algorithm": CRYPTO_ALGORITHM,
            "key_length": KEY_LENGTH,
            "library_tool": "pycryptodome+kyber-py",
            "cert_type": "X.509",
            "pqc_support": True,
            "quantum_ready": True,
        })
        payload = {
            "event_id": g.request_id,
            "source": APP_NAME,
            "event_type": "crypto_operation",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "success" if response.status_code < 400 else "failure",
            "latency_ms": latency_ms,
            "http_method": request.method,
            "path": request.path,
            **crypto_meta,
        }
        _send_cbom_event(payload)
        logger.info(f"[{APP_NAME}] response sent for {request.path}", extra={"algorithm": crypto_meta.get("crypto_algorithm", "NONE")})
        return response

    with app.app_context():
        from .models import create_tables
        create_tables(db)
        from .routes import main_bp, auth_bp
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp)

    return app
