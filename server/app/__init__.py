import os
import time
import uuid
from flask import Flask, g, request
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import requests
from sqlalchemy import event

# Optional CORS support
try:
    from flask_cors import CORS
    CORS_AVAILABLE = True
except ImportError:
    CORS_AVAILABLE = False

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()


_CBOM_ENDPOINT = os.environ.get("SERVER_CBOM_URL", "http://127.0.0.1:5600/api/cboom/events").strip()
_CBOM_TOKEN = os.environ.get("CBOM_INGEST_TOKEN") or os.environ.get("TELEMETRY_INGEST_TOKEN") or ""
_CBOM_TOKEN = _CBOM_TOKEN.strip()


def _send_cbom_event(payload: dict) -> None:
    if not _CBOM_ENDPOINT:
        return
    try:
        headers = {"Content-Type": "application/json"}
        if _CBOM_TOKEN:
            headers["Authorization"] = f"Bearer {_CBOM_TOKEN}"
            headers["X-Observer-Token"] = _CBOM_TOKEN
        verify = True
        if str(_CBOM_ENDPOINT).strip().lower().startswith("https://"):
            verify = os.getenv("SERVER_CBOM_VERIFY_TLS", "0").strip().lower() in {"1", "true", "yes", "on"}
        requests.post(_CBOM_ENDPOINT, json=payload, headers=headers, timeout=2, verify=verify)
    except Exception:
        return

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    # Basic config
    app.config.from_mapping(
        SECRET_KEY = os.environ.get("SECRET_KEY","dev-secret-change-me"),
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(app.instance_path, "app.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS = False,
        SESSION_COOKIE_SECURE = False,    # Set True when running over real HTTPS
        SESSION_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = "Lax",  # Use 'Strict' for higher protection
        WTF_CSRF_TIME_LIMIT = None,
        WTF_CSRF_CHECK_DEFAULT = True,
    )

    if test_config:
        app.config.update(test_config)

    # ensure instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # init extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    try:
        with app.app_context():
            db.create_all()
    except Exception:
        pass
    
    # Configure CORS - allow all origins for API endpoints (proxy access)
    if CORS_AVAILABLE:
        CORS(app, resources={
            r"/api/*": {
                "origins": "*",
                "methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type"]
            }
        })
    
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return User.query.get(int(user_id))

    # Make csrf available to other modules (for use in blueprints)
    import sys
    sys.modules[__name__].csrf = csrf
    
    # register blueprints
    from .auth import bp as auth_bp
    from .main import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    
    # Exempt /api/message from CSRF (internal proxy endpoint)
    # Import and exempt the view function - this is the proper Flask-WTF way
    from .main import api_message
    # Apply csrf.exempt() which adds the function to the exempt views set
    csrf.exempt(api_message)



    # Security headers
    @app.after_request
    def set_security_headers(response):
        # Content Security Policy - adjust allowed sources as needed
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
        )
        response.headers['Content-Security-Policy'] = csp
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
        # HSTS only if served over HTTPS in production
        if os.environ.get("ENABLE_HSTS","false").lower() == "true":
            response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
        return response

    @app.before_request
    def capture_proxy_identity():
        g.proxy_client_id = (request.headers.get("X-Proxy-Client-Id") or "").strip() or None

    @app.before_request
    def _cbom_before_request():
        g._cbom_req_started = time.monotonic()

    @app.after_request
    def _cbom_after_request(resp):
        try:
            started = getattr(g, "_cbom_req_started", None)
            latency_ms = round((time.monotonic() - started) * 1000.0, 3) if started is not None else None

            path = (request.path or "").strip()
            if not path:
                return resp

            if path.startswith("/static/"):
                return resp

            via_proxy = bool(getattr(g, "proxy_client_id", None))
            proto = "HTTPS" if (request.is_secure if request else False) else "HTTP"
            src_comp = "proxy" if (via_proxy and path.startswith("/api/")) else "frontend"
            payload = {
                "event_id": str(uuid.uuid4()),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z",
                "source_component": src_comp,
                "destination_component": "backend",
                "communication_protocol": proto,
                "message_type": "response",
                "status": "failure" if int(getattr(resp, "status_code", 200) or 0) >= 400 else "success",
                "api_endpoint": path[:255],
                "client_token_id": None,
                "latency_ms": latency_ms,
                "payload_summary": {
                    "method": request.method,
                    "status_code": int(getattr(resp, "status_code", 200) or 0),
                    "proxy_client_id": getattr(g, "proxy_client_id", None),
                    "path": path[:255],
                },
                "crypto": {},
            }
            _send_cbom_event(payload)
        except Exception:
            pass
        return resp

    try:
        with app.app_context():
            engine = db.engine

            @event.listens_for(engine, "before_cursor_execute")
            def _cbom_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
                try:
                    context._cbom_query_started = time.monotonic()
                except Exception:
                    pass

            @event.listens_for(engine, "after_cursor_execute")
            def _cbom_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
                try:
                    started = getattr(context, "_cbom_query_started", None)
                    latency_ms = round((time.monotonic() - started) * 1000.0, 3) if started is not None else None
                    st = (statement or "").strip().replace("\n", " ")
                    payload = {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z",
                        "source_component": "backend",
                        "destination_component": "db",
                        "communication_protocol": "SQL",
                        "message_type": "db_query",
                        "status": "success",
                        "api_endpoint": None,
                        "client_token_id": None,
                        "latency_ms": latency_ms,
                        "payload_summary": {"statement": st[:200], "executemany": bool(executemany)},
                        "crypto": {
                            "crypto_algorithm": "None (Plaintext)",
                            "library_tool": "SQLAlchemy",
                            "cert_type": "None",
                            "pqc_support": False,
                            "quantum_ready": False,
                        },
                    }
                    _send_cbom_event(payload)
                except Exception:
                    pass

            @event.listens_for(engine, "handle_error")
            def _cbom_handle_error(exception_context):
                try:
                    payload = {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z",
                        "source_component": "backend",
                        "destination_component": "db",
                        "communication_protocol": "SQL",
                        "message_type": "db_error",
                        "status": "failure",
                        "api_endpoint": None,
                        "client_token_id": None,
                        "latency_ms": None,
                        "payload_summary": {},
                        "error_details": {"error": str(getattr(exception_context, "original_exception", None) or "db_error")},
                        "crypto": {
                            "crypto_algorithm": "None (Plaintext)",
                            "library_tool": "SQLAlchemy",
                            "cert_type": "None",
                            "pqc_support": False,
                            "quantum_ready": False,
                        },
                    }
                    _send_cbom_event(payload)
                except Exception:
                    pass
                return None
    except Exception:
        pass

    return app
