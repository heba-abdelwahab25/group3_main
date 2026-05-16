import os
import time
import uuid
from datetime import timedelta

from flask import Flask, request, redirect, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash
from sqlalchemy import text

db = SQLAlchemy()
login_manager = LoginManager()


def _send_cbom_event(payload: dict) -> None:
    """Send CBOM event to observer (self) for internal tracking"""
    try:
        import sqlite3
        import json
        import os
        from datetime import datetime

        # Debug: write to log file
        with open('cbom_debug.log', 'a') as f:
            f.write(f"CBOM event: {payload.get('source_component')} -> {payload.get('destination_component')} ({payload.get('api_endpoint')})\n")

        # Use raw SQLite to avoid SQLAlchemy session conflicts
        instance_path = os.path.join(os.path.dirname(__file__), '..', 'instance')
        db_path = os.path.join(instance_path, "observer.db")
        conn = sqlite3.connect(db_path, timeout=20)
        c = conn.cursor()
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")

        ts_raw = payload.get("timestamp")
        ts_norm = None
        if isinstance(ts_raw, str) and ts_raw.strip():
            try:
                raw = ts_raw.strip()
                if raw.endswith("Z"):
                    raw = raw[:-1] + "+00:00"
                ts_dt = datetime.fromisoformat(raw)
                ts_norm = ts_dt.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
            except Exception:
                ts_norm = ts_raw.strip()

        c.execute('''
            INSERT INTO cbom_event (
                event_id, timestamp, source_component, destination_component,
                communication_protocol, message_type, status, payload_summary,
                crypto, api_endpoint, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            payload.get("event_id", str(uuid.uuid4())),
            ts_norm,
            payload.get("source_component"),
            payload.get("destination_component", "observer"),
            payload.get("communication_protocol", "HTTP"),
            payload.get("message_type", "api_request"),
            payload.get("status", "success"),
            json.dumps(payload.get("payload_summary", {})),
            json.dumps(payload.get("crypto", {})),
            payload.get("api_endpoint"),
            payload.get("latency_ms"),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        # Log the error but don't fail the request
        print(f"CBOM logging failed: {e}")
        pass


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    use_ssl = os.environ.get("OBSERVER_USE_SSL", "0").strip().lower() in {"1", "true", "yes", "on"}
    proxy_tls = os.environ.get("OBSERVER_PROXY_TLS", "0").strip().lower() in {"1", "true", "yes", "on"}
    effective_tls = bool(use_ssl or proxy_tls)
    enforce_https = os.environ.get("OBSERVER_ENFORCE_HTTPS", "").strip().lower() in {"1", "true", "yes", "on"}
    if os.environ.get("OBSERVER_ENFORCE_HTTPS") is None or os.environ.get("OBSERVER_ENFORCE_HTTPS", "").strip() == "":
        enforce_https = effective_tls

    # Trust reverse proxy headers (X-Forwarded-Proto/Host) so request.is_secure reflects TLS termination at the proxy.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("OBSERVER_SECRET_KEY", "observer-dev"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "OBSERVER_DATABASE_URI",
            "sqlite:///" + os.path.join(app.instance_path, "observer.db") + "?timeout=20",
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=int(os.environ.get("OBSERVER_MAX_CONTENT_LENGTH", str(10 * 1024 * 1024))),  # 10MB
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=effective_tls,
        REMEMBER_COOKIE_SECURE=effective_tls,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
        SESSION_REFRESH_EACH_REQUEST=True,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("OBSERVER_SESSION_LIFETIME_MIN", "60"))),
    )

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    with app.app_context():
        from sqlalchemy import event
        @event.listens_for(db.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    # CORS: default to same-origin unless explicitly configured.
    cors_origins = os.environ.get("OBSERVER_CORS_ORIGINS", "").strip()
    if cors_origins:
        origins = [o.strip() for o in cors_origins.split(",") if o.strip()]
    else:
        if effective_tls:
            origins = ["https://127.0.0.1:5600", "https://localhost:5600"]
        else:
            origins = ["http://127.0.0.1:5600", "http://localhost:5600"]
    CORS(app, resources={r"/api/*": {"origins": origins}}, supports_credentials=True)

    login_manager.init_app(app)
    login_manager.login_view = "observer.login"

    @app.before_request
    def _cbom_before_request():
        g._cbom_req_started = time.monotonic()

    @app.after_request
    def _cbom_after_request(resp):
        try:
            # Debug: always write something
            with open('cbom_debug.log', 'a') as f:
                f.write(f"After request: {request.path}\n")

            started = getattr(g, "_cbom_req_started", None)
            latency_ms = round((time.monotonic() - started) * 1000.0, 3) if started is not None else None

            path = (request.path or "").strip()
            if not path or path.startswith("/static/") or not path.startswith("/api/"):
                return resp

            via_proxy = bool(getattr(request, "headers", {}).get("X-Forwarded-Proto"))
            src_comp = "proxy" if via_proxy else "frontend"
            proto = "HTTPS" if (request.is_secure if request else False) else "HTTP"

            payload = {
                "event_id": str(uuid.uuid4()),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z",
                "source_component": src_comp,
                "destination_component": "observer",
                "communication_protocol": proto,
                "message_type": "api_response",
                "status": "failure" if int(getattr(resp, "status_code", 200) or 0) >= 400 else "success",
                "api_endpoint": path[:255],
                "latency_ms": latency_ms,
                "payload_summary": {
                    "method": request.method,
                    "status_code": int(getattr(resp, "status_code", 200) or 0),
                    "path": path[:255],
                },
                "crypto": {},
            }
            _send_cbom_event(payload)
        except Exception:
            pass
        return resp

    @app.before_request
    def _enforce_https_redirect():
        if not enforce_https:
            return None
        # ProxyFix sets request.is_secure based on X-Forwarded-Proto.
        if request.is_secure:
            return None
        # Only redirect safe methods.
        if request.method not in {"GET", "HEAD"}:
            return None
        host = request.host
        return redirect(f"https://{host}{request.full_path}".rstrip("?"), code=301)

    @app.after_request
    def _security_headers(resp):
        # Basic hardening headers (NIST 800-52/800-53 SC, ISO 27002 A.10/A.12).
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        # CSP kept minimal to avoid breaking inline scripts/styles in this project.
        # Tighten later by migrating inline styles to CSS if desired.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self';",
        )

        # HSTS only when HTTPS is actually used (either app TLS or proxy TLS).
        if effective_tls or (request.is_secure if request else False):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    from .models import User

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return User.query.get(int(user_id))
        except Exception:
            return None

    from .main import bp as main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()

        try:
            stmts = [
                "CREATE INDEX IF NOT EXISTS idx_cbom_ts ON cbom_event(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_cbom_src_dst_ts ON cbom_event(source_component, destination_component, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_cbom_proto_type_status_ts ON cbom_event(communication_protocol, message_type, status, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_cbom_api_ts ON cbom_event(api_endpoint, timestamp)",
            ]
            with db.engine.begin() as conn:
                for s in stmts:
                    try:
                        conn.execute(text(s))
                    except Exception:
                        pass
        except Exception:
            pass

        # Bootstrap a default admin if no users exist.
        if User.query.count() == 0:
            username = os.environ.get("OBSERVER_ADMIN_USERNAME", "admin")
            password = os.environ.get("OBSERVER_ADMIN_PASSWORD", "admin")
            role = os.environ.get("OBSERVER_ADMIN_ROLE", "admin")
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
            )
            db.session.add(user)
            db.session.commit()

    return app

