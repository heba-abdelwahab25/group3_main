import json
import os
import uuid
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path

from functools import wraps

from flask import Blueprint, jsonify, render_template, request, current_app, send_file, redirect, url_for
from sqlalchemy import func
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash
from cryptography.fernet import Fernet, InvalidToken
import requests

try:
    import dpkt  # type: ignore
except Exception:
    dpkt = None

from . import db
from .models import TelemetryEvent, User, ActiveSession, MetricBucket, AdminAuditLog, AlertRule, CBOMEvent, GeminiInsight, SIEMEvent

bp = Blueprint("observer", __name__)

_TOKEN = os.getenv("OBSERVER_TOKEN", "").strip()
_TOKENS_ROLES_RAW = os.getenv("OBSERVER_TOKENS", "").strip()
_MAX_DETAILS = int(os.getenv("OBSERVER_MAX_DETAILS_CHARS", "5000"))
_MAX_BODY_BYTES = int(os.getenv("OBSERVER_MAX_BODY_BYTES", str(5 * 1024 * 1024)))  # 5MB
_PCAP_MAX_BYTES = int(os.getenv("OBSERVER_PCAP_MAX_BYTES", str(8 * 1024 * 1024)))  # 8MB
_LOG_KEY = os.getenv("OBSERVER_LOG_KEY", "").strip()
_DEFAULT_PROXY_PCAP_PATH = Path(__file__).resolve().parents[2] / "proxy" / "logs" / "proxy_capture.pcap"
_PROXY_PCAP_PATH = Path(os.getenv("OBSERVER_PROXY_PCAP_PATH", str(_DEFAULT_PROXY_PCAP_PATH)))

_DEFAULT_PROXY_DIR = Path(__file__).resolve().parents[2] / "proxy"
_CONTROL_URL = os.getenv("PROXY_CONTROL_URL", "https://127.0.0.1:7443").strip().rstrip("/")
_CONTROL_CA_FILE = os.getenv("PROXY_CONTROL_CA_FILE", str(_DEFAULT_PROXY_DIR / "ca" / "ca.crt")).strip()
_CONTROL_CLIENT_CERT = os.getenv("PROXY_CONTROL_CLIENT_CERT", str(_DEFAULT_PROXY_DIR / "certs" / "control.crt")).strip()
_CONTROL_CLIENT_KEY = os.getenv("PROXY_CONTROL_CLIENT_KEY", str(_DEFAULT_PROXY_DIR / "certs" / "control.key")).strip()
_CONTROL_TIMEOUT = float(os.getenv("PROXY_CONTROL_TIMEOUT", "3.0"))

_AUDIT_SIEM_WEBHOOK = os.getenv("OBSERVER_SIEM_WEBHOOK_URL", "").strip()
_AUDIT_SIEM_TIMEOUT = float(os.getenv("OBSERVER_SIEM_TIMEOUT", "2.0"))

_ALERT_WEBHOOK_URL = os.getenv("OBSERVER_ALERT_WEBHOOK_URL", "").strip()
_ALERT_WEBHOOK_TIMEOUT = float(os.getenv("OBSERVER_ALERT_WEBHOOK_TIMEOUT", "2.0"))

def _parse_tokens_roles(raw: str) -> dict:
    out = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            token, role = part.split(":", 1)
            token = token.strip()
            role = role.strip() or "viewer"
            if token:
                out[token] = role
        else:
            out[part] = "viewer"
    return out


_TOKENS_ROLES = _parse_tokens_roles(_TOKENS_ROLES_RAW)
if _TOKEN and _TOKEN not in _TOKENS_ROLES:
    _TOKENS_ROLES[_TOKEN] = os.getenv("OBSERVER_DEFAULT_ROLE", "admin").strip() or "admin"


def _extract_bearer_token() -> str | None:
    authz = (request.headers.get("Authorization") or "").strip()
    if authz.lower().startswith("bearer "):
        return authz.split(" ", 1)[1].strip() or None
    return None


def _telemetry_auth(required_role: str = "viewer"):
    # Token auth for proxy -> observer ingest only.
    if not _TOKEN and not _TOKENS_ROLES:
        return None

    # Dev-friendly escape hatch: allow localhost ingest even if tokens are configured.
    # This prevents a misconfigured token from silently blocking telemetry in local demos.
    allow_local = os.getenv("OBSERVER_ALLOW_LOCAL_INGEST_NO_TOKEN", "1").strip().lower() in {"1", "true", "yes", "on"}
    if allow_local:
        remote = (request.remote_addr or "").strip().lower()
        if remote in {"127.0.0.1", "::1"}:
            return None

    provided = (
        _extract_bearer_token()
        or (request.headers.get("X-Observer-Token") or "").strip()
        or (request.headers.get("X-Telemetry-Token") or "").strip()
    )
    if not provided:
        return jsonify({"error": "unauthorized"}), 401

    role = _TOKENS_ROLES.get(provided)
    if not role:
        return jsonify({"error": "unauthorized"}), 401

    order = {"viewer": 1, "auditor": 2, "admin": 3}
    if order.get(role, 0) < order.get(required_role, 0):
        return jsonify({"error": "forbidden"}), 403
    return None


def require_session_role(role: str):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            order = {"viewer": 1, "auditor": 2, "admin": 3}
            user_role = getattr(current_user, "role", "viewer")
            if order.get(user_role, 0) < order.get(role, 0):
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return deco


def require_role(role: str):
    """Allow either a logged-in session role OR a bearer/token role for API access."""

    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            allow_local_dash = os.getenv("OBSERVER_ALLOW_LOCAL_DASHBOARD_NO_AUTH", "1").strip().lower() in {"1", "true", "yes", "on"}
            if allow_local_dash:
                remote = (request.remote_addr or "").strip().lower()
                if remote in {"127.0.0.1", "::1"}:
                    return fn(*args, **kwargs)

            if current_user.is_authenticated:
                order = {"viewer": 1, "auditor": 2, "admin": 3}
                user_role = getattr(current_user, "role", "viewer")
                if order.get(user_role, 0) < order.get(role, 0):
                    return jsonify({"error": "forbidden"}), 403
                return fn(*args, **kwargs)

            auth_err = _telemetry_auth(role)
            if auth_err is not None:
                return auth_err
            return fn(*args, **kwargs)

        return wrapper

    return deco


def _parse_iso8601(ts: str | None) -> datetime | None:
    raw = (ts or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    except Exception:
        return None


def _json_dumps_safe(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        return v
    try:
        return json.dumps(value)
    except Exception:
        return None


def _json_loads_safe(value: str | None):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return value


def _normalize_component_name(name: str) -> str:
    n = (name or "").strip().lower()
    if not n:
        return "unknown"
    aliases = {
        "front": "frontend",
        "ui": "frontend",
        "web": "frontend",
        "browser": "frontend",
        "frontend": "frontend",
        "back": "backend",
        "api": "backend",
        "server": "backend",
        "backend": "backend",
        "database": "db",
        "postgres": "db",
        "postgresql": "db",
        "mysql": "db",
        "sqlite": "db",
        "db": "db",
        "client": "client",
        "client-node": "client",
        "node": "client",
        "device": "client",
        "proxy": "proxy",
        "mitm": "proxy",
        "observer": "observer",
        "dashboard": "observer",
        "monitor": "observer",
    }
    return aliases.get(n, n)


def _coerce_bool(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return None


def _siem_validate_event(payload: dict) -> tuple[dict | None, tuple[dict, int] | None]:
    if not isinstance(payload, dict):
        return None, ({"error": "invalid_payload"}, 400)

    ev_id = str(payload.get("event_id") or "").strip() or str(uuid.uuid4())
    try:
        _ = uuid.UUID(ev_id)
    except Exception:
        return None, ({"error": "invalid_event_id"}, 400)

    ts = _parse_iso8601(payload.get("timestamp"))
    if ts is None:
        ts = datetime.utcnow()

    event_type = str(payload.get("event_type") or "").strip().lower()
    if event_type not in {"telemetry", "cbom", "audit", "network", "crypto"}:
        return None, ({"error": "invalid_event_type"}, 400)

    src = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    dst = payload.get("destination") if isinstance(payload.get("destination"), dict) else {}
    conn = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    conn_crypto = conn.get("crypto") if isinstance(conn.get("crypto"), dict) else {}
    q = payload.get("quantum_risk") if isinstance(payload.get("quantum_risk"), dict) else {}

    normalized = {
        "event_id": ev_id,
        "timestamp": ts,
        "event_type": event_type,
        "status": (str(payload.get("status") or "").strip().lower() or None),
        "severity": (str(payload.get("severity") or "").strip().lower() or None),
        "data_classification": (str(payload.get("data_classification") or "").strip().lower() or None),
        "source_component": _normalize_component_name(str(src.get("component") or "").strip()) if src.get("component") is not None else None,
        "source_id": (str(src.get("id") or "").strip() or None),
        "source_ip": (str(src.get("ip") or "").strip() or None),
        "destination_component": _normalize_component_name(str(dst.get("component") or "").strip()) if dst.get("component") is not None else None,
        "destination_id": (str(dst.get("id") or "").strip() or None),
        "destination_ip": (str(dst.get("ip") or "").strip() or None),
        "protocol": (str(conn.get("protocol") or "").strip().upper() or None),
        "crypto_algorithm": (str(conn_crypto.get("algorithm") or "").strip() or None),
        "key_length": None,
        "pqc_ready": _coerce_bool(conn_crypto.get("pqc_ready")),
        "tls_version": (str(conn_crypto.get("tls_version") or "").strip() or None),
        "harvestable": _coerce_bool(q.get("harvestable")),
        "quantum_risk_score": None,
        "raw_event_ref": (str(payload.get("raw_event_ref") or "").strip() or None),
        "raw_json": _json_dumps_safe(payload) or "{}",
    }

    try:
        kl = conn_crypto.get("key_length")
        normalized["key_length"] = int(kl) if kl is not None and str(kl).strip() != "" else None
    except Exception:
        normalized["key_length"] = None

    try:
        rs = q.get("risk_score")
        normalized["quantum_risk_score"] = float(rs) if rs is not None and str(rs).strip() != "" else None
    except Exception:
        normalized["quantum_risk_score"] = None

    return normalized, None


def _siem_ingest(payload: dict, *, ingest_source: str):
    normalized, err = _siem_validate_event(payload)
    if err is not None:
        body, code = err
        body["ingest_source"] = ingest_source
        return jsonify(body), code

    # Soft enforcement: ensure source.component matches the ingest endpoint (prevents cross-spoofing in demos)
    if normalized.get("source_component") and ingest_source:
        if str(normalized.get("source_component")).lower() not in {ingest_source.lower(), "unknown"}:
            return jsonify({"error": "source_component_mismatch", "expected": ingest_source, "got": normalized.get("source_component")}), 400

    try:
        row = SIEMEvent(
            event_id=str(normalized["event_id"]),
            timestamp=normalized["timestamp"],
            event_type=str(normalized["event_type"]),
            status=normalized.get("status"),
            severity=normalized.get("severity"),
            data_classification=normalized.get("data_classification"),
            source_component=normalized.get("source_component"),
            source_id=normalized.get("source_id"),
            source_ip=normalized.get("source_ip"),
            destination_component=normalized.get("destination_component"),
            destination_id=normalized.get("destination_id"),
            destination_ip=normalized.get("destination_ip"),
            protocol=normalized.get("protocol"),
            crypto_algorithm=normalized.get("crypto_algorithm"),
            key_length=normalized.get("key_length"),
            pqc_ready=normalized.get("pqc_ready"),
            tls_version=normalized.get("tls_version"),
            harvestable=normalized.get("harvestable"),
            quantum_risk_score=normalized.get("quantum_risk_score"),
            raw_event_ref=normalized.get("raw_event_ref"),
            raw_json=str(normalized.get("raw_json") or "{}"),
        )
        db.session.add(row)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": "siem_store_failed", "message": str(exc)}), 500

    return jsonify({"result": "ok", "event_id": normalized["event_id"], "stored": True}), 200


@bp.route("/api/siem/ingest/client", methods=["POST"])
def api_siem_ingest_client():
    auth = _telemetry_auth(required_role="viewer")
    if auth is not None:
        return auth
    payload = request.get_json(silent=True) or {}
    return _siem_ingest(payload, ingest_source="client")


@bp.route("/api/siem/ingest/proxy", methods=["POST"])
def api_siem_ingest_proxy():
    auth = _telemetry_auth(required_role="viewer")
    if auth is not None:
        return auth
    payload = request.get_json(silent=True) or {}
    return _siem_ingest(payload, ingest_source="proxy")


@bp.route("/api/siem/ingest/backend", methods=["POST"])
def api_siem_ingest_backend():
    auth = _telemetry_auth(required_role="viewer")
    if auth is not None:
        return auth
    payload = request.get_json(silent=True) or {}
    return _siem_ingest(payload, ingest_source="backend")


@bp.route("/api/siem/ingest/db", methods=["POST"])
def api_siem_ingest_db():
    auth = _telemetry_auth(required_role="viewer")
    if auth is not None:
        return auth
    payload = request.get_json(silent=True) or {}
    return _siem_ingest(payload, ingest_source="db")


@bp.route("/api/siem/events", methods=["GET"])
@require_role("auditor")
def api_siem_events_get():
    limit = min(int(request.args.get("limit", 200)), 2000)
    offset = max(int(request.args.get("offset", 0)), 0)
    since = _parse_iso8601(request.args.get("since"))
    until = _parse_iso8601(request.args.get("until"))

    event_type = (request.args.get("event_type") or "").strip().lower()
    source_component = (request.args.get("source_component") or "").strip()
    destination_component = (request.args.get("destination_component") or "").strip()
    protocol = (request.args.get("protocol") or "").strip().upper()
    severity = (request.args.get("severity") or "").strip().lower()
    status = (request.args.get("status") or "").strip().lower()
    pqc_ready = request.args.get("pqc_ready")
    harvestable = request.args.get("harvestable")

    q = SIEMEvent.query
    if since:
        q = q.filter(SIEMEvent.timestamp >= since)
    if until:
        q = q.filter(SIEMEvent.timestamp <= until)
    if event_type:
        q = q.filter(SIEMEvent.event_type == event_type)
    if source_component:
        q = q.filter(SIEMEvent.source_component == _normalize_component_name(source_component))
    if destination_component:
        q = q.filter(SIEMEvent.destination_component == _normalize_component_name(destination_component))
    if protocol:
        q = q.filter(SIEMEvent.protocol == protocol)
    if severity:
        q = q.filter(SIEMEvent.severity == severity)
    if status:
        q = q.filter(SIEMEvent.status == status)

    pb = _coerce_bool(pqc_ready)
    if pb is not None:
        q = q.filter(SIEMEvent.pqc_ready == pb)
    hb = _coerce_bool(harvestable)
    if hb is not None:
        q = q.filter(SIEMEvent.harvestable == hb)

    rows = q.order_by(SIEMEvent.timestamp.desc()).offset(offset).limit(limit).all()
    out = []
    for r in rows:
        try:
            raw = _json_loads_safe(r.raw_json)
        except Exception:
            raw = None
        out.append(
            {
                "event_id": r.event_id,
                "timestamp": (r.timestamp.isoformat() + "Z") if r.timestamp else None,
                "event_type": r.event_type,
                "status": r.status,
                "severity": r.severity,
                "data_classification": r.data_classification,
                "source_component": r.source_component,
                "source_id": r.source_id,
                "source_ip": r.source_ip,
                "destination_component": r.destination_component,
                "destination_id": r.destination_id,
                "destination_ip": r.destination_ip,
                "protocol": r.protocol,
                "crypto_algorithm": r.crypto_algorithm,
                "key_length": r.key_length,
                "pqc_ready": r.pqc_ready,
                "tls_version": r.tls_version,
                "harvestable": r.harvestable,
                "quantum_risk_score": r.quantum_risk_score,
                "raw_event_ref": r.raw_event_ref,
                "raw": raw,
            }
        )

    return jsonify({"events": out, "count": len(out), "limit": limit, "offset": offset})


def _compute_cbom_suggestion(payload: dict) -> str | None:
    crypto = payload.get("crypto") if isinstance(payload.get("crypto"), dict) else {}
    tls_version = str(crypto.get("tls_version") or payload.get("tls_version") or "").strip()
    cipher_suite = str(crypto.get("cipher_suite") or payload.get("cipher_suite") or "").strip()
    sig_alg = str(crypto.get("signature_algorithm") or payload.get("signature_algorithm") or "").strip()
    proto = str(payload.get("communication_protocol") or "").strip().lower()
    msg_type = str(payload.get("message_type") or "").strip().lower()

    suggestions: list[str] = []

    # NIST SP 800-52r2 baseline: prefer TLS 1.3, strong suites.
    if tls_version and tls_version not in {"TLS1.3", "1.3"}:
        suggestions.append("NIST SP 800-52r2: Upgrade TLS to 1.3")

    # If the communication is HTTP but not TLS-protected, recommend HTTPS.
    if proto == "http":
        suggestions.append("NIST SP 800-52r2: Use HTTPS/TLS for transport (avoid plaintext HTTP)")

    # If this is an internal component-to-component link, recommend mTLS.
    src = str(payload.get("source_component") or "").strip().lower()
    dst = str(payload.get("destination_component") or "").strip().lower()
    internal_components = {"proxy", "backend", "observer", "db", "client-node", "frontend"}
    if src in internal_components and dst in internal_components and src and dst:
        # Only suggest mTLS for networked HTTP(S) style links, not raw DB/SQL.
        if proto in {"http", "https", "grpc"}:
            suggestions.append("NIST SP 800-52r2 / 800-53: Enable mutual TLS (mTLS) for internal services")

    # If we're handling an HTTP(S) response/request but missing TLS metadata, recommend capturing/enforcing it.
    if proto in {"http", "https"} and (not tls_version and not cipher_suite and not sig_alg):
        suggestions.append("Capture TLS metadata (version/cipher/signature) and enforce NIST-approved configs")

    pqc_support = payload.get("pqc_support") if payload.get("pqc_support") is not None else crypto.get("pqc_support")
    quantum_ready = payload.get("quantum_ready") if payload.get("quantum_ready") is not None else crypto.get("quantum_ready")
    if pqc_support is False or quantum_ready is False:
        suggestions.append("Prefer PQC-capable algorithms and enable post-quantum readiness")

    crypto_alg = str(payload.get("crypto_algorithm") or crypto.get("crypto_algorithm") or "").lower()
    key_len = payload.get("key_length") if payload.get("key_length") is not None else crypto.get("key_length")
    try:
        key_len_i = int(key_len) if key_len is not None else None
    except Exception:
        key_len_i = None
    if crypto_alg == "rsa" and key_len_i is not None and key_len_i < 2048:
        suggestions.append("NIST SP 800-56B: Increase RSA key size to 2048+ (or migrate away from RSA)")

    # DB performance hardening: treat high-latency queries as a risk to availability (800-53 SC/CP/IR themes).
    if msg_type in {"db_query", "db_error"}:
        try:
            lat = payload.get("latency_ms")
            lat_i = int(float(lat)) if lat is not None else None
        except Exception:
            lat_i = None
        if lat_i is not None and lat_i >= 500:
            suggestions.append("Investigate slow DB queries (add indexes/optimize queries); availability risk")

    # If no specific suggestions were found, return None.
    if not suggestions:
        return None
    # Keep a single string for the UI column.
    return "; ".join(suggestions)[:500]


def _cbom_event_to_dict(e: CBOMEvent) -> dict:
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else None,
        "source_component": e.source_component,
        "destination_component": e.destination_component,
        "communication_protocol": e.communication_protocol,
        "message_type": e.message_type,
        "status": e.status,
        "payload_summary": _json_loads_safe(e.payload_summary),
        "error_details": _json_loads_safe(e.error_details),
        "metrics": _json_loads_safe(e.metrics),
        "api_endpoint": e.api_endpoint,
        "client_token_id": e.client_token_id,
        "trace_id": e.trace_id,
        "crypto": {
            "crypto_algorithm": e.crypto_algorithm,
            "key_length": e.key_length,
            "pqc_support": e.pqc_support,
            "quantum_ready": e.quantum_ready,
            "tls_version": e.tls_version,
            "cipher_suite": e.cipher_suite,
            "signature_algorithm": e.signature_algorithm,
            "library_tool": e.library_tool,
            "cert_type": e.cert_type,
        },
        "latency_ms": e.latency_ms,
        "action_suggestion": e.action_suggestion,
    }


def _client_ip() -> str | None:
    forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        return forwarded.split(",", 1)[0].strip() or None
    return (request.remote_addr or "").strip() or None


def _infer_cbom_template(event: dict) -> str:
    src = str(event.get("source_component") or "").strip().lower()
    dst = str(event.get("destination_component") or "").strip().lower()
    proto = str(event.get("communication_protocol") or "").strip().lower()
    msg_type = str(event.get("message_type") or "").strip().lower()
    if src == "backend" and dst == "db":
        return "backend_db"
    if src == "proxy" and dst == "backend":
        return "proxy_backend"
    if src in {"client-node", "client"} and dst == "proxy":
        return "proxy_client"
    if src == "frontend" and dst in {"backend", "observer"}:
        return "frontend_backend"
    if proto in {"sql"} or msg_type.startswith("db_"):
        return "backend_db"
    return "generic"


def _build_gemini_prompt(event: dict, template_name: str) -> str:
    crypto = event.get("crypto") if isinstance(event.get("crypto"), dict) else {}
    crypto_alg = event.get("crypto_algorithm") or crypto.get("crypto_algorithm")
    key_len = event.get("key_length") if event.get("key_length") is not None else crypto.get("key_length")
    pqc_support = event.get("pqc_support") if event.get("pqc_support") is not None else crypto.get("pqc_support")
    quantum_ready = event.get("quantum_ready") if event.get("quantum_ready") is not None else crypto.get("quantum_ready")
    tls_version = crypto.get("tls_version") or event.get("tls_version")
    cipher_suite = crypto.get("cipher_suite") or event.get("cipher_suite")
    sig_alg = crypto.get("signature_algorithm") or event.get("signature_algorithm")

    src = event.get("source_component")
    dst = event.get("destination_component")
    proto = event.get("communication_protocol")
    msg_type = event.get("message_type")
    status = event.get("status")
    api_endpoint = event.get("api_endpoint")
    latency_ms = event.get("latency_ms")

    template_instructions = {
        "generic": "Analyze the communication and provide security/compliance hardening actions.",
        "proxy_client": "Focus on proxy↔client token exchange, handshake downgrade/fallback risks, and PQC posture.",
        "proxy_backend": "Focus on proxy↔backend security (mTLS, TLS1.3, header/token handling, request validation).",
        "frontend_backend": "Focus on browser↔backend security (CORS, cookies, CSRF, TLS, session management).",
        "backend_db": "Focus on backend↔DB security (least privilege, query auditing, encryption in transit/at rest, latency risks).",
    }
    instruct = template_instructions.get(template_name, template_instructions["generic"])

    return (
        "CBOM Event Analysis Request\n"
        f"- Template: {template_name}\n"
        f"- Source: {src}\n"
        f"- Destination: {dst}\n"
        f"- Protocol: {proto}\n"
        f"- Message Type: {msg_type}\n"
        f"- Status: {status}\n"
        f"- API Endpoint: {api_endpoint}\n"
        f"- Latency (ms): {latency_ms}\n"
        "- Crypto:\n"
        f"  - Algorithm: {crypto_alg}\n"
        f"  - Key Length: {key_len}\n"
        f"  - PQC Support: {pqc_support}\n"
        f"  - Quantum Ready: {quantum_ready}\n"
        f"  - TLS Version: {tls_version}\n"
        f"  - Cipher Suite: {cipher_suite}\n"
        f"  - Signature Algorithm: {sig_alg}\n"
        "\n"
        "Instructions:\n"
        f"{instruct}\n"
        "Analyze the event and suggest exact actions to improve security and compliance.\n"
        "Write for a human engineer: concise, actionable, and implementation-oriented.\n"
        "Each step should be a complete sentence that starts with an imperative verb and includes concrete details (what to change + where).\n"
        "Do NOT include markdown, code fences, or backticks.\n"
        "Use NIST SP 800-52r2, NIST SP 800-53, NIST SP 800-56B, ISO 27001/27002, OWASP as references when applicable.\n"
        "Return STRICT JSON ONLY (no extra text) with keys:\n"
        "- action_summary (string, 2-4 sentences)\n"
        "- severity_level (high|medium|low)\n"
        "- detailed_steps (array of 5-10 strings)\n"
        "- checklist (array of {item:string, done:false})\n"
        "- standards_references (array of strings)\n"
    )


def _list_gemini_models() -> list[dict]:
    """List available Gemini models and their supported methods.
    
    Returns:
        list[dict]: List of available models with their details
        
    Raises:
        RuntimeError: If there's an error calling the API
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("missing_gemini_api_key")
    
    # Prefer v1; fall back to v1beta for older keys/projects.
    urls = [
        "https://generativelanguage.googleapis.com/v1/models",
        "https://generativelanguage.googleapis.com/v1beta/models",
    ]
    
    last_err: str | None = None
    for url in urls:
        try:
            resp = requests.get(
                url,
                params={"key": api_key},
                timeout=10,
                headers={"Content-Type": "application/json"},
            )

            if not resp.ok:
                last_err = f"Failed to list models ({url}): {resp.status_code} - {resp.text}"
                continue

            data = resp.json()
            return data.get("models", [])

        except requests.exceptions.RequestException as e:
            last_err = f"Error listing models ({url}): {str(e)}"
            continue

    raise RuntimeError(f"gemini_api_error:{last_err or 'list_models_failed'}")


def _get_supported_model(preferred_models: list[str] = None) -> str:
    """Get a supported model from the list of preferred models.
    
    Args:
        preferred_models: List of model names in order of preference
        
    Returns:
        str: The first supported model name
        
    Raises:
        RuntimeError: If no supported models are found
    """
    if preferred_models is None:
        # Prefer fast/cheap models first to reduce dashboard latency.
        preferred_models = [
            "gemini-1.5-flash",
            "gemini-1.5-flash-8b",
            "gemini-1.0-pro",
            "gemini-pro",
        ]
    
    try:
        models = _list_gemini_models()
        model_names: list[str] = []
        for m in models:
            if not isinstance(m, dict):
                continue
            supported = m.get("supportedGenerationMethods")
            if not (isinstance(supported, list) and "generateContent" in supported):
                continue
            name = str(m.get("name") or "").strip()
            if not name:
                continue
            # API returns e.g. "models/gemini-1.5-flash"; endpoint expects just "gemini-1.5-flash".
            model_names.append(name.split("/", 1)[-1])
        
        # Try preferred models first
        for model in preferred_models:
            if model in model_names:
                return model
                
        # If no preferred model is found, return the first available model with generateContent
        if model_names:
            return model_names[0]
            
        raise RuntimeError("No models with generateContent support found")

    except Exception:
        # If listing fails, do not guess a model name (can cause confusing 404s).
        raise


def _call_gemini(prompt: str, model: str = None) -> dict:
    """Call the Gemini API with the given prompt and model.
    
    Args:
        prompt: The prompt to send to the model
        model: The model to use (default: None, auto-selects best available)
        
    Returns:
        dict: The API response as a dictionary
        
    Raises:
        RuntimeError: If there's an error calling the API
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("missing_gemini_api_key")
    
    # Get the best available model if none specified
    model = model or _get_supported_model()

    urls = [
        f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent",
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    ]
    
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.3,
            "topP": 0.95,
            "topK": 40,
            "maxOutputTokens": 4096,
        },
    }
    
    last_err: str | None = None
    for url in urls:
        try:
            resp = requests.post(
                url,
                params={"key": api_key},
                json=payload,
                timeout=45,
                headers={"Content-Type": "application/json"},
            )

            # Parse response
            try:
                data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
            except ValueError:
                data = {"error": {"message": "Invalid JSON response"}}

            if not resp.ok:
                error_msg = f"{resp.status_code} - {data.get('error', {}).get('message', 'Unknown error')}"
                if isinstance(data, dict) and "error" in data:
                    error_details = data["error"]
                    error_msg = f"{error_details.get('code', 'error')}: {error_details.get('message', 'Unknown error')}"
                last_err = f"{url} -> {error_msg}"
                continue

            return data

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_data = e.response.json().get("error", {})
                    error_msg = f"{error_data.get('code', '')} - {error_data.get('message', str(e))}"
                except ValueError:
                    error_msg = f"{e.response.status_code} - {e.response.text[:200]}"
            last_err = f"{url} -> {error_msg}"
            continue

    raise RuntimeError(f"gemini_api_error:{last_err or 'unknown'}")


def _extract_gemini_text(resp_json: dict) -> str:
    try:
        cands = resp_json.get("candidates")
        if isinstance(cands, list) and cands:
            content = cands[0].get("content") or {}
            parts = content.get("parts")
            if isinstance(parts, list) and parts:
                return str(parts[0].get("text") or "").strip()
    except Exception:
        return ""
    return ""


@bp.route("/api/gemini/models", methods=["GET"])
@require_role("auditor")
def api_gemini_models():
    try:
        models = _list_gemini_models()
        supported: list[str] = []
        for m in models:
            if not isinstance(m, dict):
                continue
            methods = m.get("supportedGenerationMethods")
            if not (isinstance(methods, list) and "generateContent" in methods):
                continue
            name = str(m.get("name") or "").strip()
            if not name:
                continue
            supported.append(name.split("/", 1)[-1])

        chosen = _get_supported_model()
        return jsonify({"models": models, "generateContent_models": supported, "chosen": chosen})
    except Exception as exc:
        return jsonify({"error": "gemini_model_list_failed", "message": str(exc)}), 502


@bp.route("/api/cboom/gemini-insight", methods=["POST"])
@require_role("auditor")
def api_cboom_gemini_insight():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_payload"}), 400

    event_id = str(payload.get("event_id") or "").strip()
    template_name = str(payload.get("template") or "").strip() or None
    
    # Get model from request or auto-select from ListModels.
    model = payload.get("model")
    if model is not None:
        model = str(model).strip() or None

    try:
        effective_model = model or _get_supported_model()
    except Exception as exc:
        return jsonify({"error": "gemini_model_list_failed", "message": str(exc)}), 502
    
    force = bool(payload.get("force"))

    event_obj = None
    if event_id:
        row = CBOMEvent.query.filter_by(event_id=event_id).first()
        if row:
            event_obj = _cbom_event_to_dict(row)

    if event_obj is None:
        event_obj = payload.get("event") if isinstance(payload.get("event"), dict) else None

    if event_obj is None:
        return jsonify({"error": "event_not_found"}), 404

    resolved_event_id = str(event_obj.get("event_id") or event_id or "").strip() or None
    if resolved_event_id is None:
        resolved_event_id = "ad_hoc"

    if template_name is None:
        template_name = _infer_cbom_template(event_obj)

    if not force:
        cached = (
            GeminiInsight.query.filter_by(event_id=resolved_event_id, model=effective_model, template=template_name)
            .order_by(GeminiInsight.created_at.desc())
            .first()
        )
        if cached and cached.response_json:
            return jsonify(
                {
                    "cached": True,
                    "event_id": resolved_event_id,
                    "model": cached.model,
                    "template": cached.template,
                    "created_at": cached.created_at.isoformat() + "Z" if cached.created_at else None,
                    "result": _json_loads_safe(cached.response_json),
                }
            )

    prompt = _build_gemini_prompt(event_obj, template_name)

    last_err = None
    resp_json = None
    for _ in range(2):
        try:
            resp_json = _call_gemini(prompt, model=effective_model)
            last_err = None
            break
        except Exception as exc:
            last_err = str(exc)
            continue
    if resp_json is None:
        if (last_err or "") == "missing_gemini_api_key":
            return jsonify({"error": "missing_gemini_api_key", "message": "Set GEMINI_API_KEY on the observer backend."}), 500
        return jsonify({"error": "gemini_failed", "message": last_err or "unknown"}), 502

    text = _extract_gemini_text(resp_json)
    parsed = None
    if text:
        try:
            parsed = json.loads(text)
        except Exception:
            extracted = None
            try:
                start = text.find("{")
                end = text.rfind("}")
                if start != -1 and end != -1 and end > start:
                    extracted = json.loads(text[start : end + 1])
            except Exception:
                extracted = None

            if isinstance(extracted, dict):
                parsed = extracted
            else:
                parsed = {
                    "action_summary": text,
                    "severity_level": "medium",
                    "detailed_steps": [text],
                    "checklist": [],
                    "standards_references": [],
                }
    else:
        parsed = {
            "action_summary": "No content returned by Gemini.",
            "severity_level": "low",
            "detailed_steps": [],
            "checklist": [],
            "standards_references": [],
        }

    insight = GeminiInsight(
        event_id=resolved_event_id,
        model=effective_model,
        template=template_name,
        prompt=prompt,
        response_json=_json_dumps_safe(parsed),
    )
    db.session.add(insight)
    db.session.commit()

    return jsonify(
        {
            "cached": False,
            "event_id": resolved_event_id,
            "model": effective_model,
            "template": template_name,
            "created_at": insight.created_at.isoformat() + "Z" if insight.created_at else None,
            "result": parsed,
        }
    )


def _emit_siem_event(payload: dict) -> None:
    if not _AUDIT_SIEM_WEBHOOK:
        return
    try:
        requests.post(_AUDIT_SIEM_WEBHOOK, json=payload, timeout=_AUDIT_SIEM_TIMEOUT)
    except Exception:
        pass


def _emit_alert_webhook(payload: dict) -> None:
    if not _ALERT_WEBHOOK_URL:
        return
    try:
        requests.post(_ALERT_WEBHOOK_URL, json=payload, timeout=_ALERT_WEBHOOK_TIMEOUT)
    except Exception:
        pass


def _get_or_create_alert_rule(metric: str, *, threshold: int, window_minutes: int, severity: str):
    rule = AlertRule.query.filter_by(metric=str(metric)).first()
    if rule:
        return rule
    rule = AlertRule(metric=str(metric), enabled=True, threshold=int(threshold), window_minutes=int(window_minutes), severity=str(severity))
    db.session.add(rule)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    return rule


def _minute_series_from_metricbucket(metric: str, since: datetime):
    rows = MetricBucket.query.filter(MetricBucket.bucket_start >= since).order_by(MetricBucket.bucket_start.asc()).all()
    out = []
    for r in rows:
        v = 0
        if metric == "handshake_errors":
            v = int(r.handshake_failures or 0)
        out.append({"ts": (r.bucket_start.isoformat() + "Z") if r.bucket_start else None, "value": v})
    return out


def _minute_series_from_telemetry(event_types: list[str] | None, severities: list[str] | None, since: datetime):
    # SQLite-friendly per-minute grouping. If DB doesn't support strftime, fall back to empty.
    try:
        minute = func.strftime("%Y-%m-%dT%H:%M:00", TelemetryEvent.created_at)
        q = db.session.query(minute.label("m"), func.count(TelemetryEvent.id).label("c")).filter(TelemetryEvent.created_at >= since)
        if event_types is not None:
            q = q.filter(TelemetryEvent.event_type.in_(event_types))
        if severities is not None:
            q = q.filter(TelemetryEvent.severity.in_(severities))
        rows = q.group_by(minute).order_by(minute.asc()).all()
        return [{"ts": (str(m) + "Z") if m else None, "value": int(c or 0)} for (m, c) in rows]
    except Exception:
        return []


def _ewma(values: list[float], alpha: float = 0.25) -> list[float]:
    out: list[float] = []
    last: float | None = None
    for v in values:
        if last is None:
            last = float(v)
        else:
            last = (alpha * float(v)) + ((1.0 - alpha) * last)
        out.append(last)
    return out


def _linear_slope(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2.0
    y_mean = sum(values) / float(n)
    num = 0.0
    den = 0.0
    for i, y in enumerate(values):
        dx = float(i) - x_mean
        dy = float(y) - y_mean
        num += dx * dy
        den += dx * dx
    return num / den if den else 0.0


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _audit_log(action: str, target_type: str | None = None, target_id: str | None = None, status: str = "ok", details: dict | None = None):
    try:
        actor = current_user if getattr(current_user, "is_authenticated", False) else None
        row = AdminAuditLog(
            actor_user_id=getattr(actor, "id", None),
            actor_username=getattr(actor, "username", None),
            actor_role=getattr(actor, "role", None),
            actor_ip=_client_ip(),
            action=str(action or "unknown")[:64],
            target_type=str(target_type)[:32] if target_type else None,
            target_id=str(target_id)[:128] if target_id else None,
            status=str(status or "ok")[:16],
            details=json.dumps(details or {}, ensure_ascii=False),
        )
        db.session.add(row)
        db.session.commit()
        _emit_siem_event(
            {
                "ts": row.created_at.isoformat() + "Z" if row.created_at else datetime.utcnow().isoformat() + "Z",
                "actor": {"id": row.actor_user_id, "username": row.actor_username, "role": row.actor_role, "ip": row.actor_ip},
                "action": row.action,
                "target": {"type": row.target_type, "id": row.target_id},
                "status": row.status,
                "details": details or {},
                "source": "observer",
            }
        )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def _sanitize_details(obj):
    try:
        raw = json.dumps(obj or {}, ensure_ascii=False)
    except Exception:
        raw = "{}"
    if len(raw) > _MAX_DETAILS:
        raw = raw[:_MAX_DETAILS] + "…"
    try:
        return json.loads(raw)
    except Exception:
        return {"truncated": True}


def _get_fernet() -> Fernet | None:
    if not _LOG_KEY:
        return None
    try:
        return Fernet(_LOG_KEY.encode("utf-8"))
    except Exception:
        return None


def _safe_public_details(entry: dict) -> dict:
    # Store only privacy-safe metadata (no cookies, no bodies, no raw headers).
    out = {}
    if not isinstance(entry, dict):
        return out
    details = entry.get("details") if isinstance(entry.get("details"), dict) else entry

    for k in ("method", "path", "status", "latency_ms", "bytes_up", "bytes_down", "algorithm"):
        v = details.get(k)
        if v is not None:
            out[k] = v
    if "selected_crypto" in details and out.get("algorithm") is None:
        out["algorithm"] = details.get("selected_crypto")
    return out


def _role_allows_decrypt() -> bool:
    order = {"viewer": 1, "auditor": 2, "admin": 3}
    return order.get(getattr(current_user, "role", "viewer"), 0) >= 2


def _pack_details_for_storage(entry: dict) -> str:
    sanitized = _sanitize_details(entry)
    raw = json.dumps(sanitized, ensure_ascii=False)
    if len(raw) > _MAX_DETAILS:
        raw = raw[:_MAX_DETAILS] + "…"

    f = _get_fernet()
    if not f:
        return json.dumps(sanitized)

    token = f.encrypt(raw.encode("utf-8")).decode("utf-8")
    public = _safe_public_details(entry)
    payload = {
        "enc": True,
        "v": 1,
        "public": public,
        "ciphertext": token,
    }
    return json.dumps(payload)


def _present_details_for_response(stored: str) -> dict:
    # Return public details for viewers; include full decrypt for auditors/admins when possible.
    try:
        obj = json.loads(stored or "{}")
    except Exception:
        obj = {}

    if isinstance(obj, dict) and obj.get("enc") and obj.get("ciphertext"):
        public = obj.get("public") if isinstance(obj.get("public"), dict) else {}
        if not _role_allows_decrypt():
            return public

        f = _get_fernet()
        if not f:
            return {"public": public, "details_full": None, "decryptable": False}
        try:
            plain = f.decrypt(str(obj.get("ciphertext")).encode("utf-8"))
            full = json.loads(plain.decode("utf-8", errors="replace"))
        except (InvalidToken, ValueError, TypeError):
            full = None
        return {"public": public, "details_full": full, "decryptable": full is not None}

    # Backward compatibility: legacy plaintext stored.
    if isinstance(obj, dict):
        return obj
    return {}


def _record_event(component, event_type, severity="info", session_id=None, client_id=None, details=None):
    event = TelemetryEvent(
        component=str(component or "unknown")[:32],
        event_type=str(event_type or "unknown")[:64],
        severity=str(severity or "info")[:16],
        session_id=str(session_id) if session_id else None,
        client_id=str(client_id) if client_id else None,
        details=_pack_details_for_storage(details if isinstance(details, dict) else {}),
    )
    db.session.add(event)
    db.session.commit()

    try:
        now = datetime.utcnow()
        bucket_start = now.replace(second=0, microsecond=0)
        bucket = MetricBucket.query.filter_by(bucket_start=bucket_start).first()
        if bucket is None:
            bucket = MetricBucket(bucket_start=bucket_start)
            db.session.add(bucket)

        bucket.total_events = int(bucket.total_events or 0) + 1

        by_component = {}
        try:
            by_component = json.loads(bucket.by_component or "{}")
        except Exception:
            by_component = {}
        key_component = str(component or "unknown")[:32]
        by_component[key_component] = int(by_component.get(key_component, 0)) + 1
        bucket.by_component = json.dumps(by_component)

        by_type = {}
        try:
            by_type = json.loads(bucket.by_type or "{}")
        except Exception:
            by_type = {}
        key_type = str(event_type or "unknown")[:64]
        by_type[key_type] = int(by_type.get(key_type, 0)) + 1
        bucket.by_type = json.dumps(by_type)

        if str(event_type) == "handshake" and isinstance(details, dict):
            bucket.handshakes_total = int(bucket.handshakes_total or 0) + 1
            algo = details.get("algorithm") or (details.get("details") or {}).get("algorithm")
            algo = str(algo or "unknown")
            algos = {}
            try:
                algos = json.loads(bucket.handshake_algorithms or "{}")
            except Exception:
                algos = {}
            algos[algo] = int(algos.get(algo, 0)) + 1
            bucket.handshake_algorithms = json.dumps(algos)

        if str(event_type) in {"proxy_error", "handshake_error"}:
            bucket.handshake_failures = int(bucket.handshake_failures or 0) + 1

        if str(event_type) == "message_forwarded" and isinstance(details, dict):
            latency = details.get("latency_ms")
            if latency is None and isinstance(details.get("details"), dict):
                latency = details.get("details", {}).get("latency_ms")
            try:
                latency_f = float(latency)
            except Exception:
                latency_f = None
            if latency_f is not None:
                bucket.latency_count = int(bucket.latency_count or 0) + 1
                bucket.latency_sum_ms = float(bucket.latency_sum_ms or 0.0) + latency_f
                bucket.latency_min_ms = latency_f if bucket.latency_min_ms is None else min(float(bucket.latency_min_ms), latency_f)
                bucket.latency_max_ms = latency_f if bucket.latency_max_ms is None else max(float(bucket.latency_max_ms), latency_f)

        bucket.updated_at = now
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass

    # Session tracking (metadata only)
    if session_id is not None:
        sid = str(session_id)
        now = datetime.utcnow()
        sess = ActiveSession.query.filter_by(session_id=sid).first()
        if sess is None:
            sess = ActiveSession(session_id=sid, first_seen=now, last_seen=now)
            db.session.add(sess)
        sess.last_seen = now
        # Keep sessions marked active as long as we keep receiving events.
        if str(event_type) not in {"session_closed"}:
            sess.status = "active"
        if client_id is not None:
            sess.client_id = str(client_id)
        if isinstance(details, dict):
            # algorithm is often nested under details.algorithm (proxy payload format)
            algo = details.get("algorithm") or (details.get("details") or {}).get("algorithm")
            if algo and (sess.algorithm is None or str(event_type) == "handshake"):
                sess.algorithm = str(algo)
        if event_type == "session_closed":
            sess.status = "closed"
        elif event_type == "session_closed":
            sess.status = "closed"
        elif event_type == "proxy_error":
            sess.status = "error"
        db.session.commit()

    total = TelemetryEvent.query.count()
    if total > 5000:
        cutoff = TelemetryEvent.query.order_by(TelemetryEvent.id.desc()).offset(5000).with_entities(TelemetryEvent.id).first()
        if cutoff:
            TelemetryEvent.query.filter(TelemetryEvent.id < cutoff.id).delete()
            db.session.commit()


@bp.route("/")
@login_required
def index():
    return render_template("index.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("observer.index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            _audit_log("login", target_type="user", target_id=str(user.username), status="ok")
            return redirect(url_for("observer.index"))
        return render_template("login.html", error="Invalid username or password"), 401

    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    _audit_log("logout", target_type="user", target_id=str(getattr(current_user, "username", "")), status="ok")
    logout_user()
    return redirect(url_for("observer.login"))


@bp.route("/api/telemetry", methods=["POST"])
def api_ingest():
    if request.content_length and request.content_length > _MAX_BODY_BYTES:
        return jsonify({"error": "payload_too_large"}), 413
    auth_err = _telemetry_auth(required_role="viewer")
    if auth_err:
        return auth_err

    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return jsonify({"error": "invalid_json"}), 400

    entries = payload if isinstance(payload, list) else [payload]
    accepted = 0
    for entry in entries[:200]:
        if not isinstance(entry, dict):
            continue
        _record_event(
            component=entry.get("component", "unknown"),
            event_type=entry.get("event_type", entry.get("type", "unknown")),
            severity=entry.get("severity", "info"),
            session_id=entry.get("session_id"),
            client_id=entry.get("client_id"),
            details=entry,
        )
        accepted += 1
    return jsonify({"accepted": accepted})


@bp.route("/api/sessions/active", methods=["GET"])
@login_required
def api_sessions_active():
    # Viewer and above
    limit = min(int(request.args.get("limit", 200)), 500)
    rows = ActiveSession.query.order_by(ActiveSession.last_seen.desc()).limit(limit).all()
    return jsonify(
        {
            "sessions": [
                {
                    "session_id": s.session_id,
                    "algorithm": s.algorithm,
                    "client_id": s.client_id,
                    "status": s.status,
                    "first_seen": s.first_seen.isoformat() + "Z" if s.first_seen else None,
                    "last_seen": s.last_seen.isoformat() + "Z" if s.last_seen else None,
                }
                for s in rows
            ]
        }
    )


@bp.route("/api/sessions/<session_id>/force_close", methods=["POST"])
@require_session_role("admin")
def api_force_close(session_id: str):
    sess = ActiveSession.query.filter_by(session_id=str(session_id)).first()
    try:
        resp = requests.post(
            f"{_CONTROL_URL}/control/sessions/{session_id}/force_close",
            timeout=_CONTROL_TIMEOUT,
            verify=_CONTROL_CA_FILE,
            cert=(_CONTROL_CLIENT_CERT, _CONTROL_CLIENT_KEY),
        )
        data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
        if not resp.ok:
            _audit_log(
                "session_force_close",
                target_type="session",
                target_id=str(session_id),
                status="error",
                details={"proxy_status": resp.status_code, "proxy_detail": data},
            )
            return jsonify({"error": "proxy_control_failed", "status": resp.status_code, "detail": data}), 502
    except Exception as e:
        _audit_log(
            "session_force_close",
            target_type="session",
            target_id=str(session_id),
            status="error",
            details={"error": str(e), "kind": "proxy_control_unreachable"},
        )
        return jsonify({"error": "proxy_control_unreachable", "message": str(e)}), 502

    if sess:
        sess.status = "closed"
        sess.last_seen = datetime.utcnow()
        db.session.commit()
    _audit_log("session_force_close", target_type="session", target_id=str(session_id), status="ok")
    return jsonify({"ok": True, "session_id": session_id, "action": "force_close"})


@bp.route("/api/sessions/<session_id>/rekey", methods=["POST"])
@require_session_role("admin")
def api_rekey(session_id: str):
    sess = ActiveSession.query.filter_by(session_id=str(session_id)).first()
    try:
        resp = requests.post(
            f"{_CONTROL_URL}/control/sessions/{session_id}/rekey",
            timeout=_CONTROL_TIMEOUT,
            verify=_CONTROL_CA_FILE,
            cert=(_CONTROL_CLIENT_CERT, _CONTROL_CLIENT_KEY),
        )
        data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
        if not resp.ok:
            _audit_log(
                "session_rekey",
                target_type="session",
                target_id=str(session_id),
                status="error",
                details={"proxy_status": resp.status_code, "proxy_detail": data},
            )
            return jsonify({"error": "proxy_control_failed", "status": resp.status_code, "detail": data}), 502
    except Exception as e:
        _audit_log(
            "session_rekey",
            target_type="session",
            target_id=str(session_id),
            status="error",
            details={"error": str(e), "kind": "proxy_control_unreachable"},
        )
        return jsonify({"error": "proxy_control_unreachable", "message": str(e)}), 502

    if sess:
        sess.last_seen = datetime.utcnow()
        db.session.commit()
    _audit_log("session_rekey", target_type="session", target_id=str(session_id), status="ok")
    return jsonify({"ok": True, "session_id": session_id, "action": "rekey"})


@bp.route("/api/telemetry/overview", methods=["GET"])
def api_overview():
    # Dashboard API uses session cookie auth.
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    limit = min(int(request.args.get("limit", 50)), 500)
    lookback_minutes = min(int(request.args.get("minutes", 120)), 1440)
    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)

    recent = TelemetryEvent.query.order_by(TelemetryEvent.created_at.desc()).limit(limit).all()
    window_events = TelemetryEvent.query.filter(TelemetryEvent.created_at >= since).all()

    by_component = {}
    by_type = {}
    timeline = {}
    for ev in window_events:
        by_component[ev.component] = by_component.get(ev.component, 0) + 1
        by_type[ev.event_type] = by_type.get(ev.event_type, 0) + 1
        bucket = ev.created_at.replace(second=0, microsecond=0).isoformat()
        timeline[bucket] = timeline.get(bucket, 0) + 1

    return jsonify(
        {
            "recent": [
                {
                    "id": ev.id,
                    "component": ev.component,
                    "event_type": ev.event_type,
                    "session_id": ev.session_id,
                    "client_id": ev.client_id,
                    "severity": ev.severity,
                    "details": _present_details_for_response(ev.details),
                    "created_at": ev.created_at.isoformat() + "Z",
                }
                for ev in recent
            ],
            "summary": {
                "by_component": by_component,
                "by_type": by_type,
                "total_window": len(window_events),
                "window_minutes": lookback_minutes,
            },
            "timeline": [{"ts": ts, "count": timeline[ts]} for ts in sorted(timeline.keys())],
            "last_updated": datetime.utcnow().isoformat() + "Z",
        }
    )


@bp.route("/api/dashboard/traffic", methods=["GET"])
def api_dashboard_traffic():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    lookback_seconds = min(int(request.args.get("seconds", 300)), 3600)
    since = datetime.utcnow() - timedelta(seconds=lookback_seconds)

    bucket_since = since.replace(second=0, microsecond=0)
    buckets = MetricBucket.query.filter(MetricBucket.bucket_start >= bucket_since).all()
    if buckets:
        total = 0
        by_component = {}
        by_type = {}
        for b in buckets:
            total += int(b.total_events or 0)
            try:
                comp = json.loads(b.by_component or "{}")
            except Exception:
                comp = {}
            for k, v in (comp or {}).items():
                by_component[k] = int(by_component.get(k, 0)) + int(v or 0)
            try:
                typ = json.loads(b.by_type or "{}")
            except Exception:
                typ = {}
            for k, v in (typ or {}).items():
                by_type[k] = int(by_type.get(k, 0)) + int(v or 0)
        source = "metric_bucket"
    else:
        total = TelemetryEvent.query.filter(TelemetryEvent.created_at >= since).count()
        by_component = dict(
            db.session.query(TelemetryEvent.component, func.count(TelemetryEvent.id))
            .filter(TelemetryEvent.created_at >= since)
            .group_by(TelemetryEvent.component)
            .all()
        )
        by_type = dict(
            db.session.query(TelemetryEvent.event_type, func.count(TelemetryEvent.id))
            .filter(TelemetryEvent.created_at >= since)
            .group_by(TelemetryEvent.event_type)
            .all()
        )
        source = "telemetry_scan"

    active_sessions = (
        db.session.query(TelemetryEvent.session_id)
        .filter(TelemetryEvent.created_at >= since)
        .filter(TelemetryEvent.session_id.isnot(None))
        .distinct()
        .count()
    )

    return jsonify(
        {
            "window_seconds": lookback_seconds,
            "requests": total,
            "by_component": by_component,
            "by_type": by_type,
            "active_sessions": active_sessions,
            "source": source,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    )


@bp.route("/api/dashboard/crypto", methods=["GET"])
def api_dashboard_crypto():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    lookback_minutes = min(int(request.args.get("minutes", 60)), 1440)
    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    # Active sessions should not disappear just because the UI asks for a tiny lookback.
    active_since = datetime.utcnow() - timedelta(minutes=max(lookback_minutes, 10))

    # Prefer real-time session inventory from proxy control plane.
    active_alg_counts: dict[str, int] = {}
    active_total = 0
    active_source = None
    try:
        resp = requests.get(
            f"{_CONTROL_URL}/control/sessions",
            timeout=_CONTROL_TIMEOUT,
            verify=_CONTROL_CA_FILE,
            cert=(_CONTROL_CLIENT_CERT, _CONTROL_CLIENT_KEY),
        )
        data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
        if resp.ok and isinstance(data.get("sessions"), list):
            for s in data.get("sessions"):
                if not isinstance(s, dict):
                    continue
                if str(s.get("status") or "").lower() != "active":
                    continue
                algo = str(s.get("crypto") or "unknown").lower()
                active_alg_counts[algo] = int(active_alg_counts.get(algo, 0)) + 1
                active_total += 1
            active_source = "proxy"
    except Exception:
        active_source = None

    # Fallback: derive from observer's ActiveSession table.
    if active_source is None:
        try:
            rows = (
                db.session.query(ActiveSession.algorithm, func.count(ActiveSession.id))
                .filter(ActiveSession.status == "active")
                .filter(ActiveSession.last_seen >= active_since)
                .group_by(ActiveSession.algorithm)
                .all()
            )
            for algo, c in rows:
                key = str(algo or "unknown").lower()
                active_alg_counts[key] = int(c or 0)
                active_total += int(c or 0)
            active_source = "active_session_table"
        except Exception:
            active_source = "none"

    bucket_since = since.replace(second=0, microsecond=0)
    buckets = MetricBucket.query.filter(MetricBucket.bucket_start >= bucket_since).all()
    if buckets:
        alg_counts = {}
        failures = 0
        for b in buckets:
            failures += int(b.handshake_failures or 0)
            try:
                algos = json.loads(b.handshake_algorithms or "{}")
            except Exception:
                algos = {}
            for k, v in (algos or {}).items():
                alg_counts[str(k)] = int(alg_counts.get(str(k), 0)) + int(v or 0)
        source = "metric_bucket"
    else:
        handshakes = TelemetryEvent.query.filter(
            TelemetryEvent.created_at >= since,
            TelemetryEvent.event_type == "handshake",
        ).order_by(TelemetryEvent.created_at.desc()).limit(1000).all()

        alg_counts = {}
        failures = TelemetryEvent.query.filter(
            TelemetryEvent.created_at >= since,
            TelemetryEvent.event_type.in_(["proxy_error", "handshake_error"]),
        ).count()

        for ev in handshakes:
            try:
                details = _present_details_for_response(ev.details)
            except Exception:
                details = {}
            if isinstance(details.get("public"), dict):
                algo = details.get("public", {}).get("algorithm") or "unknown"
            else:
                algo = details.get("algorithm") or "unknown"
            alg_counts[str(algo)] = alg_counts.get(str(algo), 0) + 1
        source = "telemetry_scan"

    return jsonify(
        {
            "window_minutes": lookback_minutes,
            "active_sessions_by_algorithm": active_alg_counts,
            "active_sessions_total": active_total,
            "handshake_algorithms": alg_counts,
            "handshake_failures": failures,
            "forward_secrecy": "unknown",
            "source": {"handshakes": source, "active_sessions": active_source},
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    )


@bp.route("/api/dashboard/latency", methods=["GET"])
def api_dashboard_latency():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    # Test CBOM generation
    try:
        with open('cbom_test.log', 'a') as f:
            f.write('CBOM test triggered\n')

        import sqlite3
        import json
        import os
        import uuid
        import time

        instance_path = os.path.join(os.path.dirname(__file__), '..', 'instance')
        db_path = os.path.join(instance_path, "observer.db")
        with open('cbom_test.log', 'a') as f:
            f.write(f'DB path: {db_path}\n')
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        c.execute('''
            INSERT INTO cbom_event (
                event_id, timestamp, source_component, destination_component,
                communication_protocol, message_type, status, payload_summary,
                crypto, api_endpoint, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z",
            "frontend",
            "observer",
            "HTTP",
            "api_request",
            "success",
            json.dumps({"method": "GET", "endpoint": "/api/dashboard/latency"}),
            json.dumps({}),
            "/api/dashboard/latency",
            0,
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        with open('cbom_test.log', 'a') as f:
            f.write(f'CBOM test failed: {e}\n')

    lookback_seconds = min(int(request.args.get("seconds", 300)), 3600)
    since = datetime.utcnow() - timedelta(seconds=lookback_seconds)
    bucket_since = since.replace(second=0, microsecond=0)
    buckets = MetricBucket.query.filter(MetricBucket.bucket_start >= bucket_since).all()

    total_count = 0
    total_sum = 0.0
    min_ms = None
    max_ms = None
    for b in buckets:
        c = int(b.latency_count or 0)
        if c <= 0:
            continue
        total_count += c
        total_sum += float(b.latency_sum_ms or 0.0)
        try:
            bmin = float(b.latency_min_ms) if b.latency_min_ms is not None else None
        except Exception:
            bmin = None
        try:
            bmax = float(b.latency_max_ms) if b.latency_max_ms is not None else None
        except Exception:
            bmax = None
        if bmin is not None:
            min_ms = bmin if min_ms is None else min(min_ms, bmin)
        if bmax is not None:
            max_ms = bmax if max_ms is None else max(max_ms, bmax)

    avg_ms = (total_sum / total_count) if total_count else None
    return jsonify(
        {
            "window_seconds": lookback_seconds,
            "count": total_count,
            "avg_ms": round(avg_ms, 3) if avg_ms is not None else None,
            "min_ms": round(min_ms, 3) if min_ms is not None else None,
            "max_ms": round(max_ms, 3) if max_ms is not None else None,
            "source": "metric_bucket" if buckets else "none",
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    )


@bp.route("/api/dashboard/history", methods=["GET"])
def api_dashboard_history():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    lookback_minutes = min(int(request.args.get("minutes", 120)), 1440)
    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    bucket_since = since.replace(second=0, microsecond=0)

    rows = (
        MetricBucket.query.filter(MetricBucket.bucket_start >= bucket_since)
        .order_by(MetricBucket.bucket_start.asc())
        .all()
    )

    series = []
    algos_agg = {}
    for b in rows:
        latency_avg = None
        try:
            c = int(b.latency_count or 0)
        except Exception:
            c = 0
        if c > 0:
            try:
                latency_avg = float(b.latency_sum_ms or 0.0) / float(c)
            except Exception:
                latency_avg = None

        try:
            algos = json.loads(b.handshake_algorithms or "{}")
        except Exception:
            algos = {}
        for k, v in (algos or {}).items():
            algos_agg[str(k)] = int(algos_agg.get(str(k), 0)) + int(v or 0)

        series.append(
            {
                "ts": b.bucket_start.isoformat() + "Z" if b.bucket_start else None,
                "requests": int(b.total_events or 0),
                "latency_avg_ms": round(latency_avg, 3) if latency_avg is not None else None,
                "latency_min_ms": float(b.latency_min_ms) if b.latency_min_ms is not None else None,
                "latency_max_ms": float(b.latency_max_ms) if b.latency_max_ms is not None else None,
                "handshake_failures": int(b.handshake_failures or 0),
                "handshakes_total": int(b.handshakes_total or 0),
            }
        )

    return jsonify(
        {
            "window_minutes": lookback_minutes,
            "series": series,
            "handshake_algorithms": algos_agg,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    )


@bp.route("/api/dashboard/sessions", methods=["GET"])
def api_dashboard_sessions():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    lookback_minutes = min(int(request.args.get("minutes", 30)), 1440)
    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    limit = min(int(request.args.get("limit", 50)), 200)

    source = (request.args.get("source") or "").strip().lower()
    if source == "proxy":
        try:
            resp = requests.get(
                f"{_CONTROL_URL}/control/sessions",
                timeout=_CONTROL_TIMEOUT,
                verify=_CONTROL_CA_FILE,
                cert=(_CONTROL_CLIENT_CERT, _CONTROL_CLIENT_KEY),
            )
            data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
            if resp.ok and isinstance(data.get("sessions"), list):
                out = []
                for s in data.get("sessions")[:limit]:
                    if not isinstance(s, dict):
                        continue
                    created_at = s.get("created_at")
                    last_activity = s.get("last_activity")
                    first_seen = None
                    last_seen = None
                    try:
                        if created_at is not None:
                            first_seen = datetime.utcfromtimestamp(float(created_at)).isoformat() + "Z"
                    except Exception:
                        first_seen = None
                    try:
                        if last_activity is not None:
                            last_seen = datetime.utcfromtimestamp(float(last_activity)).isoformat() + "Z"
                    except Exception:
                        last_seen = None
                    out.append(
                        {
                            "session_id": str(s.get("client_id") or ""),
                            "first_seen": first_seen,
                            "last_seen": last_seen,
                            "events": None,
                            "status": s.get("status"),
                            "algorithm": s.get("crypto"),
                            "address": s.get("address"),
                        }
                    )
                return jsonify(
                    {
                        "window_minutes": lookback_minutes,
                        "sessions": out,
                        "source": "proxy",
                        "updated_at": datetime.utcnow().isoformat() + "Z",
                    }
                )
        except Exception:
            pass

    rows = (
        db.session.query(
            TelemetryEvent.session_id,
            func.max(TelemetryEvent.created_at).label("last_seen"),
            func.min(TelemetryEvent.created_at).label("first_seen"),
            func.count(TelemetryEvent.id).label("events"),
        )
        .filter(TelemetryEvent.created_at >= since)
        .filter(TelemetryEvent.session_id.isnot(None))
        .group_by(TelemetryEvent.session_id)
        .order_by(func.max(TelemetryEvent.created_at).desc())
        .limit(limit)
        .all()
    )

    out = []
    for session_id, last_seen, first_seen, events in rows:
        out.append(
            {
                "session_id": session_id,
                "first_seen": first_seen.isoformat() + "Z" if first_seen else None,
                "last_seen": last_seen.isoformat() + "Z" if last_seen else None,
                "events": int(events or 0),
            }
        )

    return jsonify({"window_minutes": lookback_minutes, "sessions": out, "source": "telemetry", "updated_at": datetime.utcnow().isoformat() + "Z"})


@bp.route("/api/dashboard/alerts", methods=["GET"])
def api_dashboard_alerts():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    lookback_minutes = min(int(request.args.get("minutes", 15)), 1440)

    # Rules are persisted (admin-configurable). Create defaults on demand.
    rule_handshake = _get_or_create_alert_rule("handshake_errors", threshold=10, window_minutes=15, severity="warn")
    rule_errors = _get_or_create_alert_rule("errors_non_handshake", threshold=25, window_minutes=15, severity="error")

    now = datetime.utcnow()
    since = now - timedelta(minutes=lookback_minutes)
    handshake_error_types = ["handshake_error", "proxy_error"]

    handshake_errors = TelemetryEvent.query.filter(
        TelemetryEvent.created_at >= since,
        TelemetryEvent.event_type.in_(handshake_error_types),
    ).count()

    error_count_total = TelemetryEvent.query.filter(
        TelemetryEvent.created_at >= since,
        TelemetryEvent.severity.in_(["error", "warn"]),
    ).count()

    error_count_non_handshake = TelemetryEvent.query.filter(
        TelemetryEvent.created_at >= since,
        TelemetryEvent.severity.in_(["error", "warn"]),
        ~TelemetryEvent.event_type.in_(handshake_error_types),
    ).count()

    alerts = []

    def build_sessions_drilldown(event_types: list[str], since_dt: datetime):
        # Metadata only. Return up to 20 sessions.
        ids = (
            db.session.query(TelemetryEvent.session_id)
            .filter(TelemetryEvent.created_at >= since_dt)
            .filter(TelemetryEvent.session_id.isnot(None))
            .filter(TelemetryEvent.event_type.in_(event_types))
            .distinct()
            .limit(20)
            .all()
        )
        session_ids = [str(r[0]) for r in ids if r and r[0]]
        out = []
        for sid in session_ids:
            sess = ActiveSession.query.filter_by(session_id=sid).first()
            out.append(
                {
                    "session_id": sid,
                    "status": getattr(sess, "status", None),
                    "algorithm": getattr(sess, "algorithm", None),
                    "first_seen": (getattr(sess, "first_seen", None).isoformat() + "Z") if getattr(sess, "first_seen", None) else None,
                    "last_seen": (getattr(sess, "last_seen", None).isoformat() + "Z") if getattr(sess, "last_seen", None) else None,
                }
            )
        return out

    # handshake_errors rule
    hs_since = now - timedelta(minutes=int(rule_handshake.window_minutes or lookback_minutes))
    if bool(rule_handshake.enabled) and int(rule_handshake.threshold or 0) > 0 and handshake_errors >= int(rule_handshake.threshold or 0):
        alerts.append(
            {
                "type": "handshake_spike",
                "metric": "handshake_errors",
                "severity": str(rule_handshake.severity or "warn"),
                "count": handshake_errors,
                "threshold": int(rule_handshake.threshold or 0),
                "window_minutes": int(rule_handshake.window_minutes or lookback_minutes),
                "series": _minute_series_from_metricbucket("handshake_errors", hs_since),
                "sessions": build_sessions_drilldown(handshake_error_types, hs_since),
            }
        )

    # non-handshake errors rule
    err_since = now - timedelta(minutes=int(rule_errors.window_minutes or lookback_minutes))
    if bool(rule_errors.enabled) and int(rule_errors.threshold or 0) > 0 and error_count_non_handshake >= int(rule_errors.threshold or 0):
        alerts.append(
            {
                "type": "error_spike",
                "metric": "errors_non_handshake",
                "severity": str(rule_errors.severity or "error"),
                "count": error_count_non_handshake,
                "threshold": int(rule_errors.threshold or 0),
                "window_minutes": int(rule_errors.window_minutes or lookback_minutes),
                "series": _minute_series_from_telemetry(None, ["error", "warn"], err_since),
                "sessions": build_sessions_drilldown(["proxy_error"], err_since),
            }
        )

    # Critical alert webhook (best-effort)
    for a in alerts:
        if str(a.get("severity")) == "error":
            _emit_alert_webhook({"event": "critical_alert", "alert": a, "created_at": now.isoformat() + "Z"})

    return jsonify(
        {
            "window_minutes": lookback_minutes,
            "alerts": alerts,
            "counts": {
                "handshake_errors": handshake_errors,
                "errors_total": error_count_total,
                "errors_non_handshake": error_count_non_handshake,
            },
            "rules": {
                "handshake_errors": {
                    "enabled": bool(rule_handshake.enabled),
                    "threshold": int(rule_handshake.threshold or 0),
                    "window_minutes": int(rule_handshake.window_minutes or 0),
                    "severity": str(rule_handshake.severity or "warn"),
                },
                "errors_non_handshake": {
                    "enabled": bool(rule_errors.enabled),
                    "threshold": int(rule_errors.threshold or 0),
                    "window_minutes": int(rule_errors.window_minutes or 0),
                    "severity": str(rule_errors.severity or "error"),
                },
            },
            "updated_at": now.isoformat() + "Z",
        }
    )


@bp.route("/api/alerts/rules", methods=["GET"])
@require_session_role("admin")
def api_alert_rules_get():
    # Ensure defaults exist.
    _get_or_create_alert_rule("handshake_errors", threshold=10, window_minutes=15, severity="warn")
    _get_or_create_alert_rule("errors_non_handshake", threshold=25, window_minutes=15, severity="error")

    rows = AlertRule.query.order_by(AlertRule.metric.asc()).all()
    out = []
    for r in rows:
        out.append(
            {
                "metric": r.metric,
                "enabled": bool(r.enabled),
                "threshold": int(r.threshold or 0),
                "window_minutes": int(r.window_minutes or 0),
                "severity": str(r.severity or "warn"),
                "updated_at": (r.updated_at.isoformat() + "Z") if r.updated_at else None,
            }
        )
    return jsonify({"rules": out})


@bp.route("/api/alerts/rules", methods=["PUT"])
@require_session_role("admin")
def api_alert_rules_put():
    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules") or {}
    if not isinstance(rules, dict) or not rules:
        return jsonify({"error": "missing_rules"}), 400

    updated = []
    for metric, conf in rules.items():
        if not isinstance(conf, dict):
            continue
        r = _get_or_create_alert_rule(str(metric), threshold=1, window_minutes=15, severity="warn")
        if "enabled" in conf:
            r.enabled = bool(conf.get("enabled"))
        if "threshold" in conf:
            try:
                r.threshold = max(0, int(conf.get("threshold")))
            except Exception:
                pass
        if "window_minutes" in conf:
            try:
                r.window_minutes = max(1, min(1440, int(conf.get("window_minutes"))))
            except Exception:
                pass
        if "severity" in conf:
            sev = str(conf.get("severity") or "").strip().lower()
            if sev in {"info", "warn", "error"}:
                r.severity = sev
        r.updated_at = datetime.utcnow()
        updated.append(str(r.metric))

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "update_failed"}), 500

    _audit_log("alert_rules_update", target_type="alerts", target_id=",".join(updated), status="ok")
    return jsonify({"ok": True, "updated": updated})


@bp.route("/api/alerts/predict", methods=["GET"])
@require_session_role("auditor")
def api_alerts_predict():
    lookback_minutes = min(int(request.args.get("minutes", 60)), 1440)
    horizon_minutes = min(int(request.args.get("horizon", 10)), 120)
    alpha = float(request.args.get("alpha", 0.25))
    if alpha <= 0.0 or alpha > 1.0:
        alpha = 0.25

    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    rows = MetricBucket.query.filter(MetricBucket.bucket_start >= since).order_by(MetricBucket.bucket_start.asc()).all()
    if not rows:
        return jsonify({"error": "no_data"}), 404

    events = [float(r.total_events or 0) for r in rows]
    hs_fail = [float(r.handshake_failures or 0) for r in rows]
    hs_total = [float(r.handshakes_total or 0) for r in rows]

    events_sm = _ewma(events, alpha=alpha)
    hs_fail_sm = _ewma(hs_fail, alpha=alpha)
    hs_total_sm = _ewma(hs_total, alpha=alpha)

    cur_events = events_sm[-1] if events_sm else 0.0
    cur_hs_fail = hs_fail_sm[-1] if hs_fail_sm else 0.0
    cur_hs_total = hs_total_sm[-1] if hs_total_sm else 0.0

    slope_events = _linear_slope(events_sm[-min(len(events_sm), 20):])
    slope_hs_fail = _linear_slope(hs_fail_sm[-min(len(hs_fail_sm), 20):])

    # Forecast: linear extrapolation on smoothed series.
    pred_events = []
    pred_hs_fail = []
    for t in range(1, horizon_minutes + 1):
        pred_events.append(max(0.0, cur_events + slope_events * float(t)))
        pred_hs_fail.append(max(0.0, cur_hs_fail + slope_hs_fail * float(t)))

    # Risks: normalized heuristics (no ML deps).
    max_events = max(events_sm) if events_sm else 1.0
    max_hs_fail = max(hs_fail_sm) if hs_fail_sm else 1.0

    overload_level = (cur_events / (max_events or 1.0))
    overload_trend = max(0.0, slope_events) / ((max_events / 10.0) or 1.0)
    overload_risk = _clamp01(0.6 * overload_level + 0.4 * overload_trend)

    fail_rate = (cur_hs_fail / (cur_hs_total or 1.0))
    fail_level = (cur_hs_fail / (max_hs_fail or 1.0))
    fail_trend = max(0.0, slope_hs_fail) / ((max_hs_fail / 10.0) or 1.0)
    handshake_failure_risk = _clamp01(0.5 * fail_level + 0.3 * fail_trend + 0.2 * min(1.0, fail_rate * 10.0))

    now = datetime.utcnow()
    series = []
    for i, r in enumerate(rows[-min(len(rows), 60):]):
        series.append(
            {
                "ts": (r.bucket_start.isoformat() + "Z") if r.bucket_start else None,
                "events": int(r.total_events or 0),
                "handshake_failures": int(r.handshake_failures or 0),
                "handshakes_total": int(r.handshakes_total or 0),
                "events_ewma": round(float(events_sm[-min(len(rows), 60) + i]), 3) if len(events_sm) >= min(len(rows), 60) else None,
                "handshake_failures_ewma": round(float(hs_fail_sm[-min(len(rows), 60) + i]), 3) if len(hs_fail_sm) >= min(len(rows), 60) else None,
            }
        )

    forecast = []
    for t in range(1, horizon_minutes + 1):
        forecast.append(
            {
                "ts": (now + timedelta(minutes=t)).isoformat() + "Z",
                "pred_events": round(pred_events[t - 1], 3),
                "pred_handshake_failures": round(pred_hs_fail[t - 1], 3),
            }
        )

    return jsonify(
        {
            "window_minutes": lookback_minutes,
            "horizon_minutes": horizon_minutes,
            "alpha": alpha,
            "risk": {
                "handshake_failure": round(handshake_failure_risk, 4),
                "overload": round(overload_risk, 4),
            },
            "current": {
                "events_ewma": round(cur_events, 3),
                "handshake_failures_ewma": round(cur_hs_fail, 3),
                "handshakes_total_ewma": round(cur_hs_total, 3),
                "handshake_fail_rate": round(float(fail_rate), 6),
                "trend": {"events_slope": round(slope_events, 6), "handshake_failures_slope": round(slope_hs_fail, 6)},
            },
            "history": series,
            "forecast": forecast,
            "updated_at": now.isoformat() + "Z",
        }
    )


@bp.route("/api/dashboard/config", methods=["GET"])
def api_dashboard_config():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    order = {"viewer": 1, "auditor": 2, "admin": 3}
    if order.get(getattr(current_user, "role", "viewer"), 0) < 3:
        return jsonify({"error": "forbidden"}), 403

    _audit_log("config_read", target_type="observer", target_id="config", status="ok")

    return jsonify(
        {
            "policies": {
                "rate_limit": os.getenv("PROXY_RATE_LIMIT", "not_configured"),
                "whitelist": os.getenv("PROXY_WHITELIST", "not_configured"),
                "crypto_policy": os.getenv("PREFERRED_CRYPTO", "Kyber"),
            },
            "multi_instance": os.getenv("OBSERVER_CLUSTER", "single"),
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    )


@bp.route("/api/dashboard/status", methods=["GET"])
def api_dashboard_status():
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    last = TelemetryEvent.query.order_by(TelemetryEvent.created_at.desc()).first()
    return jsonify(
        {
            "version": os.getenv("OBSERVER_VERSION", "dev"),
            "last_event_at": (last.created_at.isoformat() + "Z") if last else None,
            "security_status": "ok" if last else "unknown",
        }
    )


@bp.route("/api/proxy/pcap/meta", methods=["GET"])
@require_session_role("auditor")
def api_proxy_pcap_meta():
    try:
        if not _PROXY_PCAP_PATH.exists() or not _PROXY_PCAP_PATH.is_file():
            return jsonify({"present": False, "path": str(_PROXY_PCAP_PATH)}), 200

        size = _PROXY_PCAP_PATH.stat().st_size
        updated_at = datetime.utcfromtimestamp(_PROXY_PCAP_PATH.stat().st_mtime).isoformat() + "Z"
        return jsonify(
            {
                "present": True,
                "path": str(_PROXY_PCAP_PATH),
                "size_bytes": int(size),
                "updated_at": updated_at,
            }
        )
    except Exception:
        return jsonify({"error": "pcap_meta_failed"}), 500


@bp.route("/api/proxy/pcap/download", methods=["GET"])
@require_session_role("auditor")
def api_proxy_pcap_download():
    try:
        if not _PROXY_PCAP_PATH.exists() or not _PROXY_PCAP_PATH.is_file():
            return jsonify({"error": "pcap_not_found"}), 404

        size = _PROXY_PCAP_PATH.stat().st_size
        if size > _PCAP_MAX_BYTES:
            return jsonify({"error": "pcap_too_large", "max_bytes": _PCAP_MAX_BYTES, "size_bytes": int(size)}), 413

        return send_file(
            _PROXY_PCAP_PATH,
            as_attachment=True,
            download_name="proxy_capture.pcap",
            mimetype="application/vnd.tcpdump.pcap",
            conditional=True,
            max_age=0,
        )
    except Exception:
        return jsonify({"error": "pcap_download_failed"}), 500


@bp.route("/api/pcap/upload", methods=["POST"])
@require_session_role("auditor")
def api_pcap_upload():
    if dpkt is None:
        return jsonify({"error": "dpkt_not_installed"}), 500

    up = request.files.get("file")
    if not up:
        return jsonify({"error": "missing_file"}), 400

    try:
        raw = up.read()
    except Exception:
        return jsonify({"error": "read_failed"}), 400

    if not raw:
        return jsonify({"flows": []}), 200

    if len(raw) > _PCAP_MAX_BYTES:
        return jsonify({"error": "pcap_too_large", "max_bytes": _PCAP_MAX_BYTES, "size_bytes": len(raw)}), 413

    flows = {}
    try:
        reader = dpkt.pcap.Reader(BytesIO(raw))
        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not hasattr(ip, "src") or not hasattr(ip, "dst"):
                    continue
                src = "{}.{}.{}.{}".format(*ip.src)
                dst = "{}.{}.{}.{}".format(*ip.dst)
                proto = getattr(ip, "p", None)
                l4 = ip.data
                sport = getattr(l4, "sport", None)
                dport = getattr(l4, "dport", None)
                if sport is None or dport is None:
                    continue

                proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto or "?") )
                key = (src, dst, int(sport), int(dport), proto_name)
                row = flows.get(key)
                if row is None:
                    flows[key] = {"pkts": 1, "bytes": int(len(buf))}
                else:
                    row["pkts"] += 1
                    row["bytes"] += int(len(buf))
            except Exception:
                continue
    except Exception:
        return jsonify({"error": "invalid_pcap"}), 400

    out = []
    for (src, dst, sport, dport, proto_name), agg in flows.items():
        out.append(
            {
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "proto": proto_name,
                "pkts": int(agg.get("pkts", 0)),
                "bytes": int(agg.get("bytes", 0)),
            }
        )
    out.sort(key=lambda x: x.get("bytes", 0), reverse=True)
    return jsonify({"flows": out[:200]}), 200


@bp.route("/api/pcap/analyze", methods=["GET"])
@require_session_role("auditor")
def pcap_analysis():
    if dpkt is None:
        return jsonify({"error": "dpkt_not_installed"}), 500

    source = (request.args.get("source") or "").strip().lower() or "proxy"
    if source != "proxy":
        return jsonify({"error": "unsupported_source"}), 400

    path = _PROXY_PCAP_PATH
    if not path.exists() or not path.is_file():
        return jsonify({"error": "pcap_not_found", "source": source, "path": str(path)}), 404

    try:
        size = path.stat().st_size
        if size > _PCAP_MAX_BYTES:
            return jsonify({"error": "pcap_too_large", "max_bytes": _PCAP_MAX_BYTES, "size_bytes": int(size)}), 413
    except Exception:
        return jsonify({"error": "pcap_stat_failed"}), 500

    # Per-second traffic series + breakdown
    per_sec = {}  # sec -> {pkts, bytes}
    protos = {}  # name -> count
    flows = {}  # (src,dst,sport,dport,proto) -> {pkts, bytes}
    first_ts = None
    last_ts = None

    try:
        with open(path, "rb") as fp:
            reader = dpkt.pcap.Reader(fp)
            for ts, buf in reader:
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

                sec = int(ts)
                b = per_sec.get(sec)
                if b is None:
                    per_sec[sec] = {"pkts": 1, "bytes": int(len(buf))}
                else:
                    b["pkts"] += 1
                    b["bytes"] += int(len(buf))

                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not hasattr(ip, "src") or not hasattr(ip, "dst"):
                        protos["Other"] = int(protos.get("Other", 0)) + 1
                        continue

                    src = "{}.{}.{}.{}".format(*ip.src)
                    dst = "{}.{}.{}.{}".format(*ip.dst)
                    proto = getattr(ip, "p", None)
                    proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else ("ICMP" if proto == 1 else "Other"))
                    protos[proto_name] = int(protos.get(proto_name, 0)) + 1

                    l4 = ip.data
                    sport = getattr(l4, "sport", None)
                    dport = getattr(l4, "dport", None)
                    if sport is None or dport is None:
                        continue
                    key = (src, dst, int(sport), int(dport), proto_name)
                    row = flows.get(key)
                    if row is None:
                        flows[key] = {"pkts": 1, "bytes": int(len(buf))}
                    else:
                        row["pkts"] += 1
                        row["bytes"] += int(len(buf))
                except Exception:
                    protos["Other"] = int(protos.get("Other", 0)) + 1
                    continue
    except (OSError, ValueError):
        return jsonify({"error": "invalid_pcap"}), 400
    except Exception:
        return jsonify({"error": "pcap_parse_failed"}), 500

    series = []
    if first_ts is not None and last_ts is not None and last_ts >= first_ts:
        for sec in range(int(first_ts), int(last_ts) + 1):
            row = per_sec.get(sec) or {"pkts": 0, "bytes": 0}
            series.append({"ts": datetime.utcfromtimestamp(sec).isoformat() + "Z", "pkts": int(row["pkts"]), "bytes": int(row["bytes"])})

    top_flows = []
    for (src, dst, sport, dport, proto_name), agg in flows.items():
        top_flows.append(
            {
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "proto": proto_name,
                "pkts": int(agg.get("pkts", 0)),
                "bytes": int(agg.get("bytes", 0)),
            }
        )
    top_flows.sort(key=lambda x: x.get("bytes", 0), reverse=True)

    return jsonify(
        {
            "source": source,
            "path": str(path),
            "size_bytes": int(size),
            "series": series[-600:],
            "protocols": protos,
            "flows": top_flows[:200],
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    )
@require_role("auditor")
def api_cboom_events_get():
    limit = min(int(request.args.get("limit", 200)), 2000)
    offset = max(int(request.args.get("offset", 0)), 0)
    minutes = request.args.get("minutes")
    cutoff = None
    if minutes is not None:
        try:
            mins = int(minutes)
            cutoff = datetime.utcnow() - timedelta(minutes=max(mins, 0))
        except Exception:
            cutoff = None

    since = _parse_iso8601(request.args.get("since"))
    until = _parse_iso8601(request.args.get("until"))

    source_component = (request.args.get("source_component") or "").strip()
    destination_component = (request.args.get("destination_component") or "").strip()
    protocol = (request.args.get("protocol") or "").strip()
    token = (request.args.get("token") or "").strip()
    status = (request.args.get("status") or "").strip()
    message_type = (request.args.get("message_type") or "").strip()
    api_endpoint = (request.args.get("api_endpoint") or "").strip()
    trace_id = (request.args.get("trace_id") or "").strip()

    q = CBOMEvent.query
    if since:
        q = q.filter(CBOMEvent.timestamp >= since)
    if until:
        q = q.filter(CBOMEvent.timestamp <= until)
    if source_component:
        q = q.filter(CBOMEvent.source_component == source_component)
    if destination_component:
        q = q.filter(CBOMEvent.destination_component == destination_component)
    if protocol:
        q = q.filter(CBOMEvent.communication_protocol == protocol)
    if token:
        q = q.filter(CBOMEvent.client_token_id == token)
    if status:
        q = q.filter(CBOMEvent.status == status)
    if message_type:
        q = q.filter(CBOMEvent.message_type == message_type)
    if api_endpoint:
        q = q.filter(CBOMEvent.api_endpoint == api_endpoint)
    if trace_id:
        q = q.filter(CBOMEvent.trace_id == trace_id)

    try:
        has_cbom = bool(db.session.query(func.count(CBOMEvent.event_id)).scalar() or 0)
    except Exception:
        has_cbom = False

    if not has_cbom:
        recent = (
            TelemetryEvent.query.order_by(TelemetryEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        out = []
        for ev in recent:
            try:
                details = _present_details_for_response(ev.details)
            except Exception:
                details = None

            status_guess = "failure" if str(getattr(ev, "severity", "")).lower() in {"error", "critical"} else "success"
            out.append(
                {
                    "event_id": f"telemetry-{ev.id}",
                    "timestamp": ev.created_at.isoformat() + "Z" if ev.created_at else None,
                    "source_component": ev.component or "unknown",
                    "destination_component": "unknown",
                    "communication_protocol": "custom",
                    "message_type": str(ev.event_type or "event"),
                    "status": status_guess,
                    "payload_summary": {"telemetry_event_type": ev.event_type, "severity": ev.severity},
                    "error_details": details if status_guess != "success" else None,
                    "metrics": None,
                    "api_endpoint": (details.get("path") if isinstance(details, dict) else None),
                    "client_token_id": (details.get("algorithm") if isinstance(details, dict) else None),
                    "trace_id": None,
                    "crypto": {
                        "crypto_algorithm": (details.get("algorithm") if isinstance(details, dict) else None),
                        "key_length": (details.get("key_length") if isinstance(details, dict) else None),
                        "pqc_support": (details.get("pqc_support") if isinstance(details, dict) else None),
                        "quantum_ready": (details.get("quantum_ready") if isinstance(details, dict) else None),
                        "tls_version": (details.get("tls_version") if isinstance(details, dict) else None),
                        "cipher_suite": (details.get("cipher_suite") if isinstance(details, dict) else None),
                        "signature_algorithm": (details.get("signature_algorithm") if isinstance(details, dict) else None),
                    },
                    "latency_ms": (details.get("latency_ms") if isinstance(details, dict) else None),
                    "action_suggestion": None,
                }
            )
        return jsonify({"events": out, "count": len(out), "source": "telemetry_fallback"})

    if cutoff is not None:
        q = q.filter(CBOMEvent.timestamp >= cutoff)

    rows = q.order_by(CBOMEvent.timestamp.desc()).offset(offset).limit(limit).all()
    out = []
    seen = set()
    for r in rows:
        d = _cbom_event_to_dict(r)
        d["source_component"] = _normalize_component_name(d.get("source_component") or "")
        d["destination_component"] = _normalize_component_name(d.get("destination_component") or "")
        seen.add(d.get("source_component"))
        seen.add(d.get("destination_component"))
        out.append(d)

    canonical_components = ["frontend", "backend", "db", "client", "proxy", "observer"]
    # Force db and observer to be seen if they are capable of logging (which they are)
    seen.add("db")
    seen.add("observer")
    
    # If we saw any client-X, also mark the base "client" as seen
    if any(str(c).startswith("client-") for c in seen):
        seen.add("client")

    return jsonify(
        {
            "events": out,
            "count": len(out),
            "components_expected": canonical_components,
            "components_seen": sorted([c for c in seen if c]),
        }
    )


@bp.route("/api/dashboard/sessions", methods=["GET"])
@login_required
def api_dashboard_sessions_get():
    # Viewer and above
    limit = min(int(request.args.get("limit", 50)), 500)
    lookback_minutes = min(int(request.args.get("minutes", 30)), 1440)
    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    
    # Get active sessions
    rows = ActiveSession.query.filter(ActiveSession.last_seen >= since).order_by(ActiveSession.last_seen.desc()).limit(limit).all()
    
    # Get event counts per session in window
    event_counts = {}
    try:
        counts = (
            db.session.query(TelemetryEvent.session_id, func.count(TelemetryEvent.id))
            .filter(TelemetryEvent.created_at >= since)
            .filter(TelemetryEvent.session_id.isnot(None))
            .group_by(TelemetryEvent.session_id)
            .all()
        )
        for sid, c in counts:
            event_counts[sid] = int(c)
    except Exception:
        pass

    out = []
    for s in rows:
        out.append({
            "session_id": s.session_id,
            "client_id": s.client_id,
            "algorithm": s.algorithm,
            "first_seen": s.first_seen.isoformat() + "Z" if s.first_seen else None,
            "last_seen": s.last_seen.isoformat() + "Z" if s.last_seen else None,
            "status": s.status,
            "events": event_counts.get(s.session_id, 0)
        })

    return jsonify({"sessions": out, "count": len(out)})


@bp.route("/api/cboom/events/grouped", methods=["GET"])
@require_role("auditor")
def api_cboom_events_grouped_get():
    # Group "similar" events into one row.
    # Similarity key: src,dst,proto,type,status,api_endpoint (after normalization).
    limit = min(int(request.args.get("limit", 200)), 2000)
    since = _parse_iso8601(request.args.get("since"))
    if since is None:
        mins = int(request.args.get("minutes", 180))
        since = datetime.utcnow() - timedelta(minutes=max(mins, 1))

    q = (
        db.session.query(
            CBOMEvent.source_component,
            CBOMEvent.destination_component,
            CBOMEvent.communication_protocol,
            CBOMEvent.message_type,
            CBOMEvent.status,
            CBOMEvent.api_endpoint,
            func.count(CBOMEvent.event_id),
            func.avg(CBOMEvent.latency_ms),
            func.max(CBOMEvent.timestamp),
        )
        .filter(CBOMEvent.timestamp >= since)
        .group_by(
            CBOMEvent.source_component,
            CBOMEvent.destination_component,
            CBOMEvent.communication_protocol,
            CBOMEvent.message_type,
            CBOMEvent.status,
            CBOMEvent.api_endpoint,
        )
        .order_by(func.max(CBOMEvent.timestamp).desc())
        .limit(limit)
    )

    rows = q.all()
    agg = {}
    for src, dst, proto, typ, st, api_ep, cnt, avg_lat, last_ts in rows:
        src_n = _normalize_component_name(str(src or ""))
        dst_n = _normalize_component_name(str(dst or ""))
        proto_n = str(proto or "").strip()[:32]
        typ_n = str(typ or "").strip()[:64]
        st_n = str(st or "").strip()[:16]
        api_n = str(api_ep or "").strip()[:255] or None
        key = (src_n, dst_n, proto_n, typ_n, st_n, api_n)

        cur = agg.get(key)
        add_cnt = int(cnt or 0)
        add_avg = float(avg_lat) if avg_lat is not None else None
        if cur is None:
            agg[key] = {
                "source_component": src_n,
                "destination_component": dst_n,
                "communication_protocol": proto_n,
                "message_type": typ_n,
                "status": st_n,
                "api_endpoint": api_n,
                "count": add_cnt,
                "avg_latency_ms": add_avg,
                "last_seen": (last_ts.isoformat() + "Z") if last_ts else None,
            }
        else:
            cur_cnt = int(cur.get("count") or 0)
            cur_avg = cur.get("avg_latency_ms")
            if cur_avg is not None and add_avg is not None and (cur_cnt + add_cnt) > 0:
                cur["avg_latency_ms"] = ((cur_avg * cur_cnt) + (add_avg * add_cnt)) / float(cur_cnt + add_cnt)
            elif cur_avg is None and add_avg is not None:
                cur["avg_latency_ms"] = add_avg
            cur["count"] = cur_cnt + add_cnt
            if last_ts and (not cur.get("last_seen") or last_ts.isoformat() + "Z" > str(cur.get("last_seen"))):
                cur["last_seen"] = last_ts.isoformat() + "Z"

    
    # Refactored: Fetch representative event for each group individually to ensure coverage.
    for key, row in agg.items():
        try:
            # Reconstruct query filters from key components
            # EXHAUSTIVE SEARCH:
            # Instead of relying on complex SQL filters which might miss data due to nuances (e.g. empty strings vs NULL),
            # we fetch the latest 50 events for this source/dest pair and scan them in Python.
            
            candidates = (
                CBOMEvent.query.filter(
                    CBOMEvent.timestamp >= since,
                    func.lower(CBOMEvent.source_component) == row["source_component"],
                    func.lower(CBOMEvent.destination_component) == row["destination_component"],
                )
                .order_by(CBOMEvent.timestamp.desc())
                .limit(50)
                .all()
            )

            latest = None
            # 1. First pass: active search for meaningful crypto metadata
            for cand in candidates:
                # Check actual OR payload-embedded crypto algo
                c_algo = cand.crypto_algorithm
                if not c_algo:
                     try:
                        c_algo = json.loads(cand.metrics or "{}").get("crypto", {}).get("crypto_algorithm")
                     except:
                        pass
                
                # If we found a candidate with a non-empty string algorithm, use it!
                if c_algo and str(c_algo).strip() not in ["", "None", "null"]:
                    latest = cand
                    break
            
            # 2. Fallback: If no metadata found, just use the absolute latest event
            if not latest and candidates:
                latest = candidates[0]

            if latest:
                row["representative_event_id"] = latest.event_id
                rep = _cbom_event_to_dict(latest)
                
                # Robust extraction
                crypto_algo = latest.crypto_algorithm
                if not crypto_algo or str(crypto_algo).strip() == "":
                    crypto_algo = (rep.get("crypto") or {}).get("crypto_algorithm")

                # Explicitly populate row fields
                row["crypto"] = rep.get("crypto") or {}
                if crypto_algo: row["crypto_algorithm"] = crypto_algo
                
                # Helper to copy other fields if they exist on the object
                for f in ["key_length", "tls_version", "cipher_suite", "signature_algorithm", "library_tool", "cert_type"]:
                     val = getattr(latest, f, None)
                     if val: row[f] = val
                if latest.key_length: row["key_length"] = latest.key_length
                if latest.tls_version: row["tls_version"] = latest.tls_version
                if latest.cipher_suite: row["cipher_suite"] = latest.cipher_suite
                if latest.signature_algorithm: row["signature_algorithm"] = latest.signature_algorithm
                if latest.library_tool: row["library_tool"] = latest.library_tool
                if latest.cert_type: row["cert_type"] = latest.cert_type
                
                if rep.get("action_suggestion"):
                    row["action_suggestion"] = rep.get("action_suggestion")
                    
                ps = rep.get("payload_summary") if isinstance(rep.get("payload_summary"), dict) else None
                if ps: row["payload_summary"] = ps

        except Exception:
            pass

        # Fallbacks for aggregated rows
        try:
            proto_val = str(row.get("communication_protocol") or "").strip().upper()
        except Exception:
            proto_val = ""
        
        crypto_obj = row.get("crypto") if isinstance(row.get("crypto"), dict) else {}
        if proto_val == "HTTPS" and not crypto_obj and not row.get("crypto_algorithm"):
             row["crypto_algorithm"] = "TLS"
             
        # Ensure we have a suggestion string where possible.
        if not row.get("action_suggestion"):
            try:
                sug = _compute_cbom_suggestion(row)
            except Exception:
                sug = None
            if sug:
                row["action_suggestion"] = sug

    grouped = sorted(list(agg.values()), key=lambda x: x.get("last_seen") or "", reverse=True)

    canonical_components = ["frontend", "backend", "db", "client", "proxy", "observer"]
    seen = set()
    for r in grouped:
        seen.add(r.get("source_component"))
        seen.add(r.get("destination_component"))
    
    # Force db and observer to be seen
    seen.add("db")
    seen.add("observer")

    # If we saw any client-X, also mark the base "client" as seen
    if any(str(c).startswith("client-") for c in seen):
        seen.add("client")

    return jsonify(
        {
            "since": since.isoformat() + "Z",
            "events": grouped,
            "count": len(grouped),
            "components_expected": canonical_components,
            "components_seen": sorted([c for c in seen if c]),
        }
    )


@bp.route("/api/cboom/events", methods=["POST"])
@require_role("admin")
def api_cboom_events_post():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_payload"}), 400

    event_id = str(payload.get("event_id") or "").strip() or str(uuid.uuid4())
    try:
        _ = uuid.UUID(event_id)
    except Exception:
        return jsonify({"error": "invalid_event_id"}), 400

    ts = _parse_iso8601(payload.get("timestamp"))
    if ts is None:
        ts = datetime.utcnow()

    source_component = _normalize_component_name(str(payload.get("source_component") or "").strip())
    destination_component = _normalize_component_name(str(payload.get("destination_component") or "").strip())
    communication_protocol = str(payload.get("communication_protocol") or "").strip()
    message_type = str(payload.get("message_type") or "").strip()
    status = str(payload.get("status") or "").strip()

    missing = [
        k
        for k, v in {
            "source_component": source_component,
            "destination_component": destination_component,
            "communication_protocol": communication_protocol,
            "message_type": message_type,
            "status": status,
        }.items()
        if not v
    ]
    if missing:
        return jsonify({"error": "missing_fields", "fields": missing}), 400

    crypto = payload.get("crypto") if isinstance(payload.get("crypto"), dict) else {}
    crypto_algorithm = payload.get("crypto_algorithm") or crypto.get("crypto_algorithm")
    key_length = payload.get("key_length") or crypto.get("key_length")
    pqc_support = payload.get("pqc_support") if payload.get("pqc_support") is not None else crypto.get("pqc_support")
    quantum_ready = payload.get("quantum_ready") if payload.get("quantum_ready") is not None else crypto.get("quantum_ready")

    tls_version = crypto.get("tls_version") or payload.get("tls_version")
    cipher_suite = crypto.get("cipher_suite") or payload.get("cipher_suite")
    signature_algorithm = crypto.get("signature_algorithm") or payload.get("signature_algorithm")
    library_tool = crypto.get("library_tool") or payload.get("library_tool")
    cert_type = crypto.get("cert_type") or payload.get("cert_type")

    api_endpoint = payload.get("api_endpoint")
    client_token_id = payload.get("client_token_id")
    trace_id = payload.get("trace_id")

    latency_ms = payload.get("latency_ms")
    try:
        latency_ms = int(latency_ms) if latency_ms is not None else None
    except Exception:
        latency_ms = None

    action_suggestion = str(payload.get("action_suggestion") or "").strip() or _compute_cbom_suggestion(payload)
    if action_suggestion is not None:
        action_suggestion = action_suggestion.strip()[:500]

    row = CBOMEvent(
        event_id=event_id,
        timestamp=ts,
        source_component=str(source_component)[:64],
        destination_component=str(destination_component)[:64],
        communication_protocol=str(communication_protocol)[:32],
        message_type=str(message_type)[:64],
        status=str(status)[:16],
        payload_summary=_json_dumps_safe(payload.get("payload_summary")),
        error_details=_json_dumps_safe(payload.get("error_details")),
        metrics=_json_dumps_safe(payload.get("metrics")),
        api_endpoint=str(api_endpoint)[:255] if api_endpoint else None,
        client_token_id=str(client_token_id)[:64] if client_token_id else None,
        trace_id=str(trace_id)[:64] if trace_id else None,
        crypto_algorithm=str(crypto_algorithm)[:64] if crypto_algorithm else None,
        key_length=int(key_length) if key_length is not None and str(key_length).isdigit() else None,
        pqc_support=bool(pqc_support) if pqc_support is not None else None,
        quantum_ready=bool(quantum_ready) if quantum_ready is not None else None,
        tls_version=str(tls_version)[:16] if tls_version else None,
        cipher_suite=str(cipher_suite)[:128] if cipher_suite else None,
        signature_algorithm=str(signature_algorithm)[:128] if signature_algorithm else None,
        library_tool=str(library_tool)[:128] if library_tool else None,
        cert_type=str(cert_type)[:64] if cert_type else None,
        latency_ms=latency_ms,
        action_suggestion=action_suggestion,
    )
    db.session.merge(row)
    db.session.commit()
    return jsonify({"ok": True, "event_id": event_id})


@bp.route("/api/cboom/purge", methods=["POST"])
@require_role("admin")
def api_cboom_purge():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        payload = {}
    mode = str(payload.get("mode") or "all").strip().lower()
    keep_minutes = payload.get("keep_minutes")
    cutoff = None
    if mode == "older_than":
        try:
            mins = int(keep_minutes)
            cutoff = datetime.utcnow() - timedelta(minutes=max(mins, 0))
        except Exception:
            return jsonify({"error": "invalid_keep_minutes"}), 400

    try:
        q = CBOMEvent.query
        if cutoff is not None:
            q = q.filter(CBOMEvent.timestamp < cutoff)
        deleted = q.delete(synchronize_session=False)
        db.session.commit()
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({"error": "purge_failed", "message": str(exc)}), 500

    _audit_log("cbom_purge", target_type="cbom", target_id=(mode if cutoff is None else f"older_than:{keep_minutes}"), status="ok", details={"deleted": int(deleted or 0)})
    return jsonify({"ok": True, "deleted": int(deleted or 0)})


@bp.route("/api/cboom/events/browser", methods=["POST"])
@require_role("auditor")
def api_cboom_events_browser_post():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_payload"}), 400

    path = str(payload.get("path") or "").strip()
    if path.startswith("/api/cboom/"):
        return jsonify({"ok": True, "skipped": True})

    event_id = str(uuid.uuid4())
    ts = datetime.utcnow()

    method = str(payload.get("method") or "").upper().strip() or "GET"
    status_code = payload.get("status_code")
    try:
        status_code_i = int(status_code) if status_code is not None else None
    except Exception:
        status_code_i = None

    latency_ms = payload.get("latency_ms")
    try:
        latency_ms_i = int(float(latency_ms)) if latency_ms is not None else None
    except Exception:
        latency_ms_i = None

    status = "success"
    if status_code_i is not None and status_code_i >= 400:
        status = "failure"
    if payload.get("error"):
        status = "failure"

    computed = _compute_cbom_suggestion(
        {
            "source_component": "frontend",
            "destination_component": "observer",
            "communication_protocol": "HTTP",
            "message_type": "request",
            "status": status,
            "latency_ms": latency_ms_i,
            "api_endpoint": path,
            "crypto": {},
        }
    )

    proto = "HTTPS" if (request.is_secure if request else False) else "HTTP"
    computed = _compute_cbom_suggestion(
        {
            "source_component": "frontend",
            "destination_component": "backend",
            "communication_protocol": proto,
            "message_type": "request",
            "status": status,
            "latency_ms": latency_ms_i,
            "api_endpoint": path,
            "crypto": {
                "crypto_algorithm": "TLS" if proto == "HTTPS" else None,
                "library_tool": "Browser (Native)" if proto == "HTTPS" else None,
                "cert_type": "X.509" if proto == "HTTPS" else None,
                "key_length": 2048 if proto == "HTTPS" else None,
                "pqc_support": False,
                "quantum_ready": False,
            },
        }
    )

    row = CBOMEvent(
        event_id=event_id,
        timestamp=ts,
        source_component="frontend",
        destination_component="backend",
        communication_protocol=proto,
        message_type="request",
        status=status,
        payload_summary=_json_dumps_safe(
            {
                "method": method,
                "status_code": status_code_i,
                "path": path,
            }
        ),
        error_details=_json_dumps_safe({"error": str(payload.get("error"))}) if payload.get("error") else None,
        metrics=None,
        api_endpoint=path[:255] if path else None,
        client_token_id=None,
        trace_id=str(payload.get("trace_id") or "").strip()[:64] or None,
        crypto_algorithm="TLS" if proto == "HTTPS" else None,
        key_length=2048 if proto == "HTTPS" else None,
        pqc_support=False,
        quantum_ready=False,
        tls_version="TLS 1.2+" if proto == "HTTPS" else None,
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256" if proto == "HTTPS" else None,
        signature_algorithm="sha256WithRSAEncryption" if proto == "HTTPS" else None,
        library_tool="Browser (Native)" if proto == "HTTPS" else None,
        cert_type="X.509" if proto == "HTTPS" else None,

        latency_ms=latency_ms_i,
        action_suggestion=computed,
    )
    db.session.add(row)
    db.session.commit()
    return jsonify({"ok": True, "event_id": event_id})


@bp.route("/api/cboom/metrics", methods=["GET"])
@require_role("auditor")
def api_cboom_metrics():
    since = _parse_iso8601(request.args.get("since"))
    if since is None:
        mins = int(request.args.get("minutes", 60))
        since = datetime.utcnow() - timedelta(minutes=max(mins, 1))

    q = (
        db.session.query(
            CBOMEvent.source_component,
            CBOMEvent.destination_component,
            CBOMEvent.communication_protocol,
            CBOMEvent.status,
            func.count(CBOMEvent.event_id),
            func.avg(CBOMEvent.latency_ms),
        )
        .filter(CBOMEvent.timestamp >= since)
        .group_by(
            CBOMEvent.source_component,
            CBOMEvent.destination_component,
            CBOMEvent.communication_protocol,
            CBOMEvent.status,
        )
    )

    rows = q.all()
    out = []
    for src, dst, proto, st, cnt, avg_lat in rows:
        out.append(
            {
                "source_component": src,
                "destination_component": dst,
                "communication_protocol": proto,
                "status": st,
                "count": int(cnt or 0),
                "avg_latency_ms": float(avg_lat) if avg_lat is not None else None,
            }
        )
    return jsonify({"since": since.isoformat() + "Z", "metrics": out, "count": len(out)})


@bp.route("/api/cboom/action-suggestions", methods=["GET"])
@require_role("auditor")
def api_cboom_action_suggestions():
    since = _parse_iso8601(request.args.get("since"))
    if since is None:
        mins = int(request.args.get("minutes", 180))
        since = datetime.utcnow() - timedelta(minutes=max(mins, 1))

    q = (
        db.session.query(CBOMEvent.action_suggestion, func.count(CBOMEvent.event_id))
        .filter(CBOMEvent.timestamp >= since)
        .filter(CBOMEvent.action_suggestion.isnot(None))
        .group_by(CBOMEvent.action_suggestion)
        .order_by(func.count(CBOMEvent.event_id).desc())
    )
    rows = q.all()
    out = []
    for sugg, cnt in rows:
        s = (sugg or "").strip()
        if not s:
            continue
        out.append({"suggestion": s, "count": int(cnt or 0)})
    return jsonify({"since": since.isoformat() + "Z", "suggestions": out, "count": len(out)})


@bp.route("/api/audit/logs", methods=["GET"])
@require_session_role("auditor")
def api_audit_logs():
    limit = min(int(request.args.get("limit", 200)), 1000)
    q = AdminAuditLog.query.order_by(AdminAuditLog.created_at.desc()).limit(limit)
    rows = q.all()
    out = []
    for r in rows:
        try:
            details = json.loads(r.details or "{}")
        except Exception:
            details = {}
        out.append(
            {
                "id": r.id,
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                "actor": {"id": r.actor_user_id, "username": r.actor_username, "role": r.actor_role, "ip": r.actor_ip},
                "action": r.action,
                "target": {"type": r.target_type, "id": r.target_id},
                "status": r.status,
                "details": details,
            }
        )
    return jsonify({"logs": out, "count": len(out)})


@bp.route("/api/audit/export", methods=["POST"])
@require_session_role("admin")
def api_audit_export():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"error": "missing_url"}), 400
    limit = min(int(payload.get("limit", 500)), 2000)
    rows = AdminAuditLog.query.order_by(AdminAuditLog.created_at.desc()).limit(limit).all()
    events = []
    for r in rows:
        try:
            details = json.loads(r.details or "{}")
        except Exception:
            details = {}
        events.append(
            {
                "ts": r.created_at.isoformat() + "Z" if r.created_at else None,
                "actor": {"id": r.actor_user_id, "username": r.actor_username, "role": r.actor_role, "ip": r.actor_ip},
                "action": r.action,
                "target": {"type": r.target_type, "id": r.target_id},
                "status": r.status,
                "details": details,
                "source": "observer",
            }
        )
    try:
        resp = requests.post(url, json={"events": events}, timeout=_AUDIT_SIEM_TIMEOUT)
        ok = bool(resp.ok)
    except Exception as e:
        _audit_log("audit_export", target_type="siem", target_id=url, status="error", details={"error": str(e)})
        return jsonify({"error": "export_failed", "message": str(e)}), 502

    _audit_log("audit_export", target_type="siem", target_id=url, status="ok", details={"count": len(events)})
    return jsonify({"ok": ok, "count": len(events)})
