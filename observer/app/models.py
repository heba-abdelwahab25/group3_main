from datetime import datetime
from . import db
from flask_login import UserMixin


class TelemetryEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    component = db.Column(db.String(32), index=True, nullable=False)
    event_type = db.Column(db.String(64), index=True, nullable=False)
    session_id = db.Column(db.String(64), index=True, nullable=True)
    client_id = db.Column(db.String(64), index=True, nullable=True)
    severity = db.Column(db.String(16), nullable=False, default="info")
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ActiveSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, index=True, nullable=False)
    algorithm = db.Column(db.String(16), nullable=True)
    client_id = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(16), nullable=False, default="active")
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class MetricBucket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bucket_start = db.Column(db.DateTime, unique=True, index=True, nullable=False)

    total_events = db.Column(db.Integer, nullable=False, default=0)
    by_component = db.Column(db.Text, nullable=True)
    by_type = db.Column(db.Text, nullable=True)

    handshakes_total = db.Column(db.Integer, nullable=False, default=0)
    handshake_failures = db.Column(db.Integer, nullable=False, default=0)
    handshake_algorithms = db.Column(db.Text, nullable=True)

    latency_count = db.Column(db.Integer, nullable=False, default=0)
    latency_sum_ms = db.Column(db.Float, nullable=False, default=0.0)
    latency_min_ms = db.Column(db.Float, nullable=True)
    latency_max_ms = db.Column(db.Float, nullable=True)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class AdminAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    actor_user_id = db.Column(db.Integer, nullable=True, index=True)
    actor_username = db.Column(db.String(64), nullable=True, index=True)
    actor_role = db.Column(db.String(16), nullable=True, index=True)
    actor_ip = db.Column(db.String(64), nullable=True)

    action = db.Column(db.String(64), nullable=False, index=True)
    target_type = db.Column(db.String(32), nullable=True, index=True)
    target_id = db.Column(db.String(128), nullable=True, index=True)
    status = db.Column(db.String(16), nullable=False, default="ok", index=True)
    details = db.Column(db.Text, nullable=True)


class AlertRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    metric = db.Column(db.String(64), unique=True, index=True, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    window_minutes = db.Column(db.Integer, nullable=False, default=15)
    threshold = db.Column(db.Integer, nullable=False, default=0)
    severity = db.Column(db.String(16), nullable=False, default="warn")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="viewer")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class CBOMEvent(db.Model):
    event_id = db.Column(db.String(36), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)

    source_component = db.Column(db.String(64), index=True, nullable=False)
    destination_component = db.Column(db.String(64), index=True, nullable=False)
    communication_protocol = db.Column(db.String(32), index=True, nullable=False)
    message_type = db.Column(db.String(64), index=True, nullable=False)
    status = db.Column(db.String(16), index=True, nullable=False)

    payload_summary = db.Column(db.Text, nullable=True)
    error_details = db.Column(db.Text, nullable=True)
    metrics = db.Column(db.Text, nullable=True)

    api_endpoint = db.Column(db.String(255), index=True, nullable=True)
    client_token_id = db.Column(db.String(64), index=True, nullable=True)
    trace_id = db.Column(db.String(64), index=True, nullable=True)

    crypto_algorithm = db.Column(db.String(64), index=True, nullable=True)
    key_length = db.Column(db.Integer, nullable=True)
    pqc_support = db.Column(db.Boolean, nullable=True)
    quantum_ready = db.Column(db.Boolean, nullable=True)
    tls_version = db.Column(db.String(16), nullable=True)
    cipher_suite = db.Column(db.String(128), nullable=True)
    signature_algorithm = db.Column(db.String(128), nullable=True)
    library_tool = db.Column(db.String(128), nullable=True)
    cert_type = db.Column(db.String(64), nullable=True)

    latency_ms = db.Column(db.Integer, nullable=True)
    action_suggestion = db.Column(db.Text, nullable=True)


class GeminiInsight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    event_id = db.Column(db.String(36), index=True, nullable=False)
    model = db.Column(db.String(64), nullable=True)
    template = db.Column(db.String(64), nullable=True)
    prompt = db.Column(db.Text, nullable=True)
    response_json = db.Column(db.Text, nullable=True)


class SIEMEvent(db.Model):
    __tablename__ = "siem_events"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(36), unique=True, index=True, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, nullable=False)

    event_type = db.Column(db.String(32), index=True, nullable=False)  # telemetry|cbom|audit|network|crypto
    status = db.Column(db.String(16), index=True, nullable=True)  # success|fail|warning
    severity = db.Column(db.String(16), index=True, nullable=True)  # info|warning|critical
    data_classification = db.Column(db.String(16), index=True, nullable=True)  # low|medium|high|secret

    source_component = db.Column(db.String(64), index=True, nullable=True)
    source_id = db.Column(db.String(64), index=True, nullable=True)
    source_ip = db.Column(db.String(64), index=True, nullable=True)

    destination_component = db.Column(db.String(64), index=True, nullable=True)
    destination_id = db.Column(db.String(64), index=True, nullable=True)
    destination_ip = db.Column(db.String(64), index=True, nullable=True)

    protocol = db.Column(db.String(32), index=True, nullable=True)  # HTTP|HTTPS|mTLS|Custom|TCP|SQL
    crypto_algorithm = db.Column(db.String(64), index=True, nullable=True)  # RSA|Kyber|AES|Hybrid
    key_length = db.Column(db.Integer, nullable=True)
    pqc_ready = db.Column(db.Boolean, nullable=True)
    tls_version = db.Column(db.String(16), nullable=True)

    harvestable = db.Column(db.Boolean, nullable=True)
    quantum_risk_score = db.Column(db.Float, nullable=True)

    raw_event_ref = db.Column(db.String(128), index=True, nullable=True)
    raw_json = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class SIEMSession(db.Model):
    __tablename__ = "siem_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, index=True, nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(16), index=True, nullable=True)
    details_json = db.Column(db.Text, nullable=True)


class SIEMCryptoExposure(db.Model):
    __tablename__ = "siem_crypto_exposure"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    flow_id = db.Column(db.String(128), index=True, nullable=True)
    source_component = db.Column(db.String(64), index=True, nullable=True)
    destination_component = db.Column(db.String(64), index=True, nullable=True)
    protocol = db.Column(db.String(32), index=True, nullable=True)

    crypto_algorithm = db.Column(db.String(64), index=True, nullable=True)
    key_length = db.Column(db.Integer, nullable=True)
    pqc_ready = db.Column(db.Boolean, nullable=True)

    data_classification = db.Column(db.String(16), index=True, nullable=True)
    harvestable = db.Column(db.Boolean, nullable=True)
    quantum_risk_score = db.Column(db.Float, nullable=True)

    notes = db.Column(db.Text, nullable=True)


class SIEMAlert(db.Model):
    __tablename__ = "siem_alerts"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    severity = db.Column(db.String(16), index=True, nullable=False, default="info")
    alert_type = db.Column(db.String(64), index=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(16), index=True, nullable=False, default="open")

    related_event_id = db.Column(db.String(36), index=True, nullable=True)
    related_session_id = db.Column(db.String(64), index=True, nullable=True)
    details_json = db.Column(db.Text, nullable=True)


class SIEMRiskScore(db.Model):
    __tablename__ = "siem_risk_scores"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    flow_id = db.Column(db.String(128), index=True, nullable=True)
    session_id = db.Column(db.String(64), index=True, nullable=True)

    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    risk_level = db.Column(db.String(16), index=True, nullable=True)  # low|medium|high
    reason = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)

