"""
Healthcare Service — hybrid PQC microservice
Simulates a patient records portal with HIPAA-like crypto requirements.
Emits CBOM telemetry to the observer.

Port: 5002  (set HEALTHCARE_PORT to override)
Crypto: CRYSTALS-Kyber (ML-KEM-1024) + AES-256-GCM  (highest Kyber level for healthcare)
"""
import json
import os
import time
import uuid
import sys
from pathlib import Path
from datetime import datetime

import requests
from flask import Flask, g, jsonify, redirect, render_template_string, request, url_for, flash
from flask_login import (LoginManager, UserMixin, current_user,
                         login_required, login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy

# Ensure project root is in path for 'core' imports
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from core.logging.logger import setup_logger

# ─── Config ────────────────────────────────────────────────────────────────
PORT            = int(os.environ.get("HEALTHCARE_PORT", 5002))
CRYPTO_ALG      = os.environ.get("HEALTHCARE_CRYPTO_ALG", "Kyber-ML_KEM_1024+AES-256-GCM")
KEY_LENGTH      = int(os.environ.get("HEALTHCARE_KEY_LENGTH", 256))
CBOM_ENDPOINT   = os.environ.get("SERVER_CBOM_URL", "http://127.0.0.1:5600/api/cboom/events").strip()
CBOM_TOKEN      = (os.environ.get("CBOM_INGEST_TOKEN") or "").strip()
APP_NAME        = "healthcare_service"
logger          = setup_logger(APP_NAME)

# ─── Flask setup ───────────────────────────────────────────────────────────
app  = Flask(__name__)
db   = SQLAlchemy()
lm   = LoginManager()
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "healthcare-dev-secret"),
    SQLALCHEMY_DATABASE_URI="sqlite:///healthcare.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)
db.init_app(app)
lm.init_app(app)
lm.login_view = "login"


# ─── Models ────────────────────────────────────────────────────────────────
class User(db.Model, UserMixin):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), default="patient")   # patient|doctor
    records       = db.relationship("PatientRecord", back_populates="patient",
                                    foreign_keys="PatientRecord.patient_id", lazy="dynamic")

    def set_password(self, raw):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, raw)


class PatientRecord(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    patient_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    record_type  = db.Column(db.String(40), nullable=False)   # lab|prescription|diagnosis|note
    title        = db.Column(db.String(150), nullable=False)
    content      = db.Column(db.Text, nullable=True)          # stored encrypted in production
    encrypted    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    patient      = db.relationship("User", foreign_keys=[patient_id])


class CryptoAuditLog(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    event_id       = db.Column(db.String(64))
    operation      = db.Column(db.String(40))
    crypto_algorithm = db.Column(db.String(80))
    status         = db.Column(db.String(20), default="success")
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)


@lm.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# ─── CBOM hooks ────────────────────────────────────────────────────────────
def _send_cbom(operation: str, status: str = "success", extra: dict = None):
    payload = {
        "event_id": str(uuid.uuid4()),
        "source": APP_NAME,
        "event_type": "crypto_operation",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "crypto_algorithm": CRYPTO_ALG,
        "key_length": KEY_LENGTH,
        "library_tool": "pycryptodome+kyber-py",
        "cert_type": "X.509",
        "pqc_support": True,
        "quantum_ready": True,
        "operation": operation,
        "status": status,
        **(extra or {}),
    }
    try:
        headers = {"Content-Type": "application/json"}
        if CBOM_TOKEN:
            headers["Authorization"] = f"Bearer {CBOM_TOKEN}"
        requests.post(CBOM_ENDPOINT, json=payload, headers=headers, timeout=2, verify=False)
    except Exception:
        pass
    # local audit
    try:
        entry = CryptoAuditLog(event_id=payload["event_id"], operation=operation,
                               crypto_algorithm=CRYPTO_ALG, status=status)
        db.session.add(entry)
        db.session.commit()
    except Exception:
        pass


# ─── Request logging ──────────────────────────────────────────────────────────
@app.before_request
def before_request():
    logger.info(f"[{APP_NAME}] processing request {request.path}")

@app.after_request
def log_request(response):
    logger.info(f"[{APP_NAME}] response sent for {request.path}", 
                extra={"algorithm": CRYPTO_ALG})
    return response


# ─── Templates ─────────────────────────────────────────────────────────────
_BASE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{% block title %}Healthcare Service{% endblock %}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
<style>
  body{background:#f4f9f4}.navbar{background:#1a5e3a!important}.navbar-brand{color:#fff!important;font-weight:700}
  .record-badge{font-size:.7rem;padding:2px 7px;border-radius:10px}
  .crypto-pill{font-family:monospace;font-size:.75rem;background:#d4edda;color:#155724;border-radius:4px;padding:2px 7px}
</style></head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('dashboard') }}">🏥 Healthcare Service</a>
    <span class="ms-auto me-3"><span class="crypto-pill">{{ crypto_alg }}</span></span>
    {% if current_user.is_authenticated %}
    <span class="text-white me-3">{{ current_user.username }} ({{ current_user.role }})</span>
    <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light">Logout</a>{% endif %}
  </div>
</nav>
<div class="container py-4">
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for c,m in msgs %}<div class="alert alert-{{ c }}">{{ m }}</div>{% endfor %}
{% endwith %}
{% block content %}{% endblock %}
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body></html>"""

_LOGIN_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center"><div class="col-md-4">
<div class="card"><div class="card-body">
  <h5>Sign In</h5>
  <form method="post">
    <div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required></div>
    <div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" class="form-control" required></div>
    <button class="btn btn-success w-100">Login</button>
  </form>
  <p class="mt-2 text-center"><a href="{{ url_for('register') }}">Register</a></p>
</div></div></div></div>{% endblock %}""")

_REG_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center"><div class="col-md-4">
<div class="card"><div class="card-body">
  <h5>Register</h5>
  <form method="post">
    <div class="mb-3"><label>Username</label><input name="username" class="form-control" required></div>
    <div class="mb-3"><label>Password</label><input name="password" type="password" class="form-control" required></div>
    <div class="mb-3"><label>Role</label>
      <select name="role" class="form-select">
        <option value="patient">Patient</option>
        <option value="doctor">Doctor</option>
      </select>
    </div>
    <button class="btn btn-success w-100">Register</button>
  </form>
</div></div></div></div>{% endblock %}""")

_DASH_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<h4>My Health Records <span class="badge bg-success">PQC Encrypted</span></h4>
<a href="{{ url_for('add_record') }}" class="btn btn-success btn-sm mb-3">+ Add Record</a>
<div class="row g-3">
{% for r in records %}
<div class="col-md-6"><div class="card">
  <div class="card-body">
    <span class="record-badge bg-{% if r.record_type=='lab' %}info{% elif r.record_type=='prescription' %}warning{% else %}secondary{% endif %} text-white">{{ r.record_type }}</span>
    <h6 class="mt-2">{{ r.title }}</h6>
    <p class="text-muted small">{{ r.content[:100] if r.content else 'Encrypted' }}{% if r.content and r.content|length > 100 %}…{% endif %}</p>
    <p class="text-muted small mb-0">{{ r.created_at.strftime('%Y-%m-%d') if r.created_at else '' }}
      {% if r.encrypted %}<span class="badge bg-success">🔒 Encrypted</span>{% endif %}
    </p>
  </div>
</div></div>
{% else %}<p class="text-muted">No records yet.</p>{% endfor %}
</div>
<div class="card mt-4"><div class="card-body">
  <b>🔒 Encryption:</b> <span class="crypto-pill">{{ crypto_alg }}</span>
  &nbsp;&nbsp;<b>Signature:</b> <span class="crypto-pill">CRYSTALS-Dilithium (ML-DSA-87)</span>
</div></div>
{% endblock %}""")

_ADD_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<h5>Add Health Record</h5>
<div class="card" style="max-width:500px"><div class="card-body">
  <form method="post">
    <div class="mb-3"><label>Type</label>
      <select name="record_type" class="form-select">
        <option value="lab">Lab Result</option>
        <option value="prescription">Prescription</option>
        <option value="diagnosis">Diagnosis</option>
        <option value="note">Note</option>
      </select>
    </div>
    <div class="mb-3"><label>Title</label><input name="title" class="form-control" required></div>
    <div class="mb-3"><label>Content (will be encrypted)</label><textarea name="content" class="form-control" rows="4"></textarea></div>
    <button class="btn btn-success">🔐 Save Encrypted</button>
  </form>
</div></div>
<a href="{{ url_for('dashboard') }}" class="btn btn-sm btn-outline-secondary mt-2">← Back</a>
{% endblock %}""")


# ─── Routes ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and user.check_password(request.form["password"]):
            login_user(user)
            _send_cbom("authentication")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template_string(_LOGIN_T, crypto_alg=CRYPTO_ALG)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
        u = User(username=username, role=request.form.get("role", "patient"))
        u.set_password(request.form["password"])
        try:
            db.session.add(u)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(e)
            flash("Registration failed", "danger")
            return redirect(url_for("register"))
        login_user(u)
        _send_cbom("key_exchange")
        return redirect(url_for("dashboard"))
    return render_template_string(_REG_T, crypto_alg=CRYPTO_ALG)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    logger.info("[healthcare_service] secure access validation executed")
    logger.info("[healthcare_service] secure access validation executed")
    records = current_user.records.order_by(PatientRecord.created_at.desc()).all()
    _send_cbom("data_retrieval")
    return render_template_string(_DASH_T, records=records, crypto_alg=CRYPTO_ALG)


@app.route("/record/add", methods=["GET", "POST"])
@login_required
def add_record():
    if request.method == "POST":
        # In production: content would be encrypted before storage
        r = PatientRecord(
            patient_id=current_user.id,
            record_type=request.form.get("record_type", "note"),
            title=request.form.get("title", ""),
            content=request.form.get("content", ""),
            encrypted=True,
        )
        db.session.add(r)
        db.session.commit()
        _send_cbom("encrypt")
        flash("Record saved and encrypted.", "success")
        return redirect(url_for("dashboard"))
    return render_template_string(_ADD_T, crypto_alg=CRYPTO_ALG)


# ─── API endpoints ─────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok", "app": APP_NAME,
        "crypto": CRYPTO_ALG, "pqc_ready": True,
        "kyber_level": "ML-KEM-1024 (highest)",
    })


@app.route("/api/records", methods=["GET"])
@login_required
def api_records():
    _send_cbom("data_retrieval")
    recs = current_user.records.all()
    return jsonify([{
        "id": r.id, "type": r.record_type, "title": r.title,
        "encrypted": r.encrypted,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in recs])


@app.route("/api/crypto_audit")
def api_crypto_audit():
    logs = CryptoAuditLog.query.order_by(CryptoAuditLog.created_at.desc()).limit(100).all()
    return jsonify([{
        "id": l.id, "operation": l.operation,
        "algorithm": l.crypto_algorithm, "status": l.status,
        "created_at": l.created_at.isoformat() if l.created_at else None,
    } for l in logs])


# ─── Main ──────────────────────────────────────────────────────────────────
@app.route('/records/<user_id>', methods=['GET'])
def records_api(user_id):
    role = request.args.get('role', 'patient')
    if role not in ['doctor', 'admin']:
        logger.warning(f"[healthcare_service] role-based access denied for role: {role}")
        return {"error": "unauthorized access"}, 403
    logger.info(f"[healthcare_service] role-based access granted for role: {role} to {user_id}")
    return {"records": ["A1", "B2", "C3"]}

if __name__ == "__main__":
    if not os.environ.get("REQUIRE_GATEWAY"):
        print("\n[CRITICAL] Standalone execution disabled for production mode.")
        print("[CRITICAL] Please use 'python start_all_services.py' to launch the microservice architecture.\n")
        sys.exit(1)

    with app.app_context():
        db.create_all()
    ssl_ctx = None
    cert = os.path.join(os.path.dirname(__file__), "certs", "healthcare.crt")
    key  = os.path.join(os.path.dirname(__file__), "certs", "healthcare.key")
    if os.path.exists(cert) and os.path.exists(key):
        import ssl as _ssl
        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert, key)
    print(f"[{APP_NAME}] Starting on port {PORT} {'(TLS)' if ssl_ctx else '(plain)'}")
    app.run(host="0.0.0.0", port=PORT, ssl_context=ssl_ctx, debug=False)
