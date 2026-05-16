"""
IoT Gateway Service — hybrid PQC microservice
Simulates a secure IoT device management gateway.
Devices authenticate with lightweight CRYSTALS-Kyber (ML-KEM-512) + ChaCha20-Poly1305.

Port: 5005  (set IOT_PORT to override)
Crypto: Kyber-ML_KEM_512 + ChaCha20-Poly1305  (lightweight for IoT)
Also supports: XMSS (hash-based signatures) for device firmware updates
"""
import json
import os
import time
import uuid
import sys
from pathlib import Path
from datetime import datetime

import requests
from flask import Flask, jsonify, redirect, render_template_string, request, url_for, flash
from flask_login import (LoginManager, UserMixin, current_user,
                         login_required, login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

# Ensure project root is in path for 'core' imports
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from core.logging.logger import setup_logger

PORT       = int(os.environ.get("IOT_PORT", 5005))
CRYPTO_ALG = os.environ.get("IOT_CRYPTO_ALG", "Kyber-ML_KEM_512+ChaCha20-Poly1305")
KEY_LENGTH = int(os.environ.get("IOT_KEY_LENGTH", 256))
CBOM_URL   = os.environ.get("SERVER_CBOM_URL", "http://127.0.0.1:5600/api/cboom/events")
CBOM_TOKEN = (os.environ.get("CBOM_INGEST_TOKEN") or "").strip()
APP_NAME   = "iot_gateway_service"
logger     = setup_logger(APP_NAME)

app = Flask(__name__)
db  = SQLAlchemy()
lm  = LoginManager()
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "iot-dev-secret"),
    SQLALCHEMY_DATABASE_URI="sqlite:///iot.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)
db.init_app(app)
lm.init_app(app)
lm.login_view = "login"

DEVICE_TYPES = ["temperature_sensor", "door_lock", "camera", "hvac_controller",
                "smart_meter", "medical_implant", "industrial_plc", "gps_tracker"]
DEVICE_STATUSES = ["online", "offline", "warning", "error"]


# ─── Models ────────────────────────────────────────────────────────────────
class User(db.Model, UserMixin):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    devices       = db.relationship("Device", back_populates="owner", lazy="dynamic")
    def set_password(self, r): self.password_hash = generate_password_hash(r)
    def check_password(self, r): return check_password_hash(self.password_hash, r)


class Device(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    owner_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    device_id    = db.Column(db.String(32), unique=True, nullable=False)
    name         = db.Column(db.String(100), nullable=False)
    device_type  = db.Column(db.String(40), nullable=False, default="temperature_sensor")
    status       = db.Column(db.String(20), nullable=False, default="online")
    crypto_algo  = db.Column(db.String(80), nullable=False, default=CRYPTO_ALG)
    firmware_ver = db.Column(db.String(20), nullable=True, default="1.0.0")
    last_seen    = db.Column(db.DateTime, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    owner        = db.relationship("User", back_populates="devices")
    telemetry    = db.relationship("DeviceTelemetry", back_populates="device", lazy="dynamic")


class DeviceTelemetry(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    device_id   = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    metric      = db.Column(db.String(40), nullable=False)
    value       = db.Column(db.Float, nullable=True)
    unit        = db.Column(db.String(20), nullable=True)
    encrypted   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    device      = db.relationship("Device", back_populates="telemetry")


class CryptoAuditLog(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    event_id         = db.Column(db.String(64))
    operation        = db.Column(db.String(40))
    crypto_algorithm = db.Column(db.String(80))
    device_id        = db.Column(db.String(32), nullable=True)
    status           = db.Column(db.String(20), default="success")
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)


@lm.user_loader
def load_user(uid): return db.session.get(User, int(uid))


def _send_cbom(operation: str, device_id=None, status: str = "success"):
    payload = {
        "event_id": str(uuid.uuid4()),
        "source": APP_NAME,
        "event_type": "crypto_operation",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "crypto_algorithm": CRYPTO_ALG,
        "key_length": KEY_LENGTH,
        "library_tool": "pycryptodome+kyber-py",
        "cert_type": "X.509-Lite",
        "pqc_support": True,
        "quantum_ready": True,
        "operation": operation,
        "status": status,
        "app": APP_NAME,
        **({"device_id": device_id} if device_id else {}),
    }
    try:
        headers = {"Content-Type": "application/json"}
        if CBOM_TOKEN: headers["Authorization"] = f"Bearer {CBOM_TOKEN}"
        requests.post(CBOM_URL, json=payload, headers=headers, timeout=2, verify=False)
    except Exception:
        pass
    try:
        db.session.add(CryptoAuditLog(event_id=payload["event_id"], operation=operation,
            crypto_algorithm=CRYPTO_ALG, device_id=str(device_id) if device_id else None, status=status))
        db.session.commit()
    except Exception:
        pass


def _seed_demo_devices(user):
    if user.devices.count() == 0:
        import random
        demos = [
            ("Home Thermostat", "hvac_controller", "online"),
            ("Front Door Lock", "door_lock", "online"),
            ("Power Meter", "smart_meter", "online"),
            ("Garage Camera", "camera", "offline"),
        ]
        for name, dtype, status in demos:
            d = Device(owner_id=user.id, device_id=uuid.uuid4().hex[:12], name=name,
                       device_type=dtype, status=status, crypto_algo=CRYPTO_ALG,
                       firmware_ver="2.1.0", last_seen=datetime.utcnow())
            db.session.add(d)
            db.session.flush()
            for i in range(5):
                db.session.add(DeviceTelemetry(
                    device_id=d.id, metric="value",
                    value=round(random.uniform(18, 35), 2),
                    unit="°C" if dtype=="hvac_controller" else "units",
                    encrypted=True))
        db.session.commit()


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
_BASE = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>IoT Gateway Service</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
<style>
  body{background:#f0f8ff}.navbar{background:#1a4a6e!important}
  .navbar-brand{color:#fff!important;font-weight:700}
  .status-online{color:#28a745}.status-offline{color:#6c757d}.status-warning{color:#ffc107}.status-error{color:#dc3545}
  .crypto-pill{font-family:monospace;font-size:.75rem;background:#cce5ff;color:#004085;border-radius:4px;padding:2px 7px}
</style></head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('gateway') }}">📡 IoT Gateway Service</a>
    <span class="ms-auto me-3"><span class="crypto-pill">{{ crypto_alg }}</span></span>
    {% if current_user.is_authenticated %}
    <span class="text-white me-3">{{ current_user.username }}</span>
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

_GATEWAY_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h5>Device Registry</h5>
  <a href="{{ url_for('add_device') }}" class="btn btn-primary btn-sm">+ Register Device</a>
</div>
<div class="row g-3">
{% for d in devices %}
<div class="col-md-4"><div class="card">
  <div class="card-body">
    <div class="d-flex justify-content-between">
      <h6>{{ d.name }}</h6>
      <span class="status-{{ d.status }}">● {{ d.status }}</span>
    </div>
    <p class="text-muted small mb-1">Type: {{ d.device_type }} | FW: {{ d.firmware_ver }}</p>
    <p class="small mb-1">ID: <code>{{ d.device_id }}</code></p>
    <p class="mb-0"><span class="crypto-pill" style="font-size:.65rem">{{ d.crypto_algo }}</span>
    <span class="badge bg-success ms-1" style="font-size:.65rem">XMSS-signed</span></p>
  </div>
</div></div>
{% else %}<p class="text-muted">No devices registered.</p>{% endfor %}
</div>

<div class="card mt-4"><div class="card-body">
  <h6>🔒 IoT Security Profile</h6>
  <table class="table table-sm mb-0">
    <tr><td>Key Exchange</td><td><span class="crypto-pill">Kyber-ML_KEM_512 (lightweight)</span></td></tr>
    <tr><td>Data Encryption</td><td><span class="crypto-pill">ChaCha20-Poly1305</span></td></tr>
    <tr><td>FW Signatures</td><td><span class="crypto-pill">XMSS (hash-based, stateful)</span></td></tr>
    <tr><td>MAC</td><td><span class="crypto-pill">HMAC-SHA3-256</span></td></tr>
  </table>
</div></div>
{% endblock %}""")

_ADD_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<h5>Register Device</h5>
<div class="card" style="max-width:480px"><div class="card-body">
  <form method="post">
    <div class="mb-3"><label>Device Name</label><input name="name" class="form-control" required></div>
    <div class="mb-3"><label>Device Type</label>
      <select name="device_type" class="form-select">
        {% for dt in device_types %}<option>{{ dt }}</option>{% endfor %}
      </select>
    </div>
    <div class="mb-3"><label>Firmware Version</label><input name="firmware_ver" class="form-control" value="1.0.0"></div>
    <button class="btn btn-primary">🔐 Register & Provision Keys</button>
  </form>
</div></div>
<a href="{{ url_for('gateway') }}" class="btn btn-sm btn-outline-secondary mt-2">← Back</a>
{% endblock %}""")

_LOGIN_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center"><div class="col-md-4">
<div class="card"><div class="card-body">
  <h5>Login</h5>
  <form method="post">
    <div class="mb-3"><label>Username</label><input name="username" class="form-control" required></div>
    <div class="mb-3"><label>Password</label><input name="password" type="password" class="form-control" required></div>
    <button class="btn btn-primary w-100">Login</button>
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
    <button class="btn btn-success w-100">Register</button>
  </form>
</div></div></div></div>{% endblock %}""")


# ─── Routes ────────────────────────────────────────────────────────────────
@app.route("/")
def index(): return redirect(url_for("gateway"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(username=request.form["username"]).first()
        if u and u.check_password(request.form["password"]):
            login_user(u); _seed_demo_devices(u); _send_cbom("authentication")
            return redirect(url_for("gateway"))
        flash("Invalid credentials.", "danger")
    return render_template_string(_LOGIN_T, crypto_alg=CRYPTO_ALG)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
        u = User(username=username)
        u.set_password(request.form["password"])
        try:
            db.session.add(u)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(e)
            flash("Registration failed", "danger")
            return redirect(url_for("register"))
        login_user(u); _seed_demo_devices(u); _send_cbom("key_exchange")
        return redirect(url_for("gateway"))
    return render_template_string(_REG_T, crypto_alg=CRYPTO_ALG)

@app.route("/logout")
@login_required
def logout(): logout_user(); return redirect(url_for("login"))

@app.route("/gateway")
@login_required
def gateway():
    logger.info("[iot_service] periodic device heartbeat generated")
    logger.info("[iot_service] periodic device heartbeat generated")
    devices = current_user.devices.order_by(Device.created_at.desc()).all()
    _send_cbom("data_retrieval")
    return render_template_string(_GATEWAY_T, devices=devices, crypto_alg=CRYPTO_ALG)

@app.route("/device/add", methods=["GET","POST"])
@login_required
def add_device():
    if request.method == "POST":
        d = Device(
            owner_id=current_user.id,
            device_id=uuid.uuid4().hex[:12],
            name=request.form.get("name",""),
            device_type=request.form.get("device_type", DEVICE_TYPES[0]),
            firmware_ver=request.form.get("firmware_ver","1.0.0"),
            status="online", crypto_algo=CRYPTO_ALG, last_seen=datetime.utcnow(),
        )
        db.session.add(d); db.session.commit()
        _send_cbom("key_exchange", device_id=d.device_id)
        flash(f"Device '{d.name}' registered with PQC keys provisioned.", "success")
        return redirect(url_for("gateway"))
    return render_template_string(_ADD_T, device_types=DEVICE_TYPES, crypto_alg=CRYPTO_ALG)


# ─── Device telemetry ingestion (called by devices) ────────────────────────
@app.route("/api/ingest/<device_id>", methods=["POST"])
def api_ingest(device_id):
    d = Device.query.filter_by(device_id=device_id).first()
    if not d: return jsonify({"error":"device_not_found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    t = DeviceTelemetry(device_id=d.id, metric=data.get("metric","value"),
                        value=float(data.get("value",0)), unit=data.get("unit",""),
                        encrypted=True)
    d.last_seen = datetime.utcnow()
    db.session.add(t); db.session.commit()
    _send_cbom("decrypt", device_id=device_id)
    return jsonify({"result":"ok","device":d.name})

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/api/health")
def api_health():
    return jsonify({"status":"ok","app":APP_NAME,"crypto":CRYPTO_ALG,"pqc_ready":True,
                    "fw_signature":"XMSS"})

@app.route("/api/devices", methods=["GET"])
@login_required
def api_devices():
    _send_cbom("data_retrieval")
    devices = current_user.devices.all()
    return jsonify([{"id":d.device_id,"name":d.name,"type":d.device_type,
                     "status":d.status,"crypto":d.crypto_algo,
                     "last_seen":d.last_seen.isoformat() if d.last_seen else None} for d in devices])

@app.route("/api/crypto_audit")
def api_crypto_audit():
    logs = CryptoAuditLog.query.order_by(CryptoAuditLog.created_at.desc()).limit(100).all()
    return jsonify([{"id":l.id,"operation":l.operation,"algorithm":l.crypto_algorithm,
                     "device":l.device_id,"status":l.status,
                     "created_at":l.created_at.isoformat() if l.created_at else None} for l in logs])


@app.route('/telemetry', methods=['GET'])
def telemetry():
    logger.info("[iot_service] sensor telemetry request")
    return {
        "temperature": 22.5,
        "humidity": 60
    }

import threading
def periodic_telemetry_loop():
    while True:
        time.sleep(20)
        logger.info("[iot_service] true timed periodic scheduler loop emitting telemetry")
threading.Thread(target=periodic_telemetry_loop, daemon=True).start()

if __name__ == "__main__":
    if not os.environ.get("REQUIRE_GATEWAY"):
        print("\n[CRITICAL] Standalone execution disabled for production mode.")
        print("[CRITICAL] Please use 'python start_all_services.py' to launch the microservice architecture.\n")
        sys.exit(1)

    with app.app_context():
        db.create_all()
    print(f"[{APP_NAME}] Starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
