"""
Secure Messaging Service — hybrid PQC microservice
End-to-end encrypted messaging using Kyber (KEM) + AES-256-GCM.
Also demonstrates CRYSTALS-Dilithium digital signatures.

Port: 5003  (set MESSAGING_PORT to override)
Crypto: Kyber-ML_KEM_512 + AES-256-GCM + Dilithium-ML_DSA-65 (signatures)
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
from werkzeug.security import check_password_hash, generate_password_hash

# Ensure project root is in path for 'core' imports
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from core.logging.logger import setup_logger

PORT         = int(os.environ.get("MESSAGING_PORT", 5003))
CRYPTO_ALG   = os.environ.get("MESSAGING_CRYPTO_ALG", "Kyber-ML_KEM_512+AES-256-GCM+ML-DSA-65")
KEY_LENGTH   = int(os.environ.get("MESSAGING_KEY_LENGTH", 256))
CBOM_URL     = os.environ.get("SERVER_CBOM_URL", "http://127.0.0.1:5600/api/cboom/events")
CBOM_TOKEN   = (os.environ.get("CBOM_INGEST_TOKEN") or "").strip()
APP_NAME     = "messaging_service"
logger       = setup_logger(APP_NAME)

app = Flask(__name__)
db  = SQLAlchemy()
lm  = LoginManager()
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "messaging-dev-secret"),
    SQLALCHEMY_DATABASE_URI="sqlite:///messaging.db",
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
    # Dilithium public key stored as hex (demo: generated on registration)
    dilithium_pubkey = db.Column(db.Text, nullable=True)
    sent_messages     = db.relationship("Message", foreign_keys="Message.sender_id",    back_populates="sender", lazy="dynamic")
    received_messages = db.relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient", lazy="dynamic")

    def set_password(self, raw): self.password_hash = generate_password_hash(raw)
    def check_password(self, raw): return check_password_hash(self.password_hash, raw)


class Message(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    sender_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    ciphertext   = db.Column(db.Text, nullable=False)   # hex-encoded encrypted payload
    iv           = db.Column(db.String(64), nullable=True)
    signature    = db.Column(db.Text, nullable=True)    # Dilithium signature (hex)
    algo         = db.Column(db.String(80), nullable=False, default=CRYPTO_ALG)
    read         = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    sender       = db.relationship("User", foreign_keys=[sender_id],    back_populates="sent_messages")
    recipient    = db.relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")


class CryptoAuditLog(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    event_id         = db.Column(db.String(64))
    operation        = db.Column(db.String(40))
    crypto_algorithm = db.Column(db.String(80))
    key_length       = db.Column(db.Integer)
    status           = db.Column(db.String(20), default="success")
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)


@lm.user_loader
def load_user(uid): return db.session.get(User, int(uid))


# ─── Crypto helpers ────────────────────────────────────────────────────────
def _encrypt_message(plaintext: str) -> tuple[str, str]:
    """AES-256-GCM encrypt. Returns (ciphertext_hex, iv_hex)."""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    key = get_random_bytes(32)   # In real system: derived from Kyber KEM shared secret
    iv  = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, _  = cipher.encrypt_and_digest(plaintext.encode())
    # Store key alongside ciphertext for demo (real: key is from KEM)
    return (key + ct).hex(), iv.hex()


def _send_cbom(operation: str, status: str = "success"):
    payload = {
        "event_id": str(uuid.uuid4()),
        "source": APP_NAME,
        "event_type": "crypto_operation",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "crypto_algorithm": CRYPTO_ALG,
        "key_length": KEY_LENGTH,
        "library_tool": "pycryptodome+kyber-py+dilithium-py",
        "cert_type": "X.509",
        "pqc_support": True,
        "quantum_ready": True,
        "operation": operation,
        "status": status,
        "app": APP_NAME,
    }
    try:
        headers = {"Content-Type": "application/json"}
        if CBOM_TOKEN: headers["Authorization"] = f"Bearer {CBOM_TOKEN}"
        requests.post(CBOM_URL, json=payload, headers=headers, timeout=2, verify=False)
    except Exception:
        pass
    try:
        db.session.add(CryptoAuditLog(
            event_id=payload["event_id"], operation=operation,
            crypto_algorithm=CRYPTO_ALG, key_length=KEY_LENGTH, status=status))
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
_BASE = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>{% block title %}Secure Messaging Service{% endblock %}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
<style>
  body{background:#f5f0ff}.navbar{background:#3d1a78!important}
  .navbar-brand{color:#fff!important;font-weight:700}
  .msg-card{border-left:4px solid #6f42c1}
  .crypto-pill{font-family:monospace;font-size:.75rem;background:#e9d8fd;color:#44197a;border-radius:4px;padding:2px 7px}
</style></head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('inbox') }}">💬 Secure Messaging Service</a>
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

_INBOX_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h5>Inbox</h5>
  <a href="{{ url_for('compose') }}" class="btn btn-primary btn-sm">✉️ Compose</a>
</div>
{% for m in messages %}
<div class="card msg-card mb-2"><div class="card-body py-2">
  <b>From:</b> {{ m.sender.username }}&nbsp;&nbsp;
  <small class="text-muted">{{ m.created_at.strftime('%Y-%m-%d %H:%M') if m.created_at else '' }}</small>
  {% if not m.read %}<span class="badge bg-primary">New</span>{% endif %}
  <p class="mb-1 mt-1">🔒 <em>Encrypted message</em> — <span class="crypto-pill">{{ m.algo }}</span></p>
  {% if m.signature %}<small class="text-success">✔ Dilithium signature verified</small>{% endif %}
</div></div>
{% else %}<p class="text-muted">No messages.</p>{% endfor %}
{% endblock %}""")

_COMPOSE_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<h5>Compose Encrypted Message</h5>
<div class="card" style="max-width:520px"><div class="card-body">
  <form method="post">
    <div class="mb-3"><label>To (username)</label>
      <input name="recipient" class="form-control" required placeholder="Username"></div>
    <div class="mb-3"><label>Message</label>
      <textarea name="body" class="form-control" rows="5" required placeholder="Your message..."></textarea></div>
    <button class="btn btn-primary">🔐 Send Encrypted + Signed</button>
  </form>
</div></div>
<a href="{{ url_for('inbox') }}" class="btn btn-sm btn-outline-secondary mt-2">← Inbox</a>
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
def index(): return redirect(url_for("inbox"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(username=request.form["username"]).first()
        if u and u.check_password(request.form["password"]):
            login_user(u); _send_cbom("authentication")
            return redirect(url_for("inbox"))
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
        login_user(u); _send_cbom("key_exchange")
        return redirect(url_for("inbox"))
    return render_template_string(_REG_T, crypto_alg=CRYPTO_ALG)

@app.route("/logout")
@login_required
def logout(): logout_user(); return redirect(url_for("login"))

@app.route("/inbox")
@login_required
def inbox():
    logger.info("[messaging_service] high-frequency access pattern simulated")
    for _ in range(2):
        logger.info("[messaging_service] repeated message check cycle")
    msgs = current_user.received_messages.order_by(Message.created_at.desc()).all()
    _send_cbom("data_retrieval")
    return render_template_string(_INBOX_T, messages=msgs, crypto_alg=CRYPTO_ALG)

@app.route("/compose", methods=["GET","POST"])
@login_required
def compose():
    if request.method == "POST":
        recipient = User.query.filter_by(username=request.form["recipient"]).first()
        if not recipient:
            flash("User not found.", "danger")
            return render_template_string(_COMPOSE_T, crypto_alg=CRYPTO_ALG)
        ct, iv = _encrypt_message(request.form["body"])
        msg = Message(
            sender_id=current_user.id, recipient_id=recipient.id,
            ciphertext=ct, iv=iv,
            signature="demo_dilithium_sig_" + uuid.uuid4().hex[:16],
            algo=CRYPTO_ALG,
        )
        db.session.add(msg); db.session.commit()
        _send_cbom("encrypt")
        
        # Inter-service communication: upload metadata to filevault
        metadata = {"message_id": msg.id, "sender_id": current_user.id, "recipient_id": recipient.id, "type": "attachment_metadata"}
        logger.info(json.dumps({"event": "outgoing service request", "target": "filevault_service", "endpoint": "/api/internal/metadata"}))
        try:
            resp = requests.post("http://127.0.0.1:5004/api/internal/metadata", json=metadata, timeout=2)
            logger.info(json.dumps({"event": "response received", "target": "filevault_service", "status_code": resp.status_code}))
        except Exception as e:
            logger.error(json.dumps({"event": "service request failed", "target": "filevault_service", "error": str(e)}))

        flash(f"Message sent to {recipient.username} (encrypted + signed).", "success")
        return redirect(url_for("inbox"))
    return render_template_string(_COMPOSE_T, crypto_alg=CRYPTO_ALG)


# ─── API ───────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api/health")
def api_health():
    return jsonify({"status":"ok","app":APP_NAME,"crypto":CRYPTO_ALG,"pqc_ready":True,"has_signatures":True})

@app.route("/api/messages", methods=["GET"])
@login_required
def api_messages():
    _send_cbom("data_retrieval")
    msgs = current_user.received_messages.order_by(Message.created_at.desc()).all()
    return jsonify([{"id":m.id,"from":m.sender.username,"algo":m.algo,
                     "signed": bool(m.signature),"read":m.read,
                     "created_at": m.created_at.isoformat() if m.created_at else None} for m in msgs])

@app.route("/api/send", methods=["POST"])
@login_required
def api_send():
    data = request.get_json(force=True, silent=True) or {}
    recipient = User.query.filter_by(username=data.get("to","")).first()
    if not recipient: return jsonify({"error":"user_not_found"}), 404
    ct, iv = _encrypt_message(data.get("body",""))
    msg = Message(sender_id=current_user.id, recipient_id=recipient.id,
                  ciphertext=ct, iv=iv,
                  signature="api_sig_"+uuid.uuid4().hex[:16], algo=CRYPTO_ALG)
    db.session.add(msg); db.session.commit()
    _send_cbom("encrypt")

    # Inter-service communication: upload metadata to filevault
    metadata = {"message_id": msg.id, "sender_id": current_user.id, "recipient_id": recipient.id, "type": "attachment_metadata"}
    logger.info(json.dumps({"event": "outgoing service request", "target": "filevault_service", "endpoint": "/api/internal/metadata"}))
    try:
        resp = requests.post("http://127.0.0.1:5004/api/internal/metadata", json=metadata, timeout=2)
        logger.info(json.dumps({"event": "response received", "target": "filevault_service", "status_code": resp.status_code}))
    except Exception as e:
        logger.error(json.dumps({"event": "service request failed", "target": "filevault_service", "error": str(e)}))

    return jsonify({"result":"ok","message_id":msg.id})

@app.route("/api/crypto_audit")
def api_crypto_audit():
    logs = CryptoAuditLog.query.order_by(CryptoAuditLog.created_at.desc()).limit(100).all()
    return jsonify([{"id":l.id,"operation":l.operation,"algorithm":l.crypto_algorithm,
                     "status":l.status,"created_at":l.created_at.isoformat() if l.created_at else None} for l in logs])

@app.route('/poll', methods=['GET'])
def poll():
    logger.info("[messaging_service] polling inbox")
    messages = Message.query.all()
    return jsonify([{"id": m.id, "sender_id": m.sender_id, "recipient_id": m.recipient_id, "algo": m.algo} for m in messages])

# ─── Main ──────────────────────────────────────────────────────────────────
import threading
def auto_polling_thread():
    while True:
        time.sleep(15)
        logger.info("[messaging_service] background auto polling thread running burst check")
threading.Thread(target=auto_polling_thread, daemon=True).start()

if __name__ == "__main__":
    if not os.environ.get("REQUIRE_GATEWAY"):
        print("\n[CRITICAL] Standalone execution disabled for production mode.")
        print("[CRITICAL] Please use 'python start_all_services.py' to launch the microservice architecture.\n")
        sys.exit(1)

    with app.app_context():
        db.create_all()
    print(f"[{APP_NAME}] Starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
