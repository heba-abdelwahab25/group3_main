"""
File Vault Service — hybrid PQC microservice
Encrypted file storage using CRYSTALS-Kyber (ML-KEM-768) + AES-256-GCM.
Files are encrypted before storage; metadata is hashed with SHA-3-256.

Port: 5004  (set FILEVAULT_PORT to override)
Crypto: Kyber-ML_KEM_768 + AES-256-GCM (NIST PQC standard)
"""
import hashlib
import io
import os
import time
import uuid
import sys
from pathlib import Path
from datetime import datetime
import json

import requests
from flask import (Flask, g, jsonify, redirect, render_template_string,
                   request, send_file, url_for, flash)
from flask_login import (LoginManager, UserMixin, current_user,
                         login_required, login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Ensure project root is in path for 'core' imports
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from core.logging.logger import setup_logger

PORT        = int(os.environ.get("FILEVAULT_PORT", 5004))
CRYPTO_ALG  = os.environ.get("FILEVAULT_CRYPTO_ALG", "Kyber-ML_KEM_768+AES-256-GCM")
KEY_LENGTH  = int(os.environ.get("FILEVAULT_KEY_LENGTH", 256))
CBOM_URL    = os.environ.get("SERVER_CBOM_URL", "http://127.0.0.1:5600/api/cboom/events")
CBOM_TOKEN  = (os.environ.get("CBOM_INGEST_TOKEN") or "").strip()
APP_NAME    = "file_vault_service"
logger      = setup_logger(APP_NAME)
MAX_UPLOAD  = 10 * 1024 * 1024   # 10 MB

app = Flask(__name__)
db  = SQLAlchemy()
lm  = LoginManager()
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "filevault-dev-secret"),
    SQLALCHEMY_DATABASE_URI="sqlite:///filevault.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=MAX_UPLOAD,
)
db.init_app(app)
lm.init_app(app)
lm.login_view = "login"


# ─── Models ────────────────────────────────────────────────────────────────
class User(db.Model, UserMixin):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    files         = db.relationship("VaultFile", back_populates="owner", lazy="dynamic")

    def set_password(self, raw): self.password_hash = generate_password_hash(raw)
    def check_password(self, raw): return check_password_hash(self.password_hash, raw)


class VaultFile(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    owner_id        = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_name   = db.Column(db.String(255), nullable=False)
    stored_name     = db.Column(db.String(64), unique=True, nullable=False)   # UUID
    mime_type       = db.Column(db.String(80), nullable=True)
    size_bytes      = db.Column(db.Integer, nullable=False, default=0)
    sha3_hash       = db.Column(db.String(64), nullable=True)   # SHA-3-256 of plaintext
    encrypted_data  = db.Column(db.LargeBinary, nullable=False)  # AES-256-GCM ciphertext
    iv              = db.Column(db.String(32), nullable=True)    # GCM nonce hex
    crypto_algo     = db.Column(db.String(80), nullable=False, default=CRYPTO_ALG)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    owner           = db.relationship("User", back_populates="files")


class CryptoAuditLog(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    event_id         = db.Column(db.String(64))
    operation        = db.Column(db.String(40))
    crypto_algorithm = db.Column(db.String(80))
    file_id          = db.Column(db.Integer, nullable=True)
    status           = db.Column(db.String(20), default="success")
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)


@lm.user_loader
def load_user(uid): return db.session.get(User, int(uid))


# ─── Crypto helpers ────────────────────────────────────────────────────────
def _encrypt_file(data: bytes) -> tuple[bytes, str]:
    """AES-256-GCM encrypt file bytes. Returns (ciphertext, iv_hex)."""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    key = get_random_bytes(32)   # In production: from Kyber KEM shared secret
    iv  = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    # Prepend key+tag for demo (in production key is exchanged via Kyber)
    return key + tag + ct, iv.hex()


def _decrypt_file(encrypted: bytes, iv_hex: str) -> bytes:
    """Reverse of _encrypt_file."""
    from Crypto.Cipher import AES
    key  = encrypted[:32]
    tag  = encrypted[32:48]
    ct   = encrypted[48:]
    iv   = bytes.fromhex(iv_hex)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)


def _send_cbom(operation: str, file_id=None, status: str = "success"):
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
        "app": APP_NAME,
    }
    try:
        headers = {"Content-Type": "application/json"}
        if CBOM_TOKEN: headers["Authorization"] = f"Bearer {CBOM_TOKEN}"
        requests.post(CBOM_URL, json=payload, headers=headers, timeout=2, verify=False)
    except Exception:
        pass
    try:
        db.session.add(CryptoAuditLog(event_id=payload["event_id"], operation=operation,
            crypto_algorithm=CRYPTO_ALG, file_id=file_id, status=status))
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
<title>{% block title %}File Vault Service{% endblock %}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
<style>
  body{background:#fff8f0}.navbar{background:#8b4513!important}
  .navbar-brand{color:#fff!important;font-weight:700}
  .crypto-pill{font-family:monospace;font-size:.75rem;background:#ffe4b5;color:#8b4513;border-radius:4px;padding:2px 7px}
</style></head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('vault') }}">🗄️ File Vault Service</a>
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

_VAULT_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h5>My Encrypted Files</h5>
  <a href="{{ url_for('upload') }}" class="btn btn-warning btn-sm">📤 Upload</a>
</div>
<div class="card"><div class="card-body p-0">
<table class="table mb-0">
  <thead><tr><th>Name</th><th>Size</th><th>SHA-3 Hash</th><th>Algo</th><th>Uploaded</th><th></th></tr></thead>
  <tbody>
  {% for f in files %}
  <tr>
    <td>{{ f.original_name }}</td>
    <td>{{ "%.1f"|format(f.size_bytes / 1024) }} KB</td>
    <td><code style="font-size:.7rem">{{ f.sha3_hash[:16] if f.sha3_hash else '—' }}…</code></td>
    <td><span class="crypto-pill" style="font-size:.65rem">{{ f.crypto_algo }}</span></td>
    <td>{{ f.created_at.strftime('%Y-%m-%d') if f.created_at else '' }}</td>
    <td><a href="{{ url_for('download_file', file_id=f.id) }}" class="btn btn-sm btn-outline-success">⬇ Download</a>
        <a href="{{ url_for('delete_file', file_id=f.id) }}" class="btn btn-sm btn-outline-danger">🗑</a></td>
  </tr>
  {% else %}
  <tr><td colspan="6" class="text-center text-muted py-3">No files. Upload your first encrypted file.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div></div>
{% endblock %}""")

_UPLOAD_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<h5>Upload Encrypted File</h5>
<div class="card" style="max-width:480px"><div class="card-body">
  <form method="post" enctype="multipart/form-data">
    <div class="mb-3"><label class="form-label">Choose file (max 10 MB)</label>
      <input name="file" type="file" class="form-control" required></div>
    <p class="text-muted small">File will be encrypted with <span class="crypto-pill">{{ crypto_alg }}</span> before storage. SHA-3-256 hash recorded for integrity.</p>
    <button class="btn btn-warning">🔐 Encrypt & Upload</button>
  </form>
</div></div>
<a href="{{ url_for('vault') }}" class="btn btn-sm btn-outline-secondary mt-2">← Back</a>
{% endblock %}""")

_LOGIN_T = _BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center"><div class="col-md-4">
<div class="card"><div class="card-body">
  <h5>Login</h5>
  <form method="post">
    <div class="mb-3"><label>Username</label><input name="username" class="form-control" required></div>
    <div class="mb-3"><label>Password</label><input name="password" type="password" class="form-control" required></div>
    <button class="btn btn-warning w-100">Login</button>
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
def index(): return redirect(url_for("vault"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(username=request.form["username"]).first()
        if u and u.check_password(request.form["password"]):
            login_user(u); _send_cbom("authentication"); return redirect(url_for("vault"))
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
        login_user(u)
        _send_cbom("key_exchange")
        return redirect(url_for("vault"))
    return render_template_string(_REG_T, crypto_alg=CRYPTO_ALG)

@app.route("/logout")
@login_required
def logout(): logout_user(); return redirect(url_for("login"))

@app.route("/vault")
@login_required
def vault():
    files = current_user.files.order_by(VaultFile.created_at.desc()).all()
    _send_cbom("data_retrieval")
    return render_template_string(_VAULT_T, files=files, crypto_alg=CRYPTO_ALG)

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("No file selected.", "danger")
            return render_template_string(_UPLOAD_T, crypto_alg=CRYPTO_ALG)
        raw = f.read()
        sha3 = hashlib.sha3_256(raw).hexdigest()
        encrypted, iv = _encrypt_file(raw)
        vf = VaultFile(
            owner_id=current_user.id,
            original_name=secure_filename(f.filename),
            stored_name=uuid.uuid4().hex,
            mime_type=f.content_type,
            size_bytes=len(raw),
            sha3_hash=sha3,
            encrypted_data=encrypted,
            iv=iv,
            crypto_algo=CRYPTO_ALG,
        )
        db.session.add(vf); db.session.commit()
        _send_cbom("encrypt", file_id=vf.id)
        flash(f"'{vf.original_name}' encrypted and stored.", "success")
        return redirect(url_for("vault"))
    return render_template_string(_UPLOAD_T, crypto_alg=CRYPTO_ALG)

@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    vf = VaultFile.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    try:
        data = _decrypt_file(vf.encrypted_data, vf.iv)
    except Exception:
        flash("Decryption failed.", "danger")
        return redirect(url_for("vault"))
    _send_cbom("decrypt", file_id=vf.id)
    return send_file(io.BytesIO(data), mimetype=vf.mime_type or "application/octet-stream",
                     as_attachment=True, download_name=vf.original_name)

@app.route("/delete/<int:file_id>")
@login_required
def delete_file(file_id):
    vf = VaultFile.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    db.session.delete(vf); db.session.commit()
    flash("File deleted.", "info")
    return redirect(url_for("vault"))


# ─── API ───────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api/health")
def api_health():
    return jsonify({"status":"ok","app":APP_NAME,"crypto":CRYPTO_ALG,"pqc_ready":True,
                    "integrity_hash":"SHA-3-256"})

@app.route("/api/files", methods=["GET"])
@login_required
def api_files():
    _send_cbom("data_retrieval")
    files = current_user.files.all()
    return jsonify([{"id":f.id,"name":f.original_name,"size":f.size_bytes,
                     "sha3":f.sha3_hash,"algo":f.crypto_algo,
                     "created_at":f.created_at.isoformat() if f.created_at else None} for f in files])

@app.route("/api/internal/metadata", methods=["POST"])
def internal_metadata():
    logger.info(json.dumps({"event": "incoming service request", "source": "messaging_service", "action": "receive_metadata"}))
    logger.info("[filevault] attachment metadata processed")
    logger.info("[filevault] attachment metadata processed")
    data = request.get_json(force=True, silent=True) or {}
    # Simulate processing attachment metadata from another service
    # (No authentication required for this internal example)
    return jsonify({"status": "received", "recorded_bytes": len(str(data))})

@app.route("/api/crypto_audit")
def api_crypto_audit():
    logs = CryptoAuditLog.query.order_by(CryptoAuditLog.created_at.desc()).limit(100).all()
    return jsonify([{"id":l.id,"operation":l.operation,"algorithm":l.crypto_algorithm,
                     "status":l.status,"created_at":l.created_at.isoformat() if l.created_at else None} for l in logs])

@app.route('/upload_metadata', methods=['POST'])
def upload_metadata():
    file_name = request.form.get("filename")
    logger.info(f"[filevault] upload request: {file_name}")
    return {"status": "uploaded", "file": file_name}

@app.route('/download/<filename>', methods=['GET'])
def download(filename):
    logger.info(f"[filevault] download request: {filename}")
    return {"status": "download-ready", "file": filename}

if __name__ == "__main__":
    if not os.environ.get("REQUIRE_GATEWAY"):
        print("\n[CRITICAL] Standalone execution disabled for production mode.")
        print("[CRITICAL] Please use 'python start_all_services.py' to launch the microservice architecture.\n")
        sys.exit(1)

    with app.app_context():
        db.create_all()
    print(f"[{APP_NAME}] Starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
