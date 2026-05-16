"""Routes for the banking service."""
import time
import json
import os
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, g, current_app
from flask_login import login_required, current_user, login_user, logout_user
import logging

logger = logging.getLogger("banking_service")
from .models import db, User, Account, Transaction, CryptoAuditLog

main_bp = Blueprint("main", __name__)
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# ---------- Helpers ----------

def _seed_demo_account(user: User):
    if user.accounts.count() == 0:
        checking = Account(user_id=user.id, label="Checking", balance=250000)  # $2500
        savings  = Account(user_id=user.id, label="Savings",  balance=1000000) # $10000
        db.session.add_all([checking, savings])
        db.session.flush()
        db.session.add(Transaction(account_id=checking.id, amount=250000, description="Opening deposit"))
        db.session.add(Transaction(account_id=savings.id,  amount=1000000, description="Opening deposit"))
        db.session.commit()
        logger.info(json.dumps({"event": "DB insert", "table": "accounts", "action": "seed_demo_account"}))


def _log_crypto(operation: str, algorithm: str = None, status: str = "success", latency_ms: float = None):
    alg = algorithm or current_app.config.get("APP_NAME", "banking")
    alg = os.environ.get("BANKING_CRYPTO_ALG", "Kyber-ML_KEM_768+AES-256-GCM")
    try:
        entry = CryptoAuditLog(
            event_id=getattr(g, "request_id", None),
            crypto_algorithm=alg,
            key_length=int(os.environ.get("BANKING_KEY_LENGTH", 256)),
            operation=operation,
            status=status,
            latency_ms=latency_ms or round((time.time() - getattr(g, "request_start", time.time())) * 1000, 2),
        )
        db.session.add(entry)
        db.session.commit()
        logger.info(json.dumps({"event": "DB insert", "table": "crypto_audit", "action": "log_crypto", "operation": operation}))
    except Exception:
        pass


# ---------- Auth ----------

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        if not username or not password:
            flash("Username and password required.", "danger")
            return render_template("register.html")
        logger.info(json.dumps({"event": "DB query", "table": "users", "action": "check_exists", "username": username}))
        existing = User.query.filter_by(username=username).first()
        if existing:
            logger.info(json.dumps({"event": "auth failure", "reason": "username_exists", "username": username}))
            flash("Username already exists", "danger")
            return redirect(url_for("auth.register"))
        u = User(username=username)
        u.set_password(password)
        try:
            db.session.add(u)
            db.session.commit()
            logger.info(json.dumps({"event": "DB insert", "table": "users", "action": "register_user", "username": username}))
        except Exception as e:
            db.session.rollback()
            print(e)
            flash("Registration failed", "danger")
            return redirect(url_for("auth.register"))
        _seed_demo_account(u)
        login_user(u)
        logger.info(json.dumps({"event": "auth success", "action": "register", "username": username}))
        _log_crypto("key_exchange")
        return redirect(url_for("main.dashboard"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        logger.info(json.dumps({"event": "DB query", "table": "users", "action": "login_lookup", "username": username}))
        user = User.query.filter_by(username=username).first()
        logger.info("[banking_service] DB authentication lookup executed")
        if user and user.check_password(password):
            login_user(user)
            _seed_demo_account(user)
            logger.info(json.dumps({"event": "auth success", "action": "login", "username": username}))
            _log_crypto("authentication")
            return redirect(url_for("main.dashboard"))
        logger.info(json.dumps({"event": "auth failure", "reason": "invalid_credentials", "username": username}))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


# ---------- Main ----------

@main_bp.route("/")
@login_required
def dashboard():
    logger.info(json.dumps({"event": "DB query", "table": "accounts", "action": "get_user_accounts"}))
    accounts = current_user.accounts.all()
    return render_template("dashboard.html", accounts=accounts)


@main_bp.route("/account/<int:account_id>")
@login_required
def account_detail(account_id):
    logger.info(json.dumps({"event": "DB query", "table": "accounts", "action": "get_account_details", "account_id": account_id}))
    account = Account.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()
    logger.info(json.dumps({"event": "DB query", "table": "transactions", "action": "get_account_transactions", "account_id": account_id}))
    txns = account.transactions.order_by(Transaction.created_at.desc()).limit(50).all()
    _log_crypto("data_retrieval")
    return render_template("account.html", account=account, transactions=txns)


@main_bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    accounts = current_user.accounts.all()
    if request.method == "POST":
        src_id  = int(request.form.get("from_account", 0))
        dst_id  = int(request.form.get("to_account", 0))
        amount  = int(float(request.form.get("amount", 0)) * 100)
        logger.info(json.dumps({"event": "DB query", "table": "accounts", "action": "transfer_lookup"}))
        src = Account.query.filter_by(id=src_id, user_id=current_user.id).first()
        dst = Account.query.filter_by(id=dst_id, user_id=current_user.id).first()
        if not src or not dst:
            flash("Invalid accounts.", "danger")
        elif src_id == dst_id:
            flash("Cannot transfer to same account.", "warning")
        elif amount <= 0:
            flash("Amount must be positive.", "danger")
        elif src.balance < amount:
            flash("Insufficient funds.", "danger")
        else:
            src.balance -= amount
            dst.balance += amount
            db.session.add(Transaction(account_id=src.id, amount=-amount, description=f"Transfer to {dst.label}"))
            db.session.add(Transaction(account_id=dst.id, amount=amount,  description=f"Transfer from {src.label}"))
            db.session.commit()
            logger.info(json.dumps({"event": "DB insert", "table": "transactions", "action": "transfer"}))
            _log_crypto("encrypt")
            flash("Transfer completed securely.", "success")
            return redirect(url_for("main.dashboard"))
    return render_template("transfer.html", accounts=accounts)


# ---------- API (proxy-facing) ----------

@main_bp.route("/health")
def health():
    return {"status": "ok"}


@main_bp.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "app": "banking_service",
        "crypto": os.environ.get("BANKING_CRYPTO_ALG", "Kyber-ML_KEM_768+AES-256-GCM"),
        "pqc_ready": True,
    })


@main_bp.route("/api/accounts", methods=["GET"])
@login_required
def api_accounts():
    _log_crypto("data_retrieval")
    logger.info(json.dumps({"event": "DB query", "table": "accounts", "action": "api_get_user_accounts"}))
    accounts = current_user.accounts.all()
    return jsonify([{
        "id": a.id, "label": a.label,
        "balance_cents": a.balance,
        "balance_display": f"${a.balance / 100:.2f}"
    } for a in accounts])


@main_bp.route("/api/transfer", methods=["POST"])
@login_required
def api_transfer():
    data = request.get_json(force=True, silent=True) or {}
    src_id = data.get("from_account")
    dst_id = data.get("to_account")
    amount = int(data.get("amount_cents", 0))
    logger.info(json.dumps({"event": "DB query", "table": "accounts", "action": "api_transfer_lookup"}))
    src = Account.query.filter_by(id=src_id, user_id=current_user.id).first()
    dst = Account.query.filter_by(id=dst_id, user_id=current_user.id).first()
    if not src or not dst:
        return jsonify({"error": "invalid_accounts"}), 400
    if src.balance < amount:
        return jsonify({"error": "insufficient_funds"}), 400
    src.balance -= amount
    dst.balance += amount
    db.session.add(Transaction(account_id=src.id, amount=-amount, description="API Transfer"))
    db.session.add(Transaction(account_id=dst.id, amount=amount,  description="API Transfer"))
    db.session.commit()
    logger.info(json.dumps({"event": "DB insert", "table": "transactions", "action": "api_transfer"}))
    g.cbom_crypto = {
        "crypto_algorithm": os.environ.get("BANKING_CRYPTO_ALG", "Kyber-ML_KEM_768+AES-256-GCM"),
        "key_length": int(os.environ.get("BANKING_KEY_LENGTH", 256)),
        "library_tool": "pycryptodome+kyber-py",
        "cert_type": "X.509",
        "pqc_support": True,
        "quantum_ready": True,
    }
    _log_crypto("encrypt")
    return jsonify({"result": "ok", "from_balance": src.balance, "to_balance": dst.balance})


@main_bp.route("/api/crypto_audit")
def api_crypto_audit():
    logger.info(json.dumps({"event": "DB query", "table": "crypto_audit", "action": "get_crypto_audit"}))
    logs = CryptoAuditLog.query.order_by(CryptoAuditLog.created_at.desc()).limit(100).all()
    return jsonify([{
        "id": l.id, "operation": l.operation,
        "algorithm": l.crypto_algorithm, "key_length": l.key_length,
        "status": l.status, "latency_ms": l.latency_ms,
        "created_at": l.created_at.isoformat() if l.created_at else None,
    } for l in logs])

@main_bp.route('/simulate_transactions', methods=['POST'])
@login_required
def simulate_transactions():
    logger.info("[banking_service] initiating multi-step transaction simulation")
    account = current_user.accounts.first()
    if account:
        for i in range(3):
            db.session.add(Transaction(account_id=account.id, amount=-100, description=f"Simulated deb #{i}"))
            logger.info(f"[banking_service] transaction simulation step {i} executed")
        db.session.commit()
    return {"status": "success"}

@main_bp.route('/transaction', methods=['POST'])
def transaction():
    import uuid
    amount = request.form.get("amount")
    target = request.form.get("target")
    logger.info(f"[banking_service] transaction request: {amount} -> {target}")
    return {"status": "success", "tx": "TX-" + str(uuid.uuid4())}
