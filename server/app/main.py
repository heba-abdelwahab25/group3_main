from flask import Blueprint, render_template, request, jsonify, current_app, g
from .models import Product, ClientActivity
from . import db
from . import csrf
from flask_login import login_required, current_user
import os
import json

bp = Blueprint("main", __name__)


def _handle_message_payload(data: dict):
    message_type = data.get("type", "unknown")
    client_id = data.get("client_id", "unknown")

    if message_type == "health_check":
        return jsonify({
            "status": "ok",
            "type": "health_response",
            "server": "Flask",
            "timestamp": data.get("timestamp", "")
        })
    elif message_type == "message":
        return jsonify({
            "status": "received",
            "type": "message_response",
            "client_id": client_id,
            "sequence": data.get("sequence", 0),
            "echo": data.get("body", ""),
            "timestamp": data.get("timestamp", "")
        })
    else:
        return jsonify({
            "status": "ok",
            "type": "generic_response",
            "received": data
        })


def _record_activity(activity_type: str, client_id=None, details=None):
    """Ecommerce-side analytics only (no proxy observability UI here)."""
    try:
        resolved_client_id = client_id
        if resolved_client_id is None:
            resolved_client_id = getattr(g, "proxy_client_id", None)
        row = ClientActivity(
            client_id=str(resolved_client_id) if resolved_client_id is not None else None,
            activity_type=str(activity_type or "unknown")[:64],
            details=json.dumps(details or {}),
        )
        db.session.add(row)
        db.session.commit()
    except Exception as e:
        current_app.logger.error("Failed to record client activity: %s", e)

@bp.route("/")
def index():
    # list products in DB
    _record_activity("page_view", details={"path": "/"})
    products = Product.query.all()
    return render_template("index.html", products=products)

@bp.route("/api/products", methods=["GET"])
def api_products():
    # REST endpoint that returns products safely (no raw SQL)
    _record_activity("api_products", details={"path": "/api/products"})
    products = Product.query.all()
    out = [{"id":p.id,"name":p.name,"description":p.description,"price_cents":p.price_cents} for p in products]
    return jsonify(out)

@bp.route("/api/purchase", methods=["POST"])
@login_required
def api_purchase():
    # minimal demo: accept JSON {"product_id": 1}
    data = request.get_json(force=True, silent=True) or {}
    product_id = data.get("product_id")
    if not isinstance(product_id, int):
        return jsonify({"error":"invalid_product_id"}), 400
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"error":"not_found"}), 404
    # simulate purchase logic
    _record_activity(
        "purchase",
        client_id=getattr(current_user, "id", None) if getattr(current_user, "is_authenticated", False) else None,
        details={"product_id": product_id, "proxy_client_id": getattr(g, "proxy_client_id", None)},
    )
    return jsonify({"result":"ok","product":product.name})


@bp.route("/api/debug/csrf", methods=["GET"])
def api_debug_csrf():
    # Debug helper to verify which server instance/config is running.
    try:
        exempt_views = []
        raw_exempt = getattr(csrf, "_exempt_views", set())
        if isinstance(raw_exempt, (set, list, tuple)):
            exempt_views = sorted([str(x) for x in raw_exempt])[:200]
    except Exception:
        exempt_views = []

    return jsonify(
        {
            "wtf_csrf_check_default": bool(current_app.config.get("WTF_CSRF_CHECK_DEFAULT")),
            "wtf_csrf_enabled": current_app.config.get("WTF_CSRF_ENABLED", None),
            "purchase_view": "main.api_purchase",
            "purchase_decorated_exempt": True,
            "csrf_exempt_views_sample": exempt_views,
        }
    )

@bp.route("/api/message", methods=["POST"])
def api_message():
    """Endpoint for proxy to forward client messages - CSRF exempt for internal use"""
    data = request.get_json(force=True, silent=True) or {}
    _record_activity(data.get("type", "message"), client_id=data.get("client_id"), details={"raw": data})
    return _handle_message_payload(data)


@bp.route("/api/message_secure", methods=["POST"])
def api_message_secure():
    body = request.get_json(force=True, silent=True) or {}
    priv_pem = os.getenv("SERVER_RSA_PRIVATE_KEY", "").strip()
    if not priv_pem:
        return jsonify({"error": "missing_server_rsa_private_key"}), 500

    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP, AES

        enc_key = bytes.fromhex(body.get("enc_key", ""))
        nonce = bytes.fromhex(body.get("nonce", ""))
        tag = bytes.fromhex(body.get("tag", ""))
        ciphertext = bytes.fromhex(body.get("ciphertext", ""))

        rsa_key = RSA.import_key(priv_pem)
        aes_key = PKCS1_OAEP.new(rsa_key).decrypt(enc_key)

        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

        data = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        return jsonify({"error": "decrypt_failed", "message": str(e)}), 400

    g.cbom_crypto = {
        "crypto_algorithm": "RSA-OAEP+AES-GCM",
        "key_length": 2048,
        "library_tool": "pycryptodome",
        "cert_type": "None",
        "pqc_support": False,
        "quantum_ready": False,
    }

    _record_activity(data.get("type", "message"), client_id=data.get("client_id"), details={"raw": data, "secure_channel": True})

    return _handle_message_payload(data)

