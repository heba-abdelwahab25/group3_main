# hybrid_proxy.py
import asyncio
import base64
import hashlib
import json
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urljoin
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from typing import Optional
import re

import requests
try:
    import dpkt
except ImportError:
    dpkt = None

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from certificate_manager import (
    CertificateManager,
    FileCertificateSource,
    HTTPSCertificateSource,
    VaultPKICertificateSource,
)
from config import (
    AUDIT_LOG_PATH,
    BUFFER_SIZE,
    CA_FILE_PATH,
    CERT_FILE_PATH,
    KEY_FILE_PATH,
    CERT_FORCE_ROTATION_SECONDS,
    CERT_REFRESH_SECONDS,
    CERT_STORAGE_BACKEND,
    CLIENT_CA_FILE,
    LOG_LEVEL,
    LOG_SENSITIVE_DATA,
    MAX_MESSAGE_SIZE,
    PROXY_CHROOT_PATH,
    PROXY_HOST,
    PROXY_PORT,
    PROXY_SERVICE_GROUP,
    PROXY_SERVICE_USER,
    REQUIRE_CLIENT_CERT,
    SDS_ENDPOINT,
    SDS_TOKEN,
    SDS_VERIFY_TLS,
    SERVER_HOST,
    SERVER_PORT,
    SESSION_TIMEOUT,
    TLS_CIPHER_SUITES,
    TLS_MIN_VERSION,
    USE_SSL,
    VAULT_ADDR,
    VAULT_ALT_NAMES,
    VAULT_COMMON_NAME,
    VAULT_MOUNT_POINT,
    VAULT_PKI_ROLE,
    VAULT_TTL,
    VAULT_TOKEN,
)
from session_manager import SessionManager, SessionStatus

_observer_use_ssl = (
    os.getenv("OBSERVER_USE_SSL", "").strip().lower() in {"1", "true", "yes", "on"}
    or os.getenv("PROXY_OBSERVER_USE_SSL", "").strip().lower() in {"1", "true", "yes", "on"}
    or os.getenv("PROXY_USE_SSL", "").strip().lower() in {"1", "true", "yes", "on"}
)
_default_observer_scheme = "https" if _observer_use_ssl else "http"
OBSERVER_URL = os.getenv("OBSERVER_URL", f"{_default_observer_scheme}://127.0.0.1:5600/api/telemetry")
TELEMETRY_ENDPOINT = os.getenv("PROXY_TELEMETRY_URL") or OBSERVER_URL
TELEMETRY_TOKEN = os.getenv("TELEMETRY_INGEST_TOKEN", "").strip()
CBOM_ENDPOINT = os.getenv("PROXY_CBOM_URL", f"{_default_observer_scheme}://127.0.0.1:5600/api/cboom/events").strip()
SIEM_ENDPOINT = os.getenv("PROXY_SIEM_URL", f"{_default_observer_scheme}://127.0.0.1:5600/api/siem/ingest/proxy").strip()

def _should_verify_observer_tls(url: str) -> bool:
    explicit = os.getenv("PROXY_OBSERVER_VERIFY_TLS")
    if explicit is not None and explicit.strip() != "":
        return explicit.strip().lower() in {"1", "true", "yes", "on"}
    u = (url or "").strip().lower()
    if u.startswith("https://127.0.0.1") or u.startswith("https://localhost"):
        return False
    return True


def _maybe_suppress_insecure_warning(url: str) -> None:
    if _should_verify_observer_tls(url):
        return
    u = (url or "").strip().lower()
    if u.startswith("https://127.0.0.1") or u.startswith("https://localhost"):
        urllib3.disable_warnings(InsecureRequestWarning)
CAPTURE_PCAP = os.getenv("PROXY_CAPTURE_PCAP", "0").strip().lower() in {"1", "true", "yes", "on"}
PCAP_PATH = os.getenv("PROXY_PCAP_PATH", str(Path(__file__).parent / "logs" / "proxy_capture.pcap"))
PCAP_MAX_BYTES = int(os.getenv("PROXY_PCAP_MAX_BYTES", str(20 * 1024 * 1024)))  # 20MB

# --------------------------
# PQC: Kyber
# --------------------------
try:
    from kyber_py.ml_kem import ML_KEM_512 as MLKEM512
    USE_KYBER_PY = True
    logging.info("Using kyber-py (ML_KEM_512) for Kyber PQC.")
except ImportError:
    USE_KYBER_PY = False
    logging.warning("kyber-py not installed. PQC handshake will fallback to RSA.")

logger = logging.getLogger("proxy")
audit_logger = logging.getLogger("proxy.audit")

_last_telemetry_warn_ts = 0.0
_last_cbom_warn_ts = 0.0
_last_siem_warn_ts = 0.0

http_sessions = {}
session_writers = {}
main_loop: Optional[asyncio.AbstractEventLoop] = None
session_manager = SessionManager()

CONTROL_HOST = os.getenv("PROXY_CONTROL_HOST", "127.0.0.1")
CONTROL_PORT = int(os.getenv("PROXY_CONTROL_PORT", "7443"))
CONTROL_REQUIRE_MTLS = os.getenv("PROXY_CONTROL_REQUIRE_MTLS", "true").strip().lower() in {"1", "true", "yes", "on"}
CONTROL_CA_FILE = os.getenv("PROXY_CONTROL_CA_FILE", CLIENT_CA_FILE or CA_FILE_PATH)

def configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    if AUDIT_LOG_PATH:
        path = Path(AUDIT_LOG_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

def send_telemetry(event_type: str, severity: str = "info", session_id=None, client_id=None, details=None):
    """Ship a lightweight event to the Flask dashboard; failure is non-fatal."""
    if not TELEMETRY_ENDPOINT:
        return
    try:
        _maybe_suppress_insecure_warning(TELEMETRY_ENDPOINT)
        payload = {
            "component": "proxy",
            "event_type": event_type,
            "severity": severity,
            "session_id": session_id,
            "client_id": client_id,
            "details": details or {},
            "timestamp": time.time(),
        }
        headers = {}
        if TELEMETRY_TOKEN:
            headers["Authorization"] = f"Bearer {TELEMETRY_TOKEN}"
            headers["X-Telemetry-Token"] = TELEMETRY_TOKEN
        requests.post(
            TELEMETRY_ENDPOINT,
            json=payload,
            headers=headers,
            timeout=2,
            verify=_should_verify_observer_tls(TELEMETRY_ENDPOINT),
        )
    except Exception as exc:
        global _last_telemetry_warn_ts
        now = time.monotonic()
        if (now - _last_telemetry_warn_ts) > 10.0:
            _last_telemetry_warn_ts = now
            logger.warning("Telemetry post failed to %s: %s", TELEMETRY_ENDPOINT, exc)


def _algo_crypto_meta(algo: str | None) -> dict:
    a = str(algo or "").strip().lower()
    if a == "kyber":
        return {
            "crypto_algorithm": "Kyber", 
            "key_length": 1024, 
            "pqc_support": True, 
            "quantum_ready": True,
            "library_tool": "kyber-py",
            "cert_type": "None"
        }
    if a == "rsa":
        return {
            "crypto_algorithm": "RSA", 
            "key_length": 2048, 
            "pqc_support": False, 
            "quantum_ready": False,
            "library_tool": "pycryptodome",
            "cert_type": "X.509"
        }
    return {
        "crypto_algorithm": (algo or None), 
        "key_length": None, 
        "pqc_support": None, 
        "quantum_ready": None,
        "library_tool": "unknown",
        "cert_type": "None"
    }


def send_cbom_event(
    *,
    source_component: str,
    destination_component: str,
    communication_protocol: str,
    message_type: str,
    status: str,
    crypto: dict | None = None,
    api_endpoint: str | None = None,
    client_token_id: str | None = None,
    latency_ms: float | int | None = None,
    payload_summary: dict | None = None,
    error_details: dict | None = None,
    trace_id: str | None = None,
):
    if not CBOM_ENDPOINT:
        return
    try:
        _maybe_suppress_insecure_warning(CBOM_ENDPOINT)
        payload = {
            "event_id": str(uuid.uuid4()),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z",
            "source_component": source_component,
            "destination_component": destination_component,
            "communication_protocol": communication_protocol,
            "message_type": message_type,
            "status": status,
            "payload_summary": payload_summary or {},
            "crypto": crypto or {},
            "api_endpoint": api_endpoint,
            "client_token_id": client_token_id,
            "latency_ms": latency_ms,
            "error_details": error_details,
            "trace_id": trace_id,
        }
        headers = {"Content-Type": "application/json"}
        if TELEMETRY_TOKEN:
            headers["Authorization"] = f"Bearer {TELEMETRY_TOKEN}"
            headers["X-Observer-Token"] = TELEMETRY_TOKEN
        requests.post(
            CBOM_ENDPOINT,
            json=payload,
            headers=headers,
            timeout=2,
            verify=_should_verify_observer_tls(CBOM_ENDPOINT),
        )
    except Exception as exc:
        global _last_cbom_warn_ts
        now = time.monotonic()
        if (now - _last_cbom_warn_ts) > 10.0:
            _last_cbom_warn_ts = now
            logger.warning("CBOM post failed to %s: %s", CBOM_ENDPOINT, exc)


def send_siem_event(*, event: dict):
    if not SIEM_ENDPOINT:
        return
    try:
        _maybe_suppress_insecure_warning(SIEM_ENDPOINT)
        headers = {"Content-Type": "application/json"}
        if TELEMETRY_TOKEN:
            headers["Authorization"] = f"Bearer {TELEMETRY_TOKEN}"
            headers["X-Observer-Token"] = TELEMETRY_TOKEN
        requests.post(
            SIEM_ENDPOINT,
            json=event,
            headers=headers,
            timeout=2,
            verify=_should_verify_observer_tls(SIEM_ENDPOINT),
        )
    except Exception as exc:
        global _last_siem_warn_ts
        now = time.monotonic()
        if (now - _last_siem_warn_ts) > 10.0:
            _last_siem_warn_ts = now
            logger.warning("SIEM post failed to %s: %s", SIEM_ENDPOINT, exc)


def _build_siem_event(
    *,
    event_type: str,
    source_component: str,
    destination_component: str | None = None,
    protocol: str | None = None,
    algorithm: str | None = None,
    key_length: int | None = None,
    pqc_ready: bool | None = None,
    tls_version: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    data_classification: str | None = None,
    harvestable: bool | None = None,
    quantum_risk_score: float | None = None,
    raw_event_ref: str | None = None,
    extra: dict | None = None,
):
    evt = {
        "event_id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z",
        "event_type": str(event_type),
        "source": {"component": str(source_component)},
        "destination": {"component": str(destination_component)} if destination_component else {},
        "connection": {
            "protocol": str(protocol) if protocol else None,
            "crypto": {
                "algorithm": algorithm,
                "key_length": key_length,
                "pqc_ready": pqc_ready,
                "tls_version": tls_version,
            },
        },
        "data_classification": data_classification,
        "quantum_risk": {"harvestable": harvestable, "risk_score": quantum_risk_score},
        "status": status,
        "severity": severity,
        "raw_event_ref": raw_event_ref,
    }
    if extra and isinstance(extra, dict):
        evt["extra"] = extra
    return evt

class PcapRecorder:
    """Very lightweight pcap writer for proxy traffic (synthetic headers)."""

    def __init__(self, path: str, enabled: bool, max_bytes: int):
        self.enabled = enabled and dpkt is not None
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.writer = None
        if self.enabled:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.fp = open(self.path, "wb")
                self.writer = dpkt.pcap.Writer(self.fp)
                self.bytes_written = 0
                logger.info("PCAP capture enabled at %s", self.path)
            except Exception as exc:
                logger.warning("PCAP capture disabled (init error): %s", exc)
                self.enabled = False

    def _write(self, payload: bytes, src="10.0.0.1", dst="10.0.0.2", sport=40000, dport=7000, proto=6):
        if not self.enabled or not self.writer:
            return
        try:
            import socket

            ts = time.time()
            ip = dpkt.ip.IP(
                src=socket.inet_aton(src),
                dst=socket.inet_aton(dst),
                p=proto,
                len=20 + 20 + len(payload),
                ttl=64,
            )
            tcp = dpkt.tcp.TCP(
                sport=sport,
                dport=dport,
                seq=0,
                ack=0,
                flags=dpkt.tcp.TH_ACK,
                data=payload,
            )
            ip.data = tcp
            eth = dpkt.ethernet.Ethernet(
                src=b"\x00\x11\x22\x33\x44\x55",
                dst=b"\x66\x77\x88\x99\xaa\xbb",
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
            raw = bytes(eth)
            self.writer.writepkt(raw, ts=ts)
            self.bytes_written += len(raw)
            if self.bytes_written > self.max_bytes:
                logger.warning("PCAP capture reached max_bytes; stopping capture.")
                self.enabled = False
                try:
                    self.fp.close()
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("PCAP write failed: %s", exc)

sessions = {}  # session_id -> shared_secret
pcap_recorder = PcapRecorder(PCAP_PATH, CAPTURE_PCAP, PCAP_MAX_BYTES)

# --------------------------
# AES-GCM helpers
# --------------------------
def aes_encrypt(key, plaintext):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def aes_decrypt(key, data):
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def rsa_aesgcm_encrypt_for_server(server_rsa_pub_pem: str, plaintext: bytes) -> dict:
    server_key = RSA.import_key(server_rsa_pub_pem)
    aes_key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
    cipher_rsa = PKCS1_OAEP.new(server_key)
    enc_key = cipher_rsa.encrypt(aes_key)
    return {
        "enc_key": enc_key.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
    }


# --------------------------
# Kyber handshake
# --------------------------
def pqc_handshake_kyber(client_pub_key_bytes: bytes):
    if not USE_KYBER_PY:
        raise RuntimeError("kyber-py not available")
    shared_secret, ciphertext = MLKEM512.encaps(client_pub_key_bytes)
    if not isinstance(shared_secret, bytes):
        shared_secret = bytes(shared_secret)
    if not isinstance(ciphertext, bytes):
        ciphertext = bytes(ciphertext)
    logger.debug(
        "Kyber handshake: shared_secret=%d bytes, ciphertext=%d bytes",
        len(shared_secret),
        len(ciphertext),
    )
    # Generate a dummy 800-byte proxy public key so client always receives something
    proxy_pub_key = get_random_bytes(800)
    return proxy_pub_key, shared_secret, ciphertext


# --------------------------
# RSA handshake fallback
# --------------------------
def rsa_handshake(client_pub_key_bytes: bytes):
    client_rsa = RSA.import_key(client_pub_key_bytes)
    shared_secret = get_random_bytes(32)
    cipher_rsa = PKCS1_OAEP.new(client_rsa)
    ciphertext = cipher_rsa.encrypt(shared_secret)
    # Generate a dummy proxy key for RSA as well
    proxy_pub_key = get_random_bytes(294)
    return proxy_pub_key, shared_secret, ciphertext


# --------------------------
# Handshake router
# --------------------------
def perform_handshake(client_hello: dict):
    algos = client_hello.get("algos", [])
    crypto = client_hello.get("crypto", "")
    client_pub_key_raw = client_hello.get("client_pub_key") or client_hello.get("pub_key")

    # Normalize client hello fields for backwards compatibility.
    # Some clients send: {"crypto": "RSA"}
    # Others send: {"crypto": ["Kyber", "RSA"]}
    # Others send: {"algos": ["Kyber", "RSA"]}
    if isinstance(crypto, list):
        # Treat list-valued "crypto" as algorithms if algos wasn't provided.
        if not algos:
            algos = crypto
        crypto = ""
    elif crypto is None:
        crypto = ""

    if algos is None:
        algos = []

    if client_pub_key_raw is None:
        raise ValueError("client_pub_key or pub_key missing in client hello")

    try:
        client_pub_key_bytes = bytes.fromhex(client_pub_key_raw)
        is_hex_encoded = True
    except (ValueError, TypeError):
        client_pub_key_bytes = client_pub_key_raw.encode() if isinstance(client_pub_key_raw, str) else client_pub_key_raw
        is_hex_encoded = False

    crypto_lower = crypto.lower() if isinstance(crypto, str) and crypto else ""
    algos_lower = [str(a).lower() for a in algos] if algos else []
    is_likely_kyber_key = is_hex_encoded and len(client_pub_key_bytes) == 800
    client_wants_kyber = (
        "kyber" in algos_lower
        or "pqckyber" in algos_lower
        or crypto_lower == "pqckyber"
        or crypto_lower == "kyber"
        or (not crypto and not algos and is_likely_kyber_key)
    )

    if USE_KYBER_PY and client_wants_kyber:
        logger.info("Using Kyber for handshake (crypto=%s, algos=%s)", crypto, algos)
        proxy_pub_key, shared_secret, ciphertext = pqc_handshake_kyber(client_pub_key_bytes)
        return "kyber", proxy_pub_key, shared_secret, ciphertext, client_pub_key_bytes

    if "rsa" in algos_lower or crypto_lower == "rsa":
        logger.info("Using RSA for handshake (crypto=%s, algos=%s)", crypto, algos)
        proxy_pub_key, shared_secret, ciphertext = rsa_handshake(client_pub_key_bytes)
        return "rsa", proxy_pub_key, shared_secret, ciphertext, client_pub_key_bytes

    if USE_KYBER_PY:
        logger.info("Defaulting to Kyber (crypto=%s, algos=%s)", crypto, algos)
        proxy_pub_key, shared_secret, ciphertext = pqc_handshake_kyber(client_pub_key_bytes)
        return "kyber", proxy_pub_key, shared_secret, ciphertext, client_pub_key_bytes

    raise RuntimeError("No mutually supported key exchange algorithm available")


# --------------------------
# Client handler
# --------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    ssl_obj = writer.get_extra_info("ssl_object")
    tls_meta = {}
    try:
        if ssl_obj is not None:
            tls_meta["tls_version"] = ssl_obj.version()
            cipher = ssl_obj.cipher()
            if cipher and len(cipher) >= 1:
                tls_meta["cipher_suite"] = cipher[0]
    except Exception:
        tls_meta = {}
    logger.info("Connection from %s", addr)
    session_id = None
    message = None
    node_id = None

    try:
        length_bytes = await reader.readexactly(4)
        message_length = int.from_bytes(length_bytes, "big")
        if message_length > MAX_MESSAGE_SIZE:
            if len(length_bytes) >= 2 and length_bytes[0] == 0x16 and length_bytes[1] == 0x03:
                raise ValueError(
                    "Received TLS ClientHello on a non-TLS proxy port. Enable TLS on the proxy (PROXY_USE_SSL=true) and connect with TLS."
                )
            raise ValueError("Handshake exceeds allowed size")
        data = await reader.readexactly(message_length)
        message = json.loads(data.decode())

        if LOG_SENSITIVE_DATA:
            logger.debug("Received handshake message keys: %s", list(message.keys()))

        selected_alg, proxy_pub_key, shared_secret, ciphertext, client_pub_key_bytes = perform_handshake(message)
        session_key = hashlib.sha256(shared_secret).digest()

        # Ensure bytes
        proxy_pub_key = bytes(proxy_pub_key)
        ciphertext = bytes(ciphertext)
        
        node_id = message.get("node_id") if isinstance(message, dict) else None
        session_id = session_manager.create_session(
            client_addr=addr,
            crypto_method=selected_alg,
            crypto_engine=None,
            proxy_pub_key=proxy_pub_key,
            proxy_sec_key=shared_secret,
            client_pub_key=client_pub_key_bytes,
            node_id=node_id,
        )
        sessions[session_id] = session_key
        session_writers[session_id] = writer
        session_manager.update_session_status(session_id, SessionStatus.ACTIVE)
        session_started = time.monotonic()

        response = {
            "status": "ok",
            "session_id": session_id,
            "node_id": node_id,
            "algorithm": selected_alg,
            "proxy_pub_key": proxy_pub_key.hex(),
            "ciphertext": ciphertext.hex(),
        }

        response_json = json.dumps(response).encode()
        response_length = len(response_json).to_bytes(4, "big")
        writer.write(response_length + response_json)
        await writer.drain()
        logger.info("Handshake finished for session %s using %s", session_id, selected_alg)
        audit_logger.info("session=%s algorithm=%s status=ok", session_id, selected_alg)
        await asyncio.to_thread(
            send_telemetry,
            "handshake",
            "info",
            session_id=session_id,
            details={"algorithm": selected_alg, "peer": str(addr)},
        )
        await asyncio.to_thread(
            send_cbom_event,
            source_component=f"client-{node_id}" if node_id else "client",
            destination_component="proxy",
            communication_protocol="custom",
            message_type="handshake_success",
            status="success",
            crypto={**_algo_crypto_meta(selected_alg), **tls_meta},
            client_token_id=selected_alg,
            payload_summary={"peer": str(addr), "session_id": session_id, "node_id": node_id},
        )
        await asyncio.to_thread(
            send_siem_event,
            event=_build_siem_event(
                event_type="crypto",
                source_component="proxy",
                destination_component="client",
                protocol="CUSTOM",
                algorithm=_algo_crypto_meta(selected_alg).get("crypto_algorithm"),
                key_length=_algo_crypto_meta(selected_alg).get("key_length"),
                pqc_ready=_algo_crypto_meta(selected_alg).get("quantum_ready"),
                harvestable=str(selected_alg or "").strip().lower() == "rsa",
                status="success",
                severity="info",
                raw_event_ref=str(session_id),
                extra={"handshake": "success", "peer": str(addr), "session_id": session_id, "selected_alg": selected_alg},
            ),
        )

    except asyncio.IncompleteReadError as e:
        logger.info("Client disconnected during handshake: %s", e)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return

    except Exception as e:
        import traceback

        if isinstance(e, OSError) and getattr(e, "winerror", None) == 64:
            logger.info("Client disconnected during handshake: %s", e)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        logger.error("Handshake error: %s", e)
        logger.debug("Handshake details: %s", traceback.format_exc())
        safe_node_id = None
        try:
            safe_node_id = node_id
            if safe_node_id is None and isinstance(message, dict):
                safe_node_id = message.get("node_id")
        except Exception:
            safe_node_id = None
        await asyncio.to_thread(
            send_cbom_event,
            source_component="client",
            destination_component="proxy",
            communication_protocol="custom",
            message_type="handshake_failure",
            status="failure",
            payload_summary={"peer": str(addr), "node_id": safe_node_id},
            error_details={"error": str(e)},
        )
        await asyncio.to_thread(
            send_siem_event,
            event=_build_siem_event(
                event_type="crypto",
                source_component="proxy",
                destination_component="client",
                protocol="CUSTOM",
                status="fail",
                severity="warning",
                extra={"handshake": "failure", "peer": str(addr), "error": str(e)},
            ),
        )
        try:
            error_response = {"status": "error", "message": str(e)}
            error_json = json.dumps(error_response).encode()
            error_length = len(error_json).to_bytes(4, "big")
            writer.write(error_length + error_json)
            await writer.drain()
        except:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError) as close_err:
            logger.info("Client disconnected during shutdown: %s", close_err)
        except OSError as close_err:
            if getattr(close_err, "winerror", None) == 64:
                logger.info("Client disconnected during shutdown: %s", close_err)
            else:
                raise
        return

    server_rsa_pub = os.getenv("SERVER_RSA_PUBLIC_KEY", "").strip()
    backend_path = "/api/message_secure" if server_rsa_pub else "/api/message"
    backend_use_ssl = str(os.getenv("PROXY_BACKEND_USE_SSL", "1") or "").strip().lower() in {"1", "true", "yes", "on"}
    backend_scheme = "https" if backend_use_ssl else "http"
    verify_backend_tls = True
    if backend_use_ssl:
        verify_backend_tls = str(os.getenv("PROXY_BACKEND_VERIFY_TLS", "0") or "").strip().lower() in {"1", "true", "yes", "on"}

    backend_url = f"{backend_scheme}://{SERVER_HOST}:{SERVER_PORT}{backend_path}"
    logger.info("Session %s forwarding to backend %s", session_id, backend_url)

    http_session = requests.Session()
    try:
        http_session.verify = verify_backend_tls
    except Exception:
        pass
    http_sessions[session_id] = http_session
    http_base_url = f"{backend_scheme}://{SERVER_HOST}:{SERVER_PORT}"

    def _send_http_request(request_payload: dict):
        method = str(request_payload.get("method", "GET")).upper()
        path = str(request_payload.get("path", "/"))
        headers = request_payload.get("headers") or {}
        body_b64 = request_payload.get("body_base64")

        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            return {
                "type": "http_response",
                "status": 400,
                "url": None,
                "headers": {"Content-Type": "text/plain"},
                "body_base64": base64.b64encode(b"Unsupported HTTP method").decode("ascii"),
            }
        if not path.startswith("/") or ".." in path:
            return {
                "type": "http_response",
                "status": 400,
                "url": None,
                "headers": {"Content-Type": "text/plain"},
                "body_base64": base64.b64encode(b"Invalid HTTP path").decode("ascii"),
            }

        url = urljoin(http_base_url, path)

        body = None
        if body_b64 is not None:
            body = base64.b64decode(body_b64)

        outbound_headers = {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k is None or v is None:
                    continue
                outbound_headers[str(k)] = str(v)
        proxy_client_id = str(request_payload.get("client_id") or "").strip()
        if not proxy_client_id:
            proxy_client_id = f"session-{session_id}"
        outbound_headers.setdefault("X-Proxy-Client-Id", proxy_client_id)

        resp = http_session.request(
            method,
            url,
            headers=outbound_headers,
            data=body,
            allow_redirects=True,
            timeout=10,
            verify=verify_backend_tls,
        )

        resp_body = resp.content if resp.content is not None else b""
        return {
            "type": "http_response",
            "status": resp.status_code,
            "url": resp.url,
            "headers": dict(resp.headers),
            "body_base64": base64.b64encode(resp_body).decode("ascii"),
        }

    # Proxy loop
    while True:
        try:
            if time.monotonic() - session_started > SESSION_TIMEOUT:
                logger.info("Session %s expired after %ss", session_id, SESSION_TIMEOUT)
                break

            length_bytes = await reader.readexactly(4)
            frame_len = int.from_bytes(length_bytes, "big")
            if frame_len <= 0 or frame_len > MAX_MESSAGE_SIZE:
                raise ValueError("Invalid frame length")
            enc_data = await reader.readexactly(frame_len)

            plaintext = aes_decrypt(session_key, enc_data)
            try:
                session = session_manager.get_session(session_id)
                if session:
                    session.update_activity()
            except Exception:
                pass
            if pcap_recorder.enabled:
                pcap_recorder._write(enc_data, src="10.0.0.100", dst="10.0.0.2", sport=50000 + session_id, dport=PROXY_PORT)
            logger.debug("Session %s received %d bytes from client", session_id, len(plaintext))

            try:
                payload = json.loads(plaintext.decode("utf-8"))
            except Exception:
                payload = {"type": "binary", "payload": plaintext.hex()}

            def _post_to_backend():
                started = time.monotonic()
                if payload.get("type") == "http_request":
                    result = _send_http_request(payload)
                    result["latency_ms"] = round((time.monotonic() - started) * 1000.0, 3)
                    return result
                if server_rsa_pub:
                    secure_blob = rsa_aesgcm_encrypt_for_server(server_rsa_pub, json.dumps(payload).encode("utf-8"))
                    resp = requests.post(backend_url, json=secure_blob, timeout=10, verify=verify_backend_tls)
                    setattr(resp, "_proxy_latency_ms", round((time.monotonic() - started) * 1000.0, 3))
                    return resp
                resp = requests.post(backend_url, json=payload, timeout=10, verify=verify_backend_tls)
                setattr(resp, "_proxy_latency_ms", round((time.monotonic() - started) * 1000.0, 3))
                return resp

            resp = await asyncio.to_thread(_post_to_backend)
            if isinstance(resp, dict):
                server_response = json.dumps(resp).encode("utf-8")
                status_code = resp.get("status")
                latency_ms = resp.get("latency_ms")
            else:
                server_response = resp.content
                status_code = resp.status_code
                latency_ms = getattr(resp, "_proxy_latency_ms", None)

            out_frame = aes_encrypt(session_key, server_response)
            writer.write(len(out_frame).to_bytes(4, "big") + out_frame)
            await writer.drain()
            if pcap_recorder.enabled:
                pcap_recorder._write(out_frame, src="10.0.0.2", dst="10.0.0.100", sport=PROXY_PORT, dport=50000 + session_id)
            await asyncio.to_thread(
                send_telemetry,
                "message_forwarded",
                "info",
                session_id=session_id,
                client_id=payload.get("client_id"),
                details={
                    "status_code": status_code,
                    "payload_type": payload.get("type"),
                    "path": payload.get("path"),
                    "method": payload.get("method"),
                    "latency_ms": latency_ms,
                },
            )

            try:
                sess = session_manager.get_session(session_id)
                algo = sess.crypto_method if sess else None
                node_id = sess.node_id if sess else None
            except Exception:
                algo = None
                node_id = None

            proto = "https" if str(backend_url).lower().startswith("https") else "http"
            cbom_status = "success"
            try:
                if status_code is not None and int(status_code) >= 400:
                    cbom_status = "failure"
            except Exception:
                pass
            await asyncio.to_thread(
                send_cbom_event,
                source_component=f"client-{node_id}" if node_id else "client",
                destination_component="proxy",
                communication_protocol="custom",
                message_type="client_message",
                status="success",
                crypto=_algo_crypto_meta(algo),
                client_token_id=algo,
                payload_summary={"session_id": session_id, "node_id": node_id},
            )

            await asyncio.to_thread(
                send_cbom_event,
                source_component="proxy",
                destination_component="backend",
                communication_protocol=proto.upper(),
                message_type="request",
                status=cbom_status,
                crypto=_algo_crypto_meta(algo),
                api_endpoint=str(payload.get("path") or "")[:255] or None,
                client_token_id=algo,
                latency_ms=latency_ms,
                payload_summary={
                    "method": payload.get("method"),
                    "status_code": status_code,
                    "payload_type": payload.get("type"),
                    "session_id": session_id,
                    "node_id": node_id,
                },
            )

            await asyncio.to_thread(
                send_siem_event,
                event=_build_siem_event(
                    event_type="network",
                    source_component="proxy",
                    destination_component="backend",
                    protocol=proto.upper(),
                    algorithm=_algo_crypto_meta(algo).get("crypto_algorithm"),
                    key_length=_algo_crypto_meta(algo).get("key_length"),
                    pqc_ready=_algo_crypto_meta(algo).get("quantum_ready"),
                    status="success" if cbom_status == "success" else "fail",
                    severity="info" if cbom_status == "success" else "warning",
                    raw_event_ref=str(session_id),
                    extra={
                        "path": payload.get("path"),
                        "method": payload.get("method"),
                        "status_code": status_code,
                        "latency_ms": latency_ms,
                        "payload_type": payload.get("type"),
                    },
                ),
            )

        except asyncio.IncompleteReadError:
            break
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.info("Client disconnected for session %s: %s", session_id, e)
            break
        except OSError as e:
            if getattr(e, "winerror", None) == 64:
                logger.info("Client disconnected for session %s: %s", session_id, e)
                break
            raise
        except Exception as e:
            if isinstance(e, OSError) and getattr(e, "winerror", None) == 64:
                logger.info("Client disconnected for session %s: %s", session_id, e)
                break
            logger.error("Error in session %s: %s", session_id, e)
            try:
                session_manager.update_session_status(session_id, SessionStatus.ERROR)
            except Exception:
                pass
            await asyncio.to_thread(
                send_telemetry,
                "proxy_error",
                "error",
                session_id=session_id,
                details={"error": str(e)},
            )
            await asyncio.to_thread(
                send_cbom_event,
                source_component="proxy",
                destination_component="backend",
                communication_protocol="custom",
                message_type="proxy_error",
                status="failure",
                payload_summary={"session_id": session_id},
                error_details={"error": str(e)},
            )
            await asyncio.to_thread(
                send_siem_event,
                event=_build_siem_event(
                    event_type="telemetry",
                    source_component="proxy",
                    destination_component="backend",
                    protocol="CUSTOM",
                    status="fail",
                    severity="critical",
                    raw_event_ref=str(session_id),
                    extra={"proxy_error": True, "error": str(e)},
                ),
            )
            break

    logger.info("Connection closed for session %s", session_id)
    try:
        session_manager.update_session_status(session_id, SessionStatus.CLOSED)
    except Exception:
        pass
    await asyncio.to_thread(
        send_telemetry,
        "session_closed",
        "info",
        session_id=session_id,
    )
    sessions.pop(session_id, None)
    http_sessions.pop(session_id, None)
    session_writers.pop(session_id, None)
    try:
        session_manager.remove_session(session_id)
    except Exception:
        pass
    writer.close()
    try:
        await writer.wait_closed()
    except ssl.SSLError as exc:
        msg = str(exc)
        if "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" not in msg and "EOF" not in msg and "UNEXPECTED_EOF" not in msg:
            raise
    except (ConnectionResetError, BrokenPipeError):
        pass


def _build_control_tls_context(cert_manager: CertificateManager) -> ssl.SSLContext:
    # Reuse the proxy certificate bundle for the control plane.
    # CertificateManager already knows how to materialize the bundle into an SSLContext.
    ctx = cert_manager.build_context()

    if CONTROL_REQUIRE_MTLS:
        ctx.verify_mode = ssl.CERT_REQUIRED
        repo_default_ca = Path(__file__).resolve().parent / "ca" / "ca.crt"
        candidates = [CONTROL_CA_FILE, CLIENT_CA_FILE, CA_FILE_PATH, str(repo_default_ca)]
        ca_loaded = False
        for candidate in candidates:
            if not candidate:
                continue
            try:
                if not Path(str(candidate)).exists():
                    continue
                ctx.load_verify_locations(cafile=str(candidate))
                ca_loaded = True
                break
            except Exception:
                continue
        if not ca_loaded:
            raise RuntimeError(
                f"Failed to load any control plane CA file (CONTROL_CA_FILE={CONTROL_CA_FILE}, CLIENT_CA_FILE={CLIENT_CA_FILE}, CA_FILE_PATH={CA_FILE_PATH})"
            )
    else:
        ctx.verify_mode = ssl.CERT_NONE

    ctx.check_hostname = False
    return ctx


class _ControlHandler(BaseHTTPRequestHandler):
    server_version = "ProxyControl/1.0"

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args):
        logger.info("[control] %s - %s", self.address_string(), format % args)

    def do_GET(self):
        if self.path == "/control/sessions":
            try:
                payload = {"sessions": list(session_manager.list_sessions().values())}
            except Exception as exc:
                self._send_json(500, {"error": "session_list_failed", "message": str(exc)})
                return
            self._send_json(200, payload)
            return

        m = re.match(r"^/control/sessions/(\d+)$", self.path)
        if m:
            sid = int(m.group(1))
            sess = session_manager.get_session(sid)
            if not sess:
                self._send_json(404, {"error": "not_found", "session_id": sid})
                return
            self._send_json(
                200,
                {
                    "session": {
                        "client_id": sess.client_id,
                        "address": sess.client_addr,
                        "crypto": sess.crypto_method,
                        "status": sess.status.value,
                        "created_at": sess.created_at,
                        "last_activity": sess.last_activity,
                    }
                },
            )
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        m = re.match(r"^/control/sessions/(\d+)/(force_close|rekey)$", self.path)
        if not m:
            self._send_json(404, {"error": "not_found"})
            return
        sid = int(m.group(1))
        action = m.group(2)

        if action == "force_close":
            ok = _force_close_session(sid)
            self._send_json(200 if ok else 404, {"ok": ok, "session_id": sid, "action": "force_close"})
            return
        if action == "rekey":
            ok = _request_rekey(sid)
            self._send_json(200 if ok else 404, {"ok": ok, "session_id": sid, "action": "rekey"})
            return


def _force_close_session(session_id: int) -> bool:
    writer = session_writers.get(session_id)
    if not writer:
        return False
    if main_loop:
        main_loop.call_soon_threadsafe(writer.close)
    audit_logger.info("control session=%s action=force_close", session_id)
    try:
        send_telemetry("session_force_closed", "warn", session_id=session_id, details={"action": "force_close"})
    except Exception:
        pass
    return True


def _request_rekey(session_id: int) -> bool:
    if session_id not in sessions:
        return False
    audit_logger.info("control session=%s action=rekey", session_id)
    try:
        send_telemetry("session_rekey_requested", "info", session_id=session_id, details={"action": "rekey"})
    except Exception:
        pass
    return True


def _start_control_plane(cert_manager: CertificateManager) -> None:
    ctx = _build_control_tls_context(cert_manager)
    httpd = ThreadingHTTPServer((CONTROL_HOST, CONTROL_PORT), _ControlHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    logger.info("Control plane listening on https://%s:%s (mTLS=%s)", CONTROL_HOST, CONTROL_PORT, CONTROL_REQUIRE_MTLS)
    httpd.serve_forever()


# --------------------------
# TLS / SSL helpers
# --------------------------
def build_certificate_manager() -> CertificateManager:
    backend = CERT_STORAGE_BACKEND.lower()
    if backend == "vault":
        if not (VAULT_ADDR and VAULT_TOKEN):
            raise RuntimeError(
                "CERT_STORAGE_BACKEND=vault requires VAULT_ADDR and VAULT_TOKEN (or successful AppRole login)."
            )
        source = VaultPKICertificateSource(
            addr=VAULT_ADDR,
            token=VAULT_TOKEN,
            role=VAULT_PKI_ROLE,
            common_name="localhost",
            mount_point=VAULT_MOUNT_POINT,
        )

    if backend == "vault":
        pass
    elif backend in {"sds", "https"}:
        if not SDS_ENDPOINT:
            raise RuntimeError("SDS_ENDPOINT required for HTTPS/SDS backend.")
        source = HTTPSCertificateSource(endpoint=SDS_ENDPOINT, token=SDS_TOKEN, verify_tls=SDS_VERIFY_TLS)
    elif backend == "file":
        source = FileCertificateSource(CERT_FILE_PATH, KEY_FILE_PATH, CA_FILE_PATH)
    else:
        # Safety net: if an unknown backend is configured, fall back to file
        logger.warning("Unknown CERT_STORAGE_BACKEND '%s'; defaulting to 'file'.", CERT_STORAGE_BACKEND)
        source = FileCertificateSource(CERT_FILE_PATH, KEY_FILE_PATH, CA_FILE_PATH)

    return CertificateManager(
        source,
        min_version=TLS_MIN_VERSION,
        cipher_suites=TLS_CIPHER_SUITES,
        require_client_cert=REQUIRE_CLIENT_CERT,
        client_ca=CLIENT_CA_FILE,
        refresh_interval=CERT_REFRESH_SECONDS,
        force_rotation_seconds=CERT_FORCE_ROTATION_SECONDS,
    )


def install_tls_reload_signals(manager: CertificateManager, context) -> None:
    if os.name != "posix":
        return
    loop = asyncio.get_running_loop()

    def _handler(sig_name: str) -> None:
        loop.create_task(manager.reload_if_needed(context, reason=f"signal:{sig_name}", force=True))

    for sig_name in ("SIGHUP", "SIGUSR1"):
        sig = getattr(signal, sig_name, None)
        if not sig:
            continue
        try:
            loop.add_signal_handler(sig, lambda s=sig_name: _handler(s))
        except NotImplementedError:
            logger.warning("Signal handlers not supported on this platform.")
            break


def apply_runtime_isolation() -> None:
    if os.name != "posix":
        return
    try:
        if PROXY_CHROOT_PATH:
            os.chroot(PROXY_CHROOT_PATH)
            os.chdir("/")
            logger.info("Chrooted into %s", PROXY_CHROOT_PATH)
        if PROXY_SERVICE_GROUP:
            import grp

            gid = grp.getgrnam(PROXY_SERVICE_GROUP).gr_gid
            os.setgid(gid)
            logger.info("Dropped group privileges to %s", PROXY_SERVICE_GROUP)
        if PROXY_SERVICE_USER:
            import pwd

            uid = pwd.getpwnam(PROXY_SERVICE_USER).pw_uid
            os.setuid(uid)
            logger.info("Dropped user privileges to %s", PROXY_SERVICE_USER)
    except PermissionError as exc:
        logger.warning("Runtime isolation skipped: %s", exc)


# --------------------------
# Main
# --------------------------
async def main():
    configure_logging()
    logger.info(
        "Observer endpoints: telemetry=%s cbom=%s verify_tls(telemetry)=%s verify_tls(cbom)=%s",
        TELEMETRY_ENDPOINT,
        CBOM_ENDPOINT,
        _should_verify_observer_tls(TELEMETRY_ENDPOINT) if TELEMETRY_ENDPOINT else None,
        _should_verify_observer_tls(CBOM_ENDPOINT) if CBOM_ENDPOINT else None,
    )
    ssl_ctx = None
    cert_manager: Optional[CertificateManager] = None
    if not USE_SSL:
        raise RuntimeError("TLS is required: PROXY_USE_SSL must be enabled.")
    try:
        cert_manager = build_certificate_manager()
        ssl_ctx = cert_manager.build_context()
    except Exception as exc:
        logger.error("Failed to initialize TLS: %s", exc)
        raise

    apply_runtime_isolation()

    if cert_manager and ssl_ctx:
        cert_manager.start_auto_reload(ssl_ctx)
        install_tls_reload_signals(cert_manager, ssl_ctx)

    global main_loop
    main_loop = asyncio.get_running_loop()

    # Start mTLS control plane (separate port)
    threading.Thread(target=_start_control_plane, args=(cert_manager,), daemon=True).start()

    server = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT, ssl=ssl_ctx)
    addr = server.sockets[0].getsockname()
    logger.info("Proxy listening on %s (%s)", addr, "TLS" if ssl_ctx else "plain TCP")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
