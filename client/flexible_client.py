"""
Flexible PQC/RSA Client for Proxy Communication
Supports both Post-Quantum (Kyber) and Classical (RSA) cryptography
Can simulate multiple client nodes for load testing
Handles proxies that may not return ciphertext
"""
import socket
import json
import sys
import os
import ssl
import hashlib
import threading
import time
import base64
import re
import random
from typing import Tuple
from urllib.parse import urlencode

# ===== Crypto library availability =====
PQC_AVAILABLE = False
RSA_AVAILABLE = False
PQC_ENGINE = None

# ---- PQC / Kyber ----
try:
    from kyber_py.ml_kem import ML_KEM_512 as MLKEM512
    PQC_AVAILABLE = True
    PQC_ENGINE = "kyber_py"
    print("[+] Using kyber-py (ML_KEM_512)")
except ImportError:
    try:
        from pqcrypto.kem.kyber512 import generate_keypair as pq_generate_keypair, encrypt as pq_encrypt, decrypt as pq_decrypt
        PQC_AVAILABLE = True
        PQC_ENGINE = "pqcrypto"
        print("[+] Using pqcrypto.kem.kyber512")
    except ImportError:
        print("[!] No PQC library found. Install kyber-py or pqcrypto")

# ---- RSA ----
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    RSA_AVAILABLE = True
    RSA_ENGINE = "pycryptodome"
    print("[+] Using pycryptodome for RSA")
except ImportError:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import serialization, hashes
        RSA_AVAILABLE = True
        RSA_ENGINE = "cryptography"
        print("[+] Using cryptography library for RSA")
    except ImportError:
        print("[!] No RSA library found. Install pycryptodome or cryptography")

# ===== Configuration =====
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 7000
BUFFER_SIZE = 4096
TIMEOUT = int(os.getenv("CLIENT_SOCKET_TIMEOUT", "30" if os.getenv("PROXY_USE_SSL", "true").strip().lower() in {"1", "true", "yes"} else "10"))
USE_JSON = True
USE_TLS = os.getenv("PROXY_USE_SSL", "true").strip().lower() in {"1", "true", "yes"}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data)


def _extract_csrf_token(html: str) -> str | None:
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if not m:
        return None
    return m.group(1)


def _split_set_cookie(value: str) -> list[str]:
    if not value:
        return []
    parts = []
    current = []
    in_expires = False
    for ch in value:
        if ch == ',':
            token = ''.join(current)
            if not in_expires:
                parts.append(token)
                current = []
                continue
        current.append(ch)
        tail = ''.join(current).lower()
        if tail.endswith('expires='):
            in_expires = True
        if in_expires and ch == ';':
            in_expires = False
    if current:
        parts.append(''.join(current))
    return [p.strip() for p in parts if p.strip()]


def recv_exactly(sock: socket.socket, nbytes: int) -> bytes:
    data = b""
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            break
        data += chunk
    return data


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    from Crypto.Cipher import AES

    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ===== Crypto Engines =====
class CryptoEngine:
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError
    def encrypt(self, data: bytes, pub_key: bytes) -> bytes:
        raise NotImplementedError
    def decrypt(self, data: bytes, sec_key: bytes) -> bytes:
        raise NotImplementedError

class PQCKyber(CryptoEngine):
    def __init__(self):
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC library not available")
        self.engine = PQC_ENGINE
        if self.engine == "kyber_py":
            self.kyber = MLKEM512
        elif self.engine == "pqcrypto":
            pass

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        if self.engine == "kyber_py":
            pk, sk = self.kyber.keygen()
            return bytes(pk), bytes(sk)
        elif self.engine == "pqcrypto":
            return pq_generate_keypair()

    def encrypt(self, data: bytes, pub_key: bytes) -> bytes:
        if self.engine == "kyber_py":
            shared_secret, ciphertext = self.kyber.encaps(pub_key)
            return bytes(ciphertext), bytes(shared_secret)
        elif self.engine == "pqcrypto":
            return pq_encrypt(data, pub_key)

    def decrypt(self, data: bytes, sec_key: bytes) -> bytes:
        if self.engine == "kyber_py":
            return bytes(self.kyber.decaps(sec_key, data))
        elif self.engine == "pqcrypto":
            return pq_decrypt(data, sec_key)

class RSAEngine(CryptoEngine):
    def __init__(self, key_size: int = 2048):
        if not RSA_AVAILABLE:
            raise RuntimeError("RSA library not available")
        self.key_size = key_size
        self.engine = RSA_ENGINE

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        if self.engine == "pycryptodome":
            key = RSA.generate(self.key_size)
            return key.publickey().export_key(), key.export_key()
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size
            )
            pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            return pub_pem, priv_pem

    def encrypt(self, data: bytes, pub_key: bytes) -> bytes:
        if self.engine == "pycryptodome":
            rsa_key = RSA.import_key(pub_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            return cipher.encrypt(data)
        else:
            public_key = serialization.load_pem_public_key(pub_key)
            return public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

    def decrypt(self, data: bytes, sec_key: bytes) -> bytes:
        if self.engine == "pycryptodome":
            rsa_key = RSA.import_key(sec_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            return cipher.decrypt(data)
        else:
            private_key = serialization.load_pem_private_key(sec_key, password=None)
            return private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

# ===== Client Node =====
def client_node(node_id: int, crypto_choice: str = "PQCKyber", delay: float = 0.0):
    if delay > 0:
        time.sleep(delay)

    print(f"[Node {node_id}] Starting client using {crypto_choice}...")

    # 1️⃣ Select crypto engine
    if crypto_choice == "PQCKyber":
        engine = PQCKyber()
    elif crypto_choice == "RSA":
        engine = RSAEngine()
    else:
        print(f"[Node {node_id}] Unknown crypto: {crypto_choice}")
        return

    # 2️⃣ Generate keypair
    pub_key, sec_key = engine.generate_keypair()
    print(f"[Node {node_id}] Keypair generated. Pub key: {len(pub_key)} bytes")

    step_sleep_s = float(os.getenv("TRAFFIC_STEP_SLEEP", "0.15"))
    purchase_rate = float(os.getenv("PURCHASE_RATE", "0.35"))
    is_malicious = os.getenv("MALICIOUS_NODES", "0").strip().lower() in {"1", "true", "yes"}
    malicious_rate = float(os.getenv("MALICIOUS_RATE", "0.15"))
    iterations = int(os.getenv("TRAFFIC_ITERATIONS", "0"))  # 0 => infinite
    sleep_s = float(os.getenv("TRAFFIC_SLEEP", "1.5"))

    reconnect_backoff = 0.5
    max_backoff = 10.0

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
                raw_sock.settimeout(TIMEOUT)
                raw_sock.connect((PROXY_HOST, PROXY_PORT))
                s = raw_sock
                if USE_TLS:
                    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    s = context.wrap_socket(raw_sock, server_hostname=PROXY_HOST)
                    s.settimeout(TIMEOUT)
                    print(f"[Node {node_id}] Connected to proxy (TLS).")
                else:
                    print(f"[Node {node_id}] Connected to proxy.")

                # Handshake
                if USE_JSON:
                    if crypto_choice == "PQCKyber":
                        pub_key_str = pub_key.hex()
                    else:
                        pub_key_str = pub_key.decode("utf-8") if isinstance(pub_key, bytes) else pub_key
                    payload = {"node_id": node_id, "crypto": crypto_choice, "pub_key": pub_key_str, "timestamp": time.time()}
                    message = json.dumps(payload).encode("utf-8")
                    s.sendall(len(message).to_bytes(4, "big") + message)
                else:
                    s.sendall(pub_key)

                length_bytes = recv_exactly(s, 4)
                if not length_bytes or len(length_bytes) < 4:
                    raise RuntimeError("no handshake response length from proxy")
                length = int.from_bytes(length_bytes, "big")
                data = recv_exactly(s, length)
                response = json.loads(data.decode("utf-8")) if data else {}
                if response.get("status") != "ok":
                    raise RuntimeError("handshake_failed")

                ciphertext_hex = response.get("ciphertext")
                if not ciphertext_hex:
                    raise RuntimeError("no ciphertext received")
                ciphertext = bytes.fromhex(ciphertext_hex)
                shared_secret = engine.decrypt(ciphertext, sec_key)
                session_key = hashlib.sha256(shared_secret).digest()
                print(f"[Node {node_id}] Shared secret established ({len(shared_secret)} bytes)")

                username = f"node{node_id}_{int(time.time())}"
                password = "Password123!"
                did_auth = False
                csrf_token = None
                cookie_jar: dict[str, str] = {}

                def _step_sleep(mult: float = 1.0) -> None:
                    time.sleep((step_sleep_s * mult) + random.uniform(0.0, step_sleep_s))

                def _cookie_header_value() -> str:
                    if not cookie_jar:
                        return ""
                    return "; ".join([f"{k}={v}" for k, v in cookie_jar.items() if k])

                def _update_cookies_from_headers(resp_headers: dict | None) -> None:
                    if not resp_headers:
                        return
                    set_cookie_val = None
                    for k, v in resp_headers.items():
                        if str(k).lower() == "set-cookie":
                            set_cookie_val = v
                            break
                    if not set_cookie_val:
                        return
                    for cookie_str in _split_set_cookie(str(set_cookie_val)):
                        first = cookie_str.split(";", 1)[0].strip()
                        if not first or "=" not in first:
                            continue
                        name, value = first.split("=", 1)
                        name = name.strip()
                        value = value.strip()
                        if name:
                            cookie_jar[name] = value

                def send_http(method: str, path: str, *, headers: dict | None = None, body: bytes | None = None):
                    req = {
                        "type": "http_request",
                        "client_id": node_id,
                        "method": method,
                        "path": path,
                        "headers": headers or {},
                    }

                    cookie_val = _cookie_header_value()
                    if cookie_val:
                        req["headers"].setdefault("Cookie", cookie_val)

                    if body is not None:
                        req["body_base64"] = _b64e(body)
                    req_bytes = json.dumps(req).encode("utf-8")
                    frame = aes_encrypt(session_key, req_bytes)
                    s.sendall(len(frame).to_bytes(4, "big") + frame)

                    resp_len_bytes = recv_exactly(s, 4)
                    if not resp_len_bytes or len(resp_len_bytes) < 4:
                        raise RuntimeError("no response length from proxy")
                    resp_len = int.from_bytes(resp_len_bytes, "big")
                    enc_response = recv_exactly(s, resp_len)
                    if not enc_response or len(enc_response) < resp_len:
                        raise RuntimeError("incomplete response from proxy")
                    plain = aes_decrypt(session_key, enc_response)
                    resp_obj = json.loads(plain.decode("utf-8", errors="replace"))
                    try:
                        _update_cookies_from_headers(resp_obj.get("headers"))
                    except Exception:
                        pass
                    return resp_obj

                def ensure_authenticated() -> None:
                    nonlocal did_auth, csrf_token
                    if did_auth:
                        return
                    backend_origin = "https://127.0.0.1:5000"
                    reg_page = send_http("GET", "/auth/register")
                    reg_html = _b64d(reg_page.get("body_base64") or "").decode("utf-8", errors="replace")
                    csrf = _extract_csrf_token(reg_html)
                    if not csrf:
                        raise RuntimeError("csrf token not found on /auth/register")
                    _step_sleep()

                    form = urlencode({"csrf_token": csrf, "username": username, "password": password}).encode("utf-8")
                    reg_post = send_http(
                        "POST",
                        "/auth/register",
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": backend_origin,
                            "Referer": f"{backend_origin}/auth/register",
                        },
                        body=form,
                    )
                    print(f"[Node {node_id}] POST /auth/register -> {reg_post.get('status')}")
                    _step_sleep()

                    login_page = send_http("GET", "/auth/login")
                    login_html = _b64d(login_page.get("body_base64") or "").decode("utf-8", errors="replace")
                    csrf_login = _extract_csrf_token(login_html)
                    if not csrf_login:
                        raise RuntimeError("csrf token not found on /auth/login")
                    csrf_token = csrf_login
                    _step_sleep()

                    login_form = urlencode({"csrf_token": csrf_login, "username": username, "password": password}).encode("utf-8")
                    login_post = send_http(
                        "POST",
                        "/auth/login",
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": backend_origin,
                            "Referer": f"{backend_origin}/auth/login",
                        },
                        body=login_form,
                    )
                    print(f"[Node {node_id}] POST /auth/login -> {login_post.get('status')}")
                    did_auth = True
                    _step_sleep(2.0)

                def scenario_browser_flow() -> None:
                    home = send_http("GET", "/", headers={"User-Agent": "FlexibleClient/1.0"})
                    print(f"[Node {node_id}] GET / -> {home.get('status')}")
                    _step_sleep()

                    ensure_authenticated()

                    products = send_http("GET", "/api/products")
                    products_body = _b64d(products.get("body_base64") or "").decode("utf-8", errors="replace")
                    try:
                        product_list = json.loads(products_body)
                    except Exception:
                        product_list = []
                    _step_sleep()

                    if random.random() < purchase_rate:
                        product_id = product_list[0]["id"] if product_list else 1
                        purchase_payload = json.dumps({"product_id": int(product_id)}).encode("utf-8")
                        purchase = send_http(
                            "POST",
                            "/api/purchase",
                            headers={"Content-Type": "application/json", "X-CSRFToken": (csrf_token or "")},
                            body=purchase_payload,
                        )
                        purchase_body = _b64d(purchase.get("body_base64") or "").decode("utf-8", errors="replace")
                        print(f"[Node {node_id}] POST /api/purchase -> {purchase.get('status')} body={purchase_body[:120]}")
                        _step_sleep(2.0)

                def scenario_malicious() -> None:
                    choice = random.choice(["bad_path", "bad_method", "purchase_unauth", "path_traversal"])
                    if choice == "bad_path":
                        r = send_http("GET", "/does-not-exist")
                        print(f"[Node {node_id}] MAL GET /does-not-exist -> {r.get('status')}")
                    elif choice == "bad_method":
                        r = send_http("TRACE", "/")
                        print(f"[Node {node_id}] MAL TRACE / -> {r.get('status')}")
                    elif choice == "path_traversal":
                        r = send_http("GET", "/../secret")
                        print(f"[Node {node_id}] MAL GET /../secret -> {r.get('status')}")
                    else:
                        purchase_payload = json.dumps({"product_id": 1}).encode("utf-8")
                        r = send_http("POST", "/api/purchase", headers={"Content-Type": "application/json"}, body=purchase_payload)
                        body = _b64d(r.get("body_base64") or "").decode("utf-8", errors="replace")
                        print(f"[Node {node_id}] MAL POST /api/purchase unauth -> {r.get('status')} body={body[:80]}")

                loops = 0
                backoff_s = 0.0
                while True:
                    try:
                        if is_malicious and random.random() < malicious_rate:
                            scenario_malicious()
                        else:
                            scenario_browser_flow()

                        outgoing = {
                            "type": "message",
                            "client_id": node_id,
                            "sequence": loops + 1,
                            "body": f"Hello from node {node_id}",
                            "timestamp": time.time(),
                        }
                        outgoing_bytes = json.dumps(outgoing).encode("utf-8")
                        out_frame = aes_encrypt(session_key, outgoing_bytes)
                        s.sendall(len(out_frame).to_bytes(4, "big") + out_frame)
                        resp_len_bytes = recv_exactly(s, 4)
                        if resp_len_bytes and len(resp_len_bytes) == 4:
                            resp_len = int.from_bytes(resp_len_bytes, "big")
                            enc_response = recv_exactly(s, resp_len)
                            if enc_response and len(enc_response) == resp_len:
                                plain_response = aes_decrypt(session_key, enc_response)
                                print(f"[Node {node_id}] Proxy reply: {plain_response.decode('utf-8', errors='replace')}")
                    except Exception as e:
                        print(f"[Node {node_id}] Traffic loop error: {e}")
                        backoff_s = min(15.0, backoff_s * 2.0 + 1.0)
                        msg = str(e).lower()
                        if "no response length" in msg or "incomplete response" in msg or "timed out" in msg:
                            raise

                    if backoff_s > 0:
                        time.sleep(backoff_s)
                        backoff_s = max(0.0, backoff_s - 0.5)

                    loops += 1
                    if iterations > 0 and loops >= iterations:
                        return
                    time.sleep(sleep_s + random.uniform(0.0, sleep_s))

        except Exception as e:
            print(f"[Node {node_id}] Connection/handshake error: {e}")

        time.sleep(reconnect_backoff)
        reconnect_backoff = min(max_backoff, reconnect_backoff * 1.6 + 0.2)

# ===== Multi-Node Simulation =====
def simulate_load(num_nodes: int = 5, crypto_choice: str = "PQCKyber", stagger=False, stagger_delay=0.1):
    threads = []
    for i in range(num_nodes):
        node_crypto = "PQCKyber" if (crypto_choice != "mixed" or i % 2 == 0) else "RSA"
        delay = i * stagger_delay if stagger else 0
        t = threading.Thread(target=client_node, args=(i+1,node_crypto,delay))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def simulate_split_load(*, kyber_nodes: int, rsa_nodes: int, stagger: bool = False, stagger_delay: float = 0.1):
    threads = []
    node_id = 1
    for i in range(max(0, int(kyber_nodes))):
        delay = node_id * stagger_delay if stagger else 0
        t = threading.Thread(target=client_node, args=(node_id, "PQCKyber", delay))
        t.start()
        threads.append(t)
        node_id += 1

    for i in range(max(0, int(rsa_nodes))):
        delay = node_id * stagger_delay if stagger else 0
        t = threading.Thread(target=client_node, args=(node_id, "RSA", delay))
        t.start()
        threads.append(t)
        node_id += 1

    for t in threads:
        t.join()

# ===== Main =====
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Flexible PQC/RSA Client')
    parser.add_argument('--nodes', type=int, default=5)
    parser.add_argument('--crypto', type=str, default='PQCKyber', choices=['PQCKyber','RSA','mixed'])
    parser.add_argument('--kyber-nodes', type=int, default=None)
    parser.add_argument('--rsa-nodes', type=int, default=None)
    parser.add_argument('--host', type=str, default=PROXY_HOST)
    parser.add_argument('--port', type=int, default=PROXY_PORT)
    parser.add_argument('--stagger', action='store_true')
    parser.add_argument('--delay', type=float, default=0.1)
    parser.add_argument('--single', action='store_true')
    parser.add_argument('--loop', action='store_true', help='Keep generating traffic in a loop')
    parser.add_argument('--malicious', action='store_true', help='Enable malicious behavior for some requests')
    parser.add_argument('--malicious-rate', type=float, default=0.15)
    parser.add_argument('--sleep', type=float, default=1.5)
    parser.add_argument('--iterations', type=int, default=0)
    args = parser.parse_args()

    PROXY_HOST = args.host
    PROXY_PORT = args.port

    if args.loop:
        os.environ["TRAFFIC_ITERATIONS"] = str(args.iterations)
    else:
        os.environ["TRAFFIC_ITERATIONS"] = "1"
    os.environ["TRAFFIC_SLEEP"] = str(args.sleep)
    if args.malicious:
        os.environ["MALICIOUS_NODES"] = "1"
        os.environ["MALICIOUS_RATE"] = str(args.malicious_rate)

    if args.single:
        client_node(1, args.crypto)
    else:
        rsa_nodes = args.rsa_nodes if args.rsa_nodes is not None else 0
        if args.kyber_nodes is not None or (args.rsa_nodes is not None and rsa_nodes > 0):
            kyber_nodes = args.kyber_nodes if args.kyber_nodes is not None else max(0, int(args.nodes) - int(rsa_nodes))
            simulate_split_load(kyber_nodes=int(kyber_nodes), rsa_nodes=int(rsa_nodes), stagger=args.stagger, stagger_delay=args.delay)
        else:
            simulate_load(args.nodes, args.crypto, args.stagger, args.delay)
