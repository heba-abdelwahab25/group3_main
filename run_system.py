"""
Integration runner for proxy and single client.

Automatically starts Flask server, proxy, and runs a single client.
"""

from __future__ import annotations

import os
import sys
import time
import threading
from pathlib import Path
import socket
import ssl
from typing import Dict
import webbrowser
import collections
import urllib.request
import urllib.error


traffic_process = None
observer_process = None
server_process = None
server_output_tail = None
server_log_path = None

# ----- Paths -------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
PROXY_DIR = BASE_DIR / "proxy"
CLIENT_DIR = BASE_DIR / "client"
OBSERVER_DIR = BASE_DIR / "observer"

if str(PROXY_DIR) not in sys.path:
    sys.path.append(str(PROXY_DIR))

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 7000
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

CONNECT_RETRIES = 40
CONNECT_RETRY_DELAY = 0.5


# ----- Env loading for proxy --------------------------------------
def _parse_env_file(path: Path) -> Dict[str, str]:
    env_vars: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        env_vars[key.strip()] = value.strip()
    return env_vars


def load_proxy_env() -> Dict[str, str]:
    """
    Load Vault/TLS settings for the proxy.
    Priority:
      1) PROXY_ENV_FILE (if set)
      2) proxy/.env
      3) proxy/examples/vault.env (handy default template)
    """
    candidates = []
    env_hint = os.getenv("PROXY_ENV_FILE")
    if env_hint:
        candidates.append(Path(env_hint))
    candidates.append(PROXY_DIR / ".env")
    candidates.append(PROXY_DIR / "examples" / "vault.env")

    for path in candidates:
        if path.exists():
            try:
                return _parse_env_file(path)
            except Exception:
                # Fall through to next candidate
                continue
    return {}


# ----- Helper -------------------------------------------------------
def wait_for_service(host: str, port: int, name: str) -> bool:
    for _ in range(CONNECT_RETRIES):
        if name.lower().startswith("flask") and server_process is not None and server_process.poll() is not None:
            log_path = server_log_path or (BASE_DIR / "logs" / "server.log")
            print(f"[SYSTEM] {name} process exited early. See logs at {log_path}")
            tail = server_output_tail
            if tail:
                print("[SYSTEM] Last server output lines:")
                for l in list(tail)[-20:]:
                    print(f"[SERVER] {l}")
            return False
        try:
            with socket.create_connection((host, port), timeout=0.5):
                print(f"[SYSTEM] {name} is reachable on {host}:{port}")
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(CONNECT_RETRY_DELAY)
    print(f"[SYSTEM] Timeout waiting for {name} on {host}:{port}")
    return False


def wait_for_tls_service(host: str, port: int, name: str) -> bool:
    for _ in range(CONNECT_RETRIES):
        try:
            sock = socket.create_connection((host, port), timeout=0.5)
            try:
                context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=host):
                    print(f"[SYSTEM] {name} is reachable on {host}:{port} (TLS)")
                    return True
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except (ConnectionRefusedError, socket.timeout, OSError, ssl.SSLError):
            time.sleep(CONNECT_RETRY_DELAY)
    print(f"[SYSTEM] Timeout waiting for {name} (TLS) on {host}:{port}")
    return False


# ----- Process Launchers -------------------------------------------------------
def run_flask_server() -> None:
    print("[SYSTEM] Starting Flask server...")
    import subprocess
    server_dir = BASE_DIR / "server"
    env = os.environ.copy()
    env["FLASK_APP"] = "run.py"

    # Enforce HTTPS on backend in dev so internal hops can be TLS-only.
    env.setdefault("BACKEND_USE_SSL", "1")

    def _ensure_backend_tls_files(cert_path: Path, key_path: Path) -> None:
        if cert_path.exists() and key_path.exists():
            return
        cert_path.parent.mkdir(parents=True, exist_ok=True)

        from datetime import datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Backend"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ]
        )

        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        key_path.write_bytes(key_pem)
        cert_path.write_bytes(cert_pem)

    # Point backend CBOM emitter at the observer using the correct scheme.
    # When the observer is started with TLS (common in this project), HTTP posts will fail.
    proxy_env = load_proxy_env()
    proxy_use_tls = str(proxy_env.get("PROXY_USE_SSL") or env.get("PROXY_USE_SSL") or "1").strip().lower() in {"1", "true", "yes", "on"}
    env["SERVER_CBOM_URL"] = "https://127.0.0.1:5600/api/cboom/events" if proxy_use_tls else "http://127.0.0.1:5600/api/cboom/events"
    # Local dev default: observer uses a self-signed cert when TLS is enabled.
    # The server-side CBOM emitter should not fail on cert verification.
    env.setdefault("SERVER_CBOM_VERIFY_TLS", "0")
    
    # Try to use server's venv Python if available, otherwise use system Python
    server_venv_python = server_dir / "venv" / "Scripts" / "python.exe"
    if server_venv_python.exists():
        python_exe = str(server_venv_python)
    else:
        # Fallback: try to find python in server/venv/Scripts (Unix) or use system Python
        server_venv_python_unix = server_dir / "venv" / "bin" / "python"
        if server_venv_python_unix.exists():
            python_exe = str(server_venv_python_unix)
        else:
            python_exe = sys.executable
    
    global server_process
    creationflags = 0
    if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    global server_output_tail, server_log_path

    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "server.log"
    server_log_path = log_path
    log_fp = open(log_path, "a", encoding="utf-8", errors="replace")
    tail = collections.deque(maxlen=120)
    server_output_tail = tail

    # Use Flask's development server (non-blocking so we can terminate it on shutdown)
    backend_use_ssl = str(env.get("BACKEND_USE_SSL") or "").strip().lower() in {"1", "true", "yes", "on"}
    flask_args = [python_exe, "-m", "flask", "run", "--host", SERVER_HOST, "--port", str(SERVER_PORT)]
    if backend_use_ssl:
        cert_path = Path(server_dir) / "certs" / "backend.crt"
        key_path = Path(server_dir) / "certs" / "backend.key"
        _ensure_backend_tls_files(cert_path, key_path)
        flask_args.extend(["--cert", str(cert_path), "--key", str(key_path)])

    server_process = subprocess.Popen(
        flask_args,
        cwd=str(server_dir),
        env=env,
        creationflags=creationflags,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    def _pump_output() -> None:
        try:
            if server_process is None or server_process.stdout is None:
                return
            for line in server_process.stdout:
                try:
                    log_fp.write(line)
                    log_fp.flush()
                except Exception:
                    pass
                tail.append(line.rstrip("\n"))
        finally:
            try:
                log_fp.close()
            except Exception:
                pass

    threading.Thread(target=_pump_output, daemon=True).start()

    time.sleep(0.6)
    if server_process.poll() is not None:
        print(f"[SYSTEM] Flask server exited early (code {server_process.returncode}).")
        print(f"[SYSTEM] See logs at {log_path}")
        if tail:
            print("[SYSTEM] Last server output lines:")
            for l in list(tail)[-20:]:
                print(f"[SERVER] {l}")

def run_observer() -> None:
    print("[SYSTEM] Starting observer service...")
    import subprocess
    from pathlib import Path
    env = os.environ.copy()
    proxy_env = load_proxy_env()
    if "GEMINI_API_KEY" in proxy_env and "GEMINI_API_KEY" not in env:
        env["GEMINI_API_KEY"] = proxy_env["GEMINI_API_KEY"]

    def _ensure_observer_tls_files(cert_path: Path, key_path: Path) -> None:
        if cert_path.exists() and key_path.exists():
            return
        cert_path.parent.mkdir(parents=True, exist_ok=True)

        from datetime import datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Observer"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ]
        )

        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        key_path.write_bytes(key_pem)
        cert_path.write_bytes(cert_pem)

    proxy_use_ssl = str(proxy_env.get("PROXY_USE_SSL") or env.get("PROXY_USE_SSL") or "").strip().lower()
    if proxy_use_ssl in {"1", "true", "yes", "on"}:
        cert_path = Path(OBSERVER_DIR) / "certs" / "observer.crt"
        key_path = Path(OBSERVER_DIR) / "certs" / "observer.key"
        _ensure_observer_tls_files(cert_path, key_path)
        env.setdefault("OBSERVER_USE_SSL", "true")
        env.setdefault("OBSERVER_TLS_CERT_FILE", str(cert_path))
        env.setdefault("OBSERVER_TLS_KEY_FILE", str(key_path))
        env.setdefault("OBSERVER_ENFORCE_HTTPS", "true")

        # Also reflect these settings in the parent process so the code that
        # waits/opens the dashboard uses https://.
        os.environ.setdefault("OBSERVER_USE_SSL", "true")
        os.environ.setdefault("OBSERVER_TLS_CERT_FILE", str(cert_path))
        os.environ.setdefault("OBSERVER_TLS_KEY_FILE", str(key_path))
        os.environ.setdefault("OBSERVER_ENFORCE_HTTPS", "true")

    # Prefer the same interpreter running this script (so installed deps are available).
    # Use observer venv only if it exists.
    observer_venv_python = OBSERVER_DIR / "venv" / "Scripts" / "python.exe"
    python_exe = str(observer_venv_python) if observer_venv_python.exists() else sys.executable

    global observer_process
    creationflags = 0
    if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "observer.log"
    log_fp = open(log_path, "ab")
    observer_process = subprocess.Popen(
        [python_exe, "run.py"],
        cwd=str(OBSERVER_DIR),
        env=env,
        creationflags=creationflags,
        stdout=log_fp,
        stderr=log_fp,
    )

    # Wait briefly for observer to come up; if it exits, show where logs are.
    time.sleep(0.6)
    if observer_process.poll() is not None:
        print(f"[SYSTEM] Observer exited early. See logs at {log_path}")

def run_proxy() -> None:
    print("[SYSTEM] Bootstrapping proxy...")
    import subprocess
    env = os.environ.copy()
    env.update(load_proxy_env())
    # Default to TLS unless explicitly disabled.
    env.setdefault("PROXY_USE_SSL", "1")
    # Enforce TLS on proxy->backend hop (backend uses a self-signed dev cert by default).
    env.setdefault("PROXY_BACKEND_USE_SSL", "1")
    env.setdefault("PROXY_BACKEND_VERIFY_TLS", "0")

    print(
        f"[SYSTEM] Vault env present: VAULT_ADDR={'yes' if env.get('VAULT_ADDR') else 'no'} "
        f"VAULT_ROLE_ID={'yes' if env.get('VAULT_ROLE_ID') else 'no'} "
        f"VAULT_SECRET_ID={'yes' if env.get('VAULT_SECRET_ID') else 'no'} "
        f"VAULT_TOKEN={'yes' if env.get('VAULT_TOKEN') else 'no'}"
    )

    if env.get("VAULT_ROLE_ID") and env.get("VAULT_SECRET_ID"):
        try:
            import hvac

            vault_addr = env.get("VAULT_ADDR", "http://127.0.0.1:8200")
            client = hvac.Client(url=vault_addr)
            client.auth.approle.login(
                role_id=env["VAULT_ROLE_ID"],
                secret_id=env["VAULT_SECRET_ID"],
            )
            if client.is_authenticated():
                env["VAULT_TOKEN"] = client.token
                print("[SYSTEM] Vault AppRole login succeeded; VAULT_TOKEN set for proxy subprocess.")
            else:
                print("[SYSTEM] Vault AppRole login failed (client not authenticated).")
        except ImportError:
            print("[SYSTEM] hvac not installed; cannot perform Vault AppRole login.")
        except Exception as e:
            print(f"[SYSTEM] Vault AppRole login error: {e}")

    print(f"[SYSTEM] Passing VAULT_TOKEN to proxy subprocess: {'yes' if env.get('VAULT_TOKEN') else 'no'}")

    subprocess.run(
        [sys.executable, "proxy.py"],
        cwd=str(PROXY_DIR),
        env=env,
        check=False
    )

def run_flexible_client() -> None:
    print("[SYSTEM] Running flexible client...")
    import subprocess
    env = os.environ.copy()
    proxy_env = load_proxy_env()
    if "PROXY_USE_SSL" in proxy_env:
        env["PROXY_USE_SSL"] = proxy_env["PROXY_USE_SSL"]
    else:
        env.setdefault("PROXY_USE_SSL", "1")

    # Keep 50 Kyber nodes by default; optionally add some RSA nodes.
    proxy_use_tls = str(env.get("PROXY_USE_SSL") or "").strip().lower() in {"1", "true", "yes", "on"}
    kyber_nodes = env.get("TRAFFIC_NODES", "50")
    rsa_nodes = env.get("TRAFFIC_RSA_NODES", "0")
    try:
        total_nodes = int(kyber_nodes) + int(rsa_nodes)
    except Exception:
        total_nodes = int(kyber_nodes) if str(kyber_nodes).strip().isdigit() else 50
    sleep_s = env.get("TRAFFIC_SLEEP", "1")
    malicious_rate = env.get("MALICIOUS_RATE", "0.1")
    stagger_delay = env.get("TRAFFIC_STAGGER_DELAY", "0.12" if proxy_use_tls else "0.05")

    args = [
        sys.executable,
        "flexible_client.py",
        "--nodes",
        str(total_nodes),
        "--kyber-nodes",
        str(kyber_nodes),
        "--rsa-nodes",
        str(rsa_nodes),
        "--stagger",
        "--delay",
        str(stagger_delay),
        "--loop",
        "--sleep",
        str(sleep_s),
        "--malicious",
        "--malicious-rate",
        str(malicious_rate),
    ]

    global traffic_process
    traffic_process = subprocess.Popen(
        args,
        cwd=str(CLIENT_DIR),
        env=env,
    )


def generate_backend_db_traffic(*, requests_count: int = 40, delay_s: float = 0.1) -> None:
    """Generate DB queries against the backend so CBOM shows backend↔db events."""
    backend_use_ssl = os.getenv("BACKEND_USE_SSL", "1").strip().lower() in {"1", "true", "yes", "on"}
    scheme = "https" if backend_use_ssl else "http"
    url = f"{scheme}://{SERVER_HOST}:{SERVER_PORT}/api/products"
    ctx = None
    if backend_use_ssl:
        try:
            ctx = ssl._create_unverified_context()
        except Exception:
            ctx = None
    for i in range(max(0, int(requests_count))):
        try:
            with urllib.request.urlopen(url, timeout=2, context=ctx) as resp:
                try:
                    resp.read(64)
                except Exception:
                    pass
            if i == 0:
                print(f"[SYSTEM] Generating backend DB traffic via {url} ...")
        except (urllib.error.URLError, TimeoutError, OSError):
            # Backend may not be ready yet; keep trying.
            pass
        time.sleep(max(0.0, float(delay_s)))
    print("[SYSTEM] Finished generating backend DB traffic.")


# ----- Main -------------------------------------------------------
def main() -> None:
    # Start Flask server
    flask_thread = threading.Thread(target=run_flask_server, daemon=True)
    flask_thread.start()
    backend_use_ssl = os.getenv("BACKEND_USE_SSL", "1").strip().lower() in {"1", "true", "yes", "on"}
    backend_wait_fn = wait_for_tls_service if backend_use_ssl else wait_for_service
    if not backend_wait_fn(SERVER_HOST, SERVER_PORT, "Flask server"):
        print("[SYSTEM] Failed to start Flask server. Please start it manually.")
        return

    # Start observer early so CBOM ingest is available even if proxy/Vault isn't configured.
    run_observer()

    # Ensure observer is reachable before generating CBOM traffic.
    observer_use_ssl = os.getenv("OBSERVER_USE_SSL", "").strip().lower() in {"1", "true", "yes", "on"}
    observer_wait_fn = wait_for_tls_service if observer_use_ssl else wait_for_service
    observer_wait_fn("127.0.0.1", 5600, "Observer dashboard")

    # Kick off backend DB traffic to populate CBOM with backend↔db events.
    threading.Thread(target=generate_backend_db_traffic, daemon=True).start()

    # Note: The ecommerce server stays "clean" (no proxy dashboard). We only open the observer UI.

    # Start proxy
    proxy_thread = threading.Thread(target=run_proxy, daemon=True)
    proxy_thread.start()
    proxy_env = load_proxy_env()
    proxy_use_tls = os.getenv("PROXY_USE_SSL")
    if proxy_use_tls is None and "PROXY_USE_SSL" in proxy_env:
        proxy_use_tls = proxy_env["PROXY_USE_SSL"]
    use_tls = str(proxy_use_tls or "").strip().lower() in {"1", "true", "t", "yes", "on"}

    wait_fn = wait_for_tls_service if use_tls else wait_for_service
    if not wait_fn(PROXY_HOST, PROXY_PORT, "Proxy server"):
        print("[SYSTEM] Failed to start proxy server.")
        print("[SYSTEM] Continuing without proxy (CBOM/observer will still run).")
    else:
        # Start continuous traffic generator (non-blocking) only if proxy is reachable.
        run_flexible_client()
        print("[SYSTEM] Traffic generator started.")

    # Auto-open observer dashboard
    def _open_observer():
        observer_use_ssl = os.getenv("OBSERVER_USE_SSL", "").strip().lower() in {"1", "true", "yes", "on"}
        url = f"https://127.0.0.1:5600/" if observer_use_ssl else f"http://127.0.0.1:5600/"
        time.sleep(2.0)
        try:
            webbrowser.open_new_tab(url)
            print(f"[SYSTEM] Opened observer dashboard at {url}")
        except Exception as e:
            print(f"[SYSTEM] Could not auto-open observer dashboard: {e}")

    threading.Thread(target=_open_observer, daemon=True).start()

    # Keep runner alive so dashboard stays up. Ctrl+C stops traffic first, second Ctrl+C exits.
    traffic_stopped = False
    while True:
        try:
            time.sleep(1.0)
        except KeyboardInterrupt:
            global traffic_process, server_process, observer_process
            if not traffic_stopped and traffic_process and traffic_process.poll() is None:
                try:
                    traffic_process.terminate()
                except Exception:
                    pass
                traffic_stopped = True
                print("\n[SYSTEM] Traffic generator stopped. Dashboard is still running at http://127.0.0.1:5600/ (Ctrl+C again to exit).")
                continue
            print("\n[SYSTEM] Shutting down...")
            if observer_process and observer_process.poll() is None:
                try:
                    observer_process.terminate()
                except Exception:
                    pass
            if server_process and server_process.poll() is None:
                try:
                    server_process.terminate()
                except Exception:
                    pass
            return


if __name__ == "__main__":
    main()
