"""Entry point for the Banking Sample App."""
import os
import sys
from pathlib import Path

# Ensure the service directory is in path so we can import 'app'
service_dir = str(Path(__file__).resolve().parent)
if service_dir not in sys.path:
    sys.path.append(service_dir)

from app import create_app

app = create_app()

if __name__ == "__main__":
    if not os.environ.get("REQUIRE_GATEWAY"):
        print("\n[CRITICAL] Standalone execution disabled for production mode.")
        print("[CRITICAL] Please use 'python start_all_services.py' to launch the microservice architecture.\n")
        sys.exit(1)

    port = int(os.environ.get("BANKING_PORT", 5001))
    ssl_ctx = None
    cert = os.path.join(os.path.dirname(__file__), "certs", "banking.crt")
    key  = os.path.join(os.path.dirname(__file__), "certs", "banking.key")
    if os.path.exists(cert) and os.path.exists(key):
        import ssl as _ssl
        ssl_ctx = (_ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER))
        ssl_ctx.load_cert_chain(cert, key)
        print(f"[banking_app] Starting with TLS on port {port}")
    else:
        print(f"[banking_app] Starting WITHOUT TLS on port {port} (no certs found)")

    app.run(host="0.0.0.0", port=port, ssl_context=ssl_ctx, debug=False)
