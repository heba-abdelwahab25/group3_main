import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("OBSERVER_HOST", "127.0.0.1")
    port = int(os.environ.get("OBSERVER_PORT", "5600"))

    use_ssl = os.environ.get("OBSERVER_USE_SSL", "0").strip().lower() in {"1", "true", "yes", "on"}
    cert = os.environ.get("OBSERVER_TLS_CERT_FILE", "").strip()
    key = os.environ.get("OBSERVER_TLS_KEY_FILE", "").strip()
    ssl_context = None
    if use_ssl:
        if cert and key:
            ssl_context = (cert, key)
        else:
            raise RuntimeError("OBSERVER_USE_SSL=true requires OBSERVER_TLS_CERT_FILE and OBSERVER_TLS_KEY_FILE")

    app.run(host=host, port=port, ssl_context=ssl_context)

