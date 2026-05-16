# TCP Proxy Server with PQC/RSA Support

A TCP proxy server that handles client connections, negotiates cryptographic methods (PQC Kyber or RSA), and forwards requests to backend servers.

## Features

✅ **Client-Facing (Upstream)**
- Accepts connections from multiple clients
- Health checks and handshake detection
- Supports both PQC (Kyber) and RSA encryption
- Automatic crypto method selection (PQC preferred, RSA fallback)

✅ **Server-Facing (Downstream)**
- Connects to backend Flask servers
- Transparent request/response relay
- Secure encrypted communication

✅ **Session Management**
- Tracks each client session and chosen crypto method
- Maps client sessions to server connections
- Automatic cleanup of stale sessions
- Multi-threaded handling for concurrent clients

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. If `pqcrypto` installation fails, you may need to install it from source:
```bash
pip install git+https://github.com/microsoft/PQCrypto-LWEKE.git
```

## Configuration

Edit `proxy.py` to configure:

```python
PROXY_HOST = '0.0.0.0'      # Proxy listening address
PROXY_PORT = 7000           # Proxy listening port
SERVER_HOST = '127.0.0.1'   # Backend server address
SERVER_PORT = 5000          # Backend server port
SESSION_TIMEOUT = 300       # Session timeout in seconds
```

### Production security checklist

Security-sensitive settings are now fully configurable via environment
variables so the same build can be promoted through environments without
source-code changes. Highlights:

- **Certificate storage backends** – set `CERT_STORAGE_BACKEND` to `file`
  (default), `vault`, or `sds` to pull material from local files, HashiCorp
  Vault PKI, or any HTTPS/SDS service that returns PEM/base64 bundles.
- **Automated issuance & renewal** – Vault/SDS backends mint short-lived certs
  at startup. The certificate manager polls on `CERT_REFRESH_SECONDS` (default
  300s), responds to `SIGHUP`/`SIGUSR1`, and can force re-issuance via
  `CERT_FORCE_ROTATION_SECONDS`.
- **Protected key files** – the file backend enforces `600` permissions on
  private keys and fails fast if they are group/world-readable.
- **Runtime key access** – the proxy reads keys only from the configured backend
  at runtime (no embedding in artifacts). SDS/Vault never persist secrets to
  disk; file mode reads them from locked-down paths.
- **TLS hardening** – control `TLS_MIN_VERSION`, `TLS_CIPHER_SUITES`, OCSP
  stapling toggles, and enable mTLS with `PROXY_REQUIRE_CLIENT_CERT=true` plus
  `PROXY_CLIENT_CA_FILE=/path/to/clients.pem`.
- **Hot reload** – certificates are reloaded in-place with zero downtime whenever
  the upstream source changes, the rotation interval elapses, or a signal is
  received.
- **Least privilege** – drop privileges and optionally chroot via
  `PROXY_SERVICE_USER`, `PROXY_SERVICE_GROUP`, and `PROXY_CHROOT_PATH`.
- **Key rotation & rollback** – run `python -m proxy.operations.key_rotation rotate`
  with `--cert/--key` arguments to atomically swap material while keeping a
  timestamped backup. Use `rollback --backup <ID>` to restore.
- **Logging hygiene** – decrypted payloads and raw secrets are never written to
  logs. Set `PROXY_LOG_SENSITIVE_DATA=true` only for short-lived debugging.
- **Auditing** – certificate loads and session events are emitted to
  `logs/proxy_audit.log` (override with `PROXY_AUDIT_LOG_PATH`) to support
  access reviews.

| Variable | Purpose |
| --- | --- |
| `PROXY_USE_SSL` | Enable TLS termination (default `false`) |
| `CERT_STORAGE_BACKEND` | `file`, `vault`, or `sds` |
| `PROXY_CERT_FILE`, `PROXY_KEY_FILE`, `PROXY_CA_FILE` | File backend paths |
| `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_PKI_ROLE`, `VAULT_COMMON_NAME`, `VAULT_ALT_NAMES` | Vault PKI issuance |
| `SDS_ENDPOINT`, `SDS_TOKEN`, `SDS_VERIFY_TLS` | HTTPS/SDS secret retrieval |
| `CERT_REFRESH_SECONDS`, `CERT_FORCE_ROTATION_SECONDS` | Auto-reload cadence and forced rotation |
| `PROXY_REQUIRE_CLIENT_CERT`, `PROXY_CLIENT_CA_FILE` | Mutual TLS enforcement |
| `PROXY_SERVICE_USER`, `PROXY_SERVICE_GROUP`, `PROXY_CHROOT_PATH` | Runtime isolation |
| `PROXY_AUDIT_LOG_PATH` | Location of audit log |

Audit logging is enabled by default. Remember to rotate Vault/SDS tokens and
review audit entries after any suspected incident.

### Vault quickstart (PKI backend)

1) Install optional deps:
```
pip install -r proxy/requirements.txt
```
2) Ensure Vault PKI is enabled and configured (admin task):
```
vault secrets enable -path=pki pki
vault secrets tune -path=pki -max-lease-ttl=87600h
vault write pki/root/generate/internal common_name="example.com" ttl=87600h
vault write pki/config/urls \
  issuing_certificates="https://vault.example.com:8200/v1/pki/ca" \
  crl_distribution_points="https://vault.example.com:8200/v1/pki/crl"
```
3) Create/update a role for the proxy (fills the checklist’s automated issuance):
```
python -m proxy.tools.bootstrap_vault_pki \
  --addr https://vault.example.com:8200 \
  --token-file /path/to/token \
  --role proxy \
  --mount pki \
  --allowed-domains proxy.local,proxy.internal,127.0.0.1 \
  --max-ttl 72h \
  --ttl 24h
```
4) Configure the proxy to fetch and hot-reload Vault-issued certs (edit your env or copy `proxy/examples/vault.env.example`):
```
PROXY_USE_SSL=true
CERT_STORAGE_BACKEND=vault
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN_FILE=/path/to/token
VAULT_PKI_ROLE=proxy
VAULT_COMMON_NAME=proxy.local
VAULT_ALT_NAMES=proxy,proxy.internal,127.0.0.1
# Optional: mTLS to clients
# PROXY_REQUIRE_CLIENT_CERT=true
# PROXY_CLIENT_CA_FILE=/path/to/clients-ca.pem
```
5) Start the proxy:
```
python proxy/proxy.py
```
6) Rotate or force reload:
- The proxy polls every `CERT_REFRESH_SECONDS` (default 300s).
- To force immediate renewal, set `CERT_FORCE_ROTATION_SECONDS` or send `SIGHUP`/`SIGUSR1` (Unix). On Windows, restart the process.

## Usage

### Start the Proxy Server

```bash
python proxy.py
```

The proxy will:
- Listen on `0.0.0.0:7000` for client connections
- Forward requests to `127.0.0.1:5000` (your Flask app)
- Handle multiple concurrent clients
- Automatically select crypto method based on client capabilities

### Client Handshake Format

Clients should send a JSON handshake:

```json
{
  "client_id": 1,
  "crypto": ["Kyber", "RSA"],
  "pub_key": "<hex-encoded-public-key>"
}
```

The proxy responds with:

```json
{
  "status": "ok",
  "session_id": 1,
  "crypto": "Kyber",
  "proxy_pub_key": "<hex-encoded-proxy-public-key>"
}
```

### Message Format

After handshake, messages are encrypted and sent with length prefix:
- 4 bytes: message length (big-endian)
- N bytes: encrypted message

The decrypted message format:

```json
{
  "client_id": 1,
  "crypto": "Kyber",
  "payload": "<base64-encoded-data>"
}
```

## Architecture

```
Client 1 (PQC) ──┐
Client 2 (RSA) ──┼──> Proxy Server ──> Backend Flask App
Client 3 (PQC) ──┘
```

### Components

- **`proxy.py`**: Main proxy server with TCP handling
- **`crypto_engines.py`**: Crypto abstraction (PQC Kyber, RSA)
- **`session_manager.py`**: Session tracking and management

### Crypto Selection Logic

1. Client sends supported crypto methods in handshake
2. Proxy selects:
   - **Kyber** if client supports it
   - **RSA** as fallback
3. Proxy generates session keypair using selected method
4. All subsequent messages use negotiated crypto

## Testing

You can test the proxy with a simple client:

```python
import socket
import json
import struct

# Connect to proxy
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 7000))

# Send handshake
handshake = {
    "client_id": 1,
    "crypto": ["RSA"],  # or ["Kyber", "RSA"]
    "pub_key": "<your-public-key>"
}
message = json.dumps(handshake).encode()
length = struct.pack('>I', len(message))
sock.sendall(length + message)

# Receive handshake response
# ... (implement response handling)
```

## Notes

- The proxy uses hybrid encryption for RSA (AES + RSA) to handle large messages
- Kyber uses KEM (Key Encapsulation Mechanism) for key exchange
- Sessions are automatically cleaned up after timeout
- Each client connection runs in a separate thread

## Troubleshooting

**PQC not available**: If you see warnings about PQC, install `pqcrypto` package. The proxy will automatically fall back to RSA.

**Connection errors**: Ensure your backend Flask server is running on the configured port before starting the proxy.

**Session timeout**: Adjust `SESSION_TIMEOUT` in `proxy.py` if clients need longer sessions.

