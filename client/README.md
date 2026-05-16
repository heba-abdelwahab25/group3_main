# Flexible PQC/RSA Client

A robust Python client that supports both Post-Quantum Cryptography (Kyber) and Classical RSA, designed to communicate with a proxy layer and simulate multiple client nodes for load testing.

## Features

- ✅ **Dual Cryptography Support**: Post-Quantum (Kyber) and Classical (RSA)
- ✅ **Proxy Communication**: All traffic goes through proxy layer
- ✅ **Load Testing**: Simulate multiple concurrent client nodes
- ✅ **Flexible Libraries**: Supports multiple PQC/RSA library implementations
- ✅ **JSON Protocol**: Structured message format with metadata
- ✅ **Error Handling**: Robust error handling and logging

## Installation

### Option 1: Using pqcrypto (Recommended for PQC)

```bash
pip install pqcrypto pycryptodome
```

### Option 2: Alternative PQC Libraries

```bash
# Using smaj-kyber
pip install smaj-kyber pycryptodome

# OR using kybercffi
pip install kybercffi pycryptodome
```

### Option 3: Using cryptography library for RSA

```bash
pip install pqcrypto cryptography
```

## Usage

### Basic Usage

```bash
# Run with 5 PQC clients
python flexible_client.py --nodes 5 --crypto PQCKyber

# Run with 10 RSA clients
python flexible_client.py --nodes 10 --crypto RSA

# Run with mixed clients (alternating PQC and RSA)
python flexible_client.py --nodes 20 --crypto mixed

# Stagger connections (useful for load testing)
python flexible_client.py --nodes 50 --crypto PQCKyber --stagger --delay 0.05

# Custom proxy address
python flexible_client.py --nodes 5 --crypto PQCKyber --host 192.168.1.100 --port 8080
```

### Command Line Arguments

- `--nodes N`: Number of client nodes to simulate (default: 5)
- `--crypto TYPE`: Cryptography type - `PQCKyber`, `RSA`, or `mixed` (default: PQCKyber)
- `--host HOST`: Proxy server hostname/IP (default: 127.0.0.1)
- `--port PORT`: Proxy server port (default: 65432)
- `--stagger`: Stagger connection starts (useful for load testing)
- `--delay SECONDS`: Delay between connections when staggering (default: 0.1)

## Architecture

### Crypto Engines

The client uses a plugin-style architecture with base `CryptoEngine` class:

- **PQCKyber**: Post-Quantum Kyber512 KEM
- **RSAEngine**: Classical RSA-2048 encryption

### Communication Protocol

The client sends JSON messages to the proxy with:
- `node_id`: Unique client identifier
- `crypto`: Cryptography type ("PQCKyber" or "RSA")
- `pub_key`: Public key (hex-encoded for PQC, PEM for RSA)
- `timestamp`: Connection timestamp

### Message Format

**Request (Client → Proxy):**
```json
{
  "node_id": 1,
  "crypto": "PQCKyber",
  "pub_key": "a1b2c3d4...",
  "timestamp": 1234567890.123
}
```

**Response (Proxy → Client):**
```json
{
  "ciphertext": "e5f6g7h8...",
  "status": "success"
}
```

## Example Output

```
[+] Using pqcrypto.kem.kyber512
[+] Using pycryptodome for RSA

============================================================
Starting load simulation: 5 nodes, crypto: PQCKyber
============================================================

[Node 1] Starting client using PQCKyber...
[Node 1] Generating PQCKyber keypair...
[Node 1] Keypair generated. Pub key: 800 bytes
[Node 1] Connecting to proxy 127.0.0.1:65432...
[Node 1] Connected to proxy.
[Node 1] Sent JSON payload (156 bytes) to proxy.
[Node 1] Waiting for response from proxy...
[Node 1] Received ciphertext (768 bytes).
[Node 1] Decrypting/decapsulating...
[Node 1] ✓ Shared secret established!
[Node 1] Shared secret (hex): 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d...
[Node 1] Shared secret length: 32 bytes

============================================================
Load simulation complete: 5 nodes in 2.34 seconds
============================================================
```

## Load Testing

For heavy load testing:

```bash
# 100 concurrent clients
python flexible_client.py --nodes 100 --crypto PQCKyber

# 1000 clients with staggered starts
python flexible_client.py --nodes 1000 --crypto mixed --stagger --delay 0.01
```

## Requirements

- Python 3.7+
- One PQC library: `pqcrypto`, `smaj-kyber`, or `kybercffi`
- One RSA library: `pycryptodome` or `cryptography`

## Notes

- The proxy must support both PQC and RSA protocols
- For production use, ensure proper security practices
- Shared secrets can be used to derive symmetric keys for AES encryption
- The client handles connection errors, timeouts, and decryption failures gracefully

