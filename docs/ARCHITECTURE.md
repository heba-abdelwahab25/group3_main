# Architecture

## System overview
This project consists of three runtime services plus a traffic generator:

- **Server (Flask, :5000)**
  - Application endpoints (e-commerce + message endpoints)
  - CSRF protection for browser flows
- **Proxy (asyncio TCP forwarder + HTTP client)**
  - Terminates custom client protocol
  - Performs crypto handshake (RSA / PQC Kyber when available)
  - Forwards HTTP(S) requests to the server
  - Emits telemetry to Observer
  - Exposes a separate **mTLS control plane** for session actions
- **Observer (Flask, :5600)**
  - Dashboard UI + RBAC (viewer/auditor/admin)
  - Telemetry ingestion (token auth)
  - Metrics aggregation + alerting
  - PCAP tooling (download proxy capture + upload/analyze)
  - Audit logging (append-only)
- **Client traffic generator**
  - Simulates multiple nodes via proxy
  - Uses browser-like login + CSRF token handling

## Data flows

```mermaid
flowchart LR
  UI[Dashboard UI<br/>HTTPS + Session Cookies + RBAC] -->|same-origin| OBS[Observer<br/>UI + API Layer]

  PROXY[Proxy Core<br/>Traffic Forwarder] -->|secure telemetry<br/>token-auth| OBS

  CLIENT[Flexible Client<br/>Traffic Generator] -->|custom protocol| PROXY

  PROXY -->|HTTP(S) forwarding| SRV[Server<br/>Application API]

  OBS -->|mTLS control plane<br/>force-close / rekey| CTRL[Proxy Control Plane]

  PROXY -->|pcap file| PCAP[(proxy_capture.pcap)]
  OBS -->|read-only meta + download| PCAP
```

## Trust boundaries

- **Dashboard session boundary**: browser session cookie used only between browser and Observer.
- **Telemetry ingest boundary**: token-authenticated POSTs from Proxy to Observer. This is separate from browser session cookies.
- **Control plane boundary**: Observer (admin) calls proxy control plane over **mTLS**.

## RBAC summary

- **viewer**
  - Can view non-sensitive dashboard data (traffic, crypto health, sessions metadata)
- **auditor**
  - Can access audit logs and PCAP tools
  - Can access predictive/alert analytics
- **admin**
  - Can force-close/rekey sessions via control plane
  - Can manage alert thresholds

## Ports

- **Server**: `127.0.0.1:5000`
- **Observer**: `127.0.0.1:5600`
- **Proxy (data plane)**: configured in proxy config (default in code)
- **Proxy (control plane)**: `https://127.0.0.1:7443` (mTLS)

## Security features implemented

- **Session cookies hardened** in Observer (`HttpOnly`, `SameSite=Lax`, `Secure` when HTTPS enabled).
- **Security headers** in Observer (CSP, HSTS when HTTPS, anti-clickjacking, etc.).
- **Telemetry details encryption-at-rest** in Observer DB with role-based decryption policy.
- **Append-only admin audit log** in Observer.
- **mTLS control plane** to proxy for admin session actions.

