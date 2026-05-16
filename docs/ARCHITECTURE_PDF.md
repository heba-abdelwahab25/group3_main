# Hybrid Classical + PQC Proxy System

## 1) Architecture Diagram

```mermaid
flowchart LR
  subgraph ClientSide[Client Side]
    UI[Dashboard UI<br/>HTTPS + Session Cookies + RBAC]
    TG[Traffic Generator<br/>Flexible_Client.py]
  end

  subgraph ObserverLayer[Observer / Proxy API Layer]
    OBS[Observer (Flask :5600)<br/>Flask-Login + RBAC]
    DB[(Observer DB<br/>TelemetryEvent + MetricBucket + Audit + AlertRule)]
  end

  subgraph ProxyLayer[Proxy Core / Traffic Forwarder]
    PROXY[Proxy (asyncio)
    Custom protocol terminator
    HTTP(S) forwarder]
    CTRL[Proxy Control Plane<br/>mTLS HTTPS :7443]
  end

  subgraph ServerLayer[Application Server]
    SRV[Server (Flask :5000)]
  end

  UI -->|Same-origin requests
session cookie| OBS
  OBS --> DB

  TG -->|custom encrypted protocol| PROXY
  PROXY -->|HTTP(S) requests| SRV

  PROXY -->|secure telemetry
(token-auth POST /api/telemetry)| OBS

  OBS -->|admin actions
mTLS control| CTRL
```

## 2) Dataflow Diagram

```mermaid
sequenceDiagram
  autonumber
  participant UI as Browser Dashboard UI
  participant OBS as Observer (Flask)
  participant DB as Observer DB
  participant TG as Traffic Generator
  participant PX as Proxy
  participant SRV as Server

  UI->>OBS: GET /login
  UI->>OBS: POST /login (Flask-Login)
  OBS-->>UI: Set-Cookie (session)

  TG->>PX: Custom handshake (RSA/Kyber)
  TG->>PX: Encrypted request frames
  PX->>SRV: HTTP(S) forward (requests.Session)
  SRV-->>PX: HTTP response
  PX-->>TG: Encrypted response frame

  PX->>OBS: POST /api/telemetry (Bearer/Token)
  OBS->>DB: Store TelemetryEvent (details encrypted-at-rest)
  OBS->>DB: Update MetricBucket aggregates

  UI->>OBS: GET /api/dashboard/* (cookie)
  OBS->>DB: Query aggregates/events
  OBS-->>UI: JSON stats
```

## 3) Control Flow Diagram (Admin control plane)

```mermaid
sequenceDiagram
  autonumber
  participant UI as Browser Dashboard UI
  participant OBS as Observer
  participant CTRL as Proxy Control Plane (mTLS)
  participant PX as Proxy Core
  participant DB as Observer DB

  UI->>OBS: POST /login (admin)
  OBS-->>UI: session cookie

  UI->>OBS: POST /api/sessions/{id}/force_close
  OBS->>DB: Append AdminAuditLog (action=force_close)
  OBS->>CTRL: mTLS POST /control/sessions/{id}/force_close
  CTRL->>PX: Close session writer (asyncio)
  PX-->>CTRL: ok
  CTRL-->>OBS: ok
  OBS-->>UI: ok

  UI->>OBS: POST /api/sessions/{id}/rekey
  OBS->>DB: Append AdminAuditLog (action=rekey)
  OBS->>CTRL: mTLS POST /control/sessions/{id}/rekey
  CTRL->>PX: Rekey session metadata
  PX-->>CTRL: ok
  CTRL-->>OBS: ok
  OBS-->>UI: ok
```

## Notes (standards alignment)

- **NIST SP 800-53 (AC/AU/SI/SC)**
  - RBAC + least privilege for sensitive endpoints.
  - Audit logging for privileged actions.
  - Monitoring + alerting (threshold + predictive).
- **NIST SP 800-52**
  - HTTPS support for Observer, mTLS for proxy control plane.
- **ISO 27001/27002**
  - A.9 access control (RBAC), A.10 crypto (TLS, encryption-at-rest), A.12 logging/monitoring.

