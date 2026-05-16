# Standards Mapping (Implementation-Oriented)

This document maps implemented controls to the standards referenced in the architecture.

## NIST SP 800-53 (selected)

### AC-2 (Account Management)
- **Implemented**: Observer bootstraps admin user; roles stored on `User` model.
- **Implemented**: RBAC enforced via decorators (`require_session_role`).

### AC-3 / AC-6 (Access Enforcement / Least Privilege)
- **Implemented**: Role gates for:
  - PCAP endpoints (auditor+)
  - Alert rule management (admin)
  - Audit export (admin)
  - Control-plane session actions (admin)

### AC-17 (Remote Access)
- **Implemented (local dev)**: Session-based UI auth; can be run over HTTPS.
- **Implemented**: Separate telemetry ingest auth (token/bearer) from UI sessions.

### AU-6 / AU-9 (Audit Review / Protection)
- **Implemented**: Append-only admin audit log (`AdminAuditLog`).
- **Implemented**: Optional SIEM export hook.

### SI-4 (System Monitoring)
- **Implemented**: Aggregated telemetry (`MetricBucket`) and dashboard alerts.
- **Implemented**: Predictive alerts endpoint (heuristic forecaster).

### SC-8 / SC-13 / SC-23 (Transmission Confidentiality / Cryptographic Protection)
- **Implemented**: Proxy uses TLS/mTLS for control plane.
- **Implemented**: Optional Observer HTTPS mode.

## NIST SP 800-52 (TLS)
- **Implemented**: HTTPS support for Observer (`OBSERVER_USE_SSL=true` + cert/key).
- **Implemented**: Proxy control plane uses TLS + client cert verification.

## ISO 27001 / 27002 (selected)

### A.9 (Access control)
- **Implemented**: RBAC in Observer; secure session cookies; role-based feature visibility.

### A.10 (Cryptography)
- **Implemented**: Encryption-at-rest for telemetry details (role-based decryption).
- **Implemented**: TLS for control plane; optional TLS for Observer.

### A.12.4 (Logging and monitoring)
- **Implemented**: Audit log; telemetry event store; alerts and dashboards.

### A.12.3 (Backup)
- **Planned**: Encrypted backup/export procedures for DB and audit logs.

## Security hardening controls implemented (Observer)

- Secure session cookies:
  - `SESSION_COOKIE_HTTPONLY=True`
  - `SESSION_COOKIE_SAMESITE=Lax`
  - `SESSION_COOKIE_SECURE=True` when `OBSERVER_USE_SSL=true`
- Security headers:
  - `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, CSP
  - HSTS enabled only in HTTPS mode
- CORS tightened to allow-list, with env override (`OBSERVER_CORS_ORIGINS`).

