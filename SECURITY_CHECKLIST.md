## Production Security Checklist Status

| Checklist Item | Implementation Details |
| --- | --- |
| Choose storage: HSM, cloud-managed certs, or Vault | `CERT_STORAGE_BACKEND` selects between `file` (locked-down), `vault` (HashiCorp PKI via `hvac`), and `sds` (generic HTTPS/SDS). Extendable for HSM integrations via the `CertificateSource` interface in `proxy/certificate_manager.py`. |
| Issue certs via automated pipeline | Vault backend calls the PKI engine to mint short-lived certs, SDS backend pulls from a delivery API, and file backend can be fed by ACME tooling (e.g., certbot) running in cron/CI. |
| Store private keys securely | File backend enforces `600` permissions, keys never logged. Vault/SDS keep material in process memory only. Temp files created during `ssl` loading are `600` and removed immediately. |
| Proxy reads keys at runtime from protected location | `CertificateManager` fetches keys on startup and during rotations directly from the configured backend; no secrets are bundled with artifacts. SDS/Vault fetch via API and keep data in-memory. |
| Configure proxy for secure TLS | TLS 1.2+ enforced (`TLS_MIN_VERSION`), strong cipher suite defaults, optional mTLS (`PROXY_REQUIRE_CLIENT_CERT`), OCSP hook support, and centralized SSL context creation. |
| Automate certificate renewal & hot reload | `CertificateManager` polls every `CERT_REFRESH_SECONDS`, supports forced rotation timers, and reloads on `SIGHUP`/`SIGUSR1` without restarting the process. |
| Dedicated service user + isolation | Environment variables (`PROXY_SERVICE_USER`, `PROXY_SERVICE_GROUP`, `PROXY_CHROOT_PATH`) drop privileges/chroot on Unix after TLS initialization. |
| Key rotation policy & rollback | `python -m proxy.operations.key_rotation` performs atomic rotations with timestamped backups and `rollback` support for testing recovery. |
| Enable mTLS for client auth | Toggle via `PROXY_REQUIRE_CLIENT_CERT=true` and provide client CA bundle (`PROXY_CLIENT_CA_FILE`). |
| Avoid logging secrets | Payload logging removed; only structural metadata recorded. Setting `PROXY_LOG_SENSITIVE_DATA` is required to inspect handshake keys during debugging. Audit logs intentionally omit PEM/base64 blobs. |
| Audit access & rotate credentials after suspicion | Certificate load/rotation events emit to `proxy/logs/proxy_audit.log` (path configurable). Rotate Vault/SDS tokens by updating their env vars and restarting; signals or the rotation script can trigger immediate reloads. |

### Operational Runbook

1. **Provision certificates**
   - For ACME: run certbot (or similar) to write to `proxy/certs/server.crt` and `proxy/certs/server.key` with `600` permissions.
   - For Vault: export `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_PKI_ROLE`, etc.; set `CERT_STORAGE_BACKEND=vault`.
   - For SDS/cloud stores: expose an HTTPS endpoint that returns JSON `{certificate, private_key, issuing_ca}` and set `CERT_STORAGE_BACKEND=sds`.
2. **Start the proxy**
   ```bash
   PROXY_USE_SSL=true \
   CERT_STORAGE_BACKEND=vault \
   PROXY_REQUIRE_CLIENT_CERT=true \
   PROXY_SERVICE_USER=proxy \
   python proxy/proxy.py
   ```
3. **Rotate certificates**
   ```bash
   python -m proxy.operations.key_rotation rotate \
       --cert /tmp/new/server.crt \
       --key /tmp/new/server.key
   ```
4. **Rollback (test quarterly)**
   ```bash
   python -m proxy.operations.key_rotation rollback --backup 20250101T120000Z
   ```
5. **Audit**
   - Review `PROXY_AUDIT_LOG_PATH` after incidents.
   - Rotate Vault/SDS tokens (update env or secret file) and send `SIGHUP` to trigger reload.

### Systemd + Vault Agent implementation (reference)
- Use `CERT_STORAGE_BACKEND=vault` in `proxy/.env` (or `PROXY_ENV_FILE`) and prefer `VAULT_TOKEN_FILE` or Vault Agent auth.
- Deploy Vault Agent with templates that write `/run/proxy-certs/server.crt`, `server.key`, and `ca.crt` owned by `root:proxy-user` (`0640` for cert/CA, `0600` for key) and run `systemctl kill -s SIGHUP my-proxy.service` after updates. See `proxy/examples/vault-agent.hcl` and `proxy/examples/templates/`.
- Run the proxy as `proxy-user` and allow read access to `/run/proxy-certs` (e.g., group `proxy-user`).
- Systemd units: `proxy/examples/systemd/vault-agent-proxy.service` (agent) and `proxy/examples/systemd/my-proxy.service` (proxy) with `Restart=on-failure` and `ExecReload` wired to `SIGHUP`.
- Enable Vault audit device and CI/CD policies to rotate tokens/roles used by the agent.
- Test hot reload by forcing issuance in Vault → agent updates files → agent triggers `SIGHUP` → proxy reloads without downtime.

Extending the checklist for HSM/cloud-managed cert services only requires a new
`CertificateSource` implementation that fetches PEM/key material from the target
provider and plugs into `CertificateManager`.


