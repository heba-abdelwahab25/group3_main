# Operations Runbook

## Quick start (dev)

1. Start the whole system:
   - Run: `python run_system.py`
2. Open Observer dashboard:
   - `http://127.0.0.1:5600/`

## Observer HTTPS mode

To run the Observer over HTTPS (recommended for standards alignment):

- Set:
  - `OBSERVER_USE_SSL=true`
  - `OBSERVER_TLS_CERT_FILE=<path-to-cert.pem>`
  - `OBSERVER_TLS_KEY_FILE=<path-to-key.pem>`
  - Optional:
    - `OBSERVER_HOST=127.0.0.1`
    - `OBSERVER_PORT=5600`

The Observer will refuse to start in HTTPS mode unless both cert and key are provided.

## Proxy PCAP capture

The proxy only writes a capture when enabled.

- Enable capture:
  - `PROXY_CAPTURE_PCAP=true`
- Optional:
  - `PROXY_PCAP_PATH=<path>`
  - `PROXY_PCAP_MAX_BYTES=<int>`

Observer reads the file path via:
- `OBSERVER_PROXY_PCAP_PATH` (defaults to `proxy/logs/proxy_capture.pcap`)

Observer endpoints:
- `GET /api/proxy/pcap/meta` (auditor+)
- `GET /api/proxy/pcap/download` (auditor+)
- `POST /api/pcap/upload` (auditor+)
- `GET /api/pcap/analyze?source=proxy` (auditor+)

## Alerting

- Dashboard alerts:
  - `GET /api/dashboard/alerts`
- Alert rules (admin):
  - `GET /api/alerts/rules`
  - `PUT /api/alerts/rules`
- Predictive alerts (auditor+):
  - `GET /api/alerts/predict`

Webhook notifications (critical alerts):
- `OBSERVER_ALERT_WEBHOOK_URL=<https://...>`
- `OBSERVER_ALERT_WEBHOOK_TIMEOUT=2.0`

## Common troubleshooting

### Observer routes not found (404)
- Ensure you restarted the Observer process after code changes.

### PCAP download button disabled
- Check `GET /api/proxy/pcap/meta`.
  - If `present:false`, the proxy capture file does not exist yet.
- Ensure `PROXY_CAPTURE_PCAP=true` for the proxy process.

### Predictive widget shows —
- Requires MetricBucket history; generate traffic for a few minutes.
- Ensure your logged-in role is `auditor` or `admin`.

