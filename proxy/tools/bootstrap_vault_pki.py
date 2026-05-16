"""
Bootstrap a Vault PKI role for the proxy.

This script creates or updates a PKI role that can issue certificates for the
proxy. It assumes the PKI secrets engine is already enabled at the specified
mount. If it is not, enable it separately (may require admin privileges):

    vault secrets enable -path=pki pki
    vault secrets tune -max-lease-ttl=87600h pki
    vault write pki/root/generate/internal common_name="example.com" ttl=87600h
    vault write pki/config/urls issuing_certificates="https://vault.example.com:8200/v1/pki/ca" \
        crl_distribution_points="https://vault.example.com:8200/v1/pki/crl"

Usage:
    python -m proxy.tools.bootstrap_vault_pki --addr https://vault.example.com:8200 \
        --token-file /path/to/token \
        --role proxy \
        --mount pki \
        --allowed-domains proxy.local,proxy.internal \
        --max-ttl 72h \
        --ttl 24h
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import hvac  # type: ignore
except ImportError:  # pragma: no cover
    print("hvac is required. Install with: pip install hvac", file=sys.stderr)
    raise SystemExit(1)


def read_token(token: str | None, token_file: str | None) -> str:
    if token:
        return token
    if token_file:
        path = Path(token_file)
        if not path.exists():
            raise FileNotFoundError(f"Token file not found: {token_file}")
        return path.read_text(encoding="utf-8").strip()
    env = os.getenv("VAULT_TOKEN")
    if env:
        return env.strip()
    raise ValueError("Vault token is required (use --token, --token-file, or VAULT_TOKEN).")


def ensure_pki_mount(client: hvac.Client, mount: str) -> None:
    mounts = client.sys.list_mounted_secrets_engines()["data"]
    if f"{mount}/" not in mounts:
        raise RuntimeError(
            f"PKI mount '{mount}' not found. Enable it first (vault secrets enable -path={mount} pki)."
        )


def create_role(
    client: hvac.Client,
    mount: str,
    role: str,
    allowed_domains: list[str],
    max_ttl: str,
    ttl: str,
    allow_subdomains: bool,
    allow_ip_sans: bool,
) -> None:
    client.secrets.pki.create_or_update_role(
        name=role,
        mount_point=mount,
        allowed_domains=allowed_domains,
        allow_subdomains=allow_subdomains,
        allow_any_name=False,
        allow_ip_sans=allow_ip_sans,
        max_ttl=max_ttl,
        ttl=ttl,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create/Update a Vault PKI role for the proxy.")
    parser.add_argument("--addr", required=True, help="Vault address, e.g., https://vault.example.com:8200")
    parser.add_argument("--token", help="Vault token (or set VAULT_TOKEN env)")
    parser.add_argument("--token-file", help="Path to file containing Vault token")
    parser.add_argument("--mount", default="pki", help="PKI mount point (default: pki)")
    parser.add_argument("--role", default="proxy", help="PKI role name (default: proxy)")
    parser.add_argument(
        "--allowed-domains",
        required=True,
        help="Comma-separated DNS names (no spaces).",
    )
    parser.add_argument("--max-ttl", default="72h", help="Max TTL for issued certs (default: 72h)")
    parser.add_argument("--ttl", default="24h", help="Default TTL for issued certs (default: 24h)")
    parser.add_argument("--allow-subdomains", action="store_true", default=True, help="Allow subdomains.")
    parser.add_argument("--allow-ip-sans", action="store_true", help="Allow IP SANs (disable if not needed).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    token = read_token(args.token, args.token_file)

    client = hvac.Client(url=args.addr, token=token)
    if not client.is_authenticated():
        print("Authentication to Vault failed.", file=sys.stderr)
        return 1

    ensure_pki_mount(client, args.mount)

    domains = [d.strip() for d in args.allowed_domains.split(",") if d.strip()]
    if not domains:
        print("At least one allowed domain is required.", file=sys.stderr)
        return 1

    create_role(
        client=client,
        mount=args.mount,
        role=args.role,
        allowed_domains=domains,
        max_ttl=args.max_ttl,
        ttl=args.ttl,
        allow_subdomains=args.allow_subdomains,
        allow_ip_sans=args.allow_ip_sans,
    )
    print(
        f"Role '{args.role}' updated on mount '{args.mount}'. "
        f"Allowed domains: {','.join(domains)} | max_ttl={args.max_ttl} | ttl={args.ttl}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


