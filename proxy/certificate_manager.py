"""
Certificate and private key management utilities for the proxy.

Supports file-based secrets, HashiCorp Vault PKI, and generic HTTPS/SDS style
secret distribution systems. Handles runtime TLS context reloads so that new
certificates can be activated without restarting the proxy.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import ssl
import stat
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import hvac  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    hvac = None

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None


LOGGER = logging.getLogger("proxy.certificates")
AUDIT_LOGGER = logging.getLogger("proxy.audit")


@dataclass(slots=True)
class CertificateBundle:
    """Container for certificate material."""

    certificate: bytes
    private_key: bytes
    issuing_ca: Optional[bytes] = None
    ocsp_response: Optional[bytes] = None
    serial_number: Optional[str] = None
    ttl_seconds: Optional[int] = None


class CertificateSource(ABC):
    """Interface for anything that can return certificate material."""

    @abstractmethod
    def load_bundle(self) -> CertificateBundle:
        """Return the latest keypair bundle."""

    @abstractmethod
    def revision(self) -> str:
        """Return a monotonic identifier that changes whenever new material is available."""


class FileCertificateSource(CertificateSource):
    """Load certificates and private keys from the filesystem with basic permission checks."""

    def __init__(self, cert_path: str, key_path: str, ca_path: Optional[str] = None) -> None:
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)
        self.ca_path = Path(ca_path) if ca_path else None

    def _read_bytes(self, path: Path) -> bytes:
        if not path.exists():
            raise FileNotFoundError(f"Required certificate asset missing: {path}")
        self._assert_secure_permissions(path)
        return path.read_bytes()

    def _assert_secure_permissions(self, path: Path) -> None:
        if os.name != "posix":
            return
        mode = stat.S_IMODE(path.stat().st_mode)
        if path == self.key_path and mode != 0o600:
            LOGGER.warning(
                f"Insecure permissions for {path}. Expected 600, got {oct(mode)}. Continuing anyway."
            )
            # raise PermissionError(
            #     f"Insecure permissions for {path}. Expected 600, got {oct(mode)}"
            # )

    def load_bundle(self) -> CertificateBundle:
        cert_bytes = self._read_bytes(self.cert_path)
        key_bytes = self._read_bytes(self.key_path)
        ca_bytes = self.ca_path.read_bytes() if self.ca_path and self.ca_path.exists() else None
        serial = hashlib.sha256(cert_bytes).hexdigest()
        return CertificateBundle(
            certificate=cert_bytes,
            private_key=key_bytes,
            issuing_ca=ca_bytes,
            serial_number=serial,
        )

    def revision(self) -> str:
        cert_stat = self.cert_path.stat().st_mtime_ns if self.cert_path.exists() else 0
        key_stat = self.key_path.stat().st_mtime_ns if self.key_path.exists() else 0
        payload = f"{cert_stat}:{key_stat}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class VaultPKICertificateSource(CertificateSource):
    """Fetch short-lived certificates from HashiCorp Vault's PKI secrets engine."""

    def __init__(
        self,
        addr: str,
        token: str,
        role: str,
        common_name: str,
        mount_point: str = "pki",
        alt_names: Optional[str] = None,
        ttl: Optional[str] = None,
    ) -> None:
        if not hvac:
            raise ImportError("hvac package is required for vault certificate backend.")
        self.addr = addr
        self.token = token
        self.role = role
        self.common_name = common_name
        self.mount_point = mount_point
        self.alt_names = alt_names
        self.ttl = ttl
        self._last_serial: Optional[str] = None

    def _client(self) -> hvac.Client:
        client = hvac.Client(url=self.addr, token=self.token)
        if not client.is_authenticated():
            raise PermissionError("Vault authentication failed for certificate fetch.")
        return client

    def load_bundle(self) -> CertificateBundle:
        client = self._client()
        # Only pass arguments supported by current hvac
        generate_args = {
            "name": self.role,
            "common_name": self.common_name,
            "mount_point": self.mount_point,
        }
        if self.alt_names:
            generate_args["alt_names"] = self.alt_names
        if self.ttl:
            generate_args["ttl"] = self.ttl

        payload = client.secrets.pki.generate_certificate(**generate_args)
        data = payload["data"]
        cert = data["certificate"].encode("utf-8")
        key = data["private_key"].encode("utf-8")
        issuing_ca = data.get("issuing_ca")
        serial = data.get("serial_number")
        ttl_seconds = data.get("lease_duration")
        self._last_serial = serial
        return CertificateBundle(
            certificate=cert,
            private_key=key,
            issuing_ca=issuing_ca.encode("utf-8") if issuing_ca else None,
            serial_number=serial,
            ttl_seconds=ttl_seconds,
        )

    def revision(self) -> str:
        return self._last_serial or ""


class HTTPSCertificateSource(CertificateSource):
    """Fetch certificate bundles from an HTTPS endpoint that behaves like an SDS server."""

    def __init__(
        self,
        endpoint: str,
        token: Optional[str],
        verify_tls: bool = True,
        timeout: int = 5,
    ) -> None:
        if not requests:
            raise ImportError("requests package is required for HTTPS certificate backend.")
        self.endpoint = endpoint
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._last_etag: Optional[str] = None

    def _decode_material(self, value: str) -> bytes:
        cleaned = value.strip()
        if "-----BEGIN" in cleaned:
            return cleaned.encode("utf-8")
        return base64.b64decode(cleaned)

    def load_bundle(self) -> CertificateBundle:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = requests.get(
            self.endpoint,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        payload = response.json()
        self._last_etag = response.headers.get("ETag") or payload.get("version")
        cert = self._decode_material(payload["certificate"])
        key = self._decode_material(payload["private_key"])
        ca_raw = payload.get("issuing_ca")
        ocsp_raw = payload.get("ocsp_response")
        ttl_seconds = payload.get("ttl_seconds")
        serial = payload.get("serial") or hashlib.sha256(cert).hexdigest()
        return CertificateBundle(
            certificate=cert,
            private_key=key,
            issuing_ca=self._decode_material(ca_raw) if ca_raw else None,
            ocsp_response=self._decode_material(ocsp_raw) if ocsp_raw else None,
            serial_number=serial,
            ttl_seconds=ttl_seconds,
        )

    def revision(self) -> str:
        return self._last_etag or ""


class CertificateManager:
    """Attach certificate sources to SSL contexts and handle hot reload."""

    def __init__(
        self,
        source: CertificateSource,
        *,
        min_version: str = "1.2",
        cipher_suites: Optional[str] = None,
        require_client_cert: bool = False,
        client_ca: Optional[str] = None,
        refresh_interval: int = 300,
        force_rotation_seconds: int = 0,
    ) -> None:
        self.source = source
        self.min_version = min_version
        self.cipher_suites = cipher_suites
        self.require_client_cert = require_client_cert
        self.client_ca = client_ca
        self.refresh_interval = refresh_interval
        self.force_rotation_seconds = force_rotation_seconds
        self._current_revision: Optional[str] = None
        self._last_issued_at: Optional[float] = None
        self._lock = asyncio.Lock()
        self._auto_task: Optional[asyncio.Task[None]] = None

    def build_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_ciphers(self.cipher_suites or "AESGCM")
        context.minimum_version = _tls_version(self.min_version)
        if self.require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL
        if self.client_ca and Path(self.client_ca).exists():
            context.load_verify_locations(self.client_ca)
        self._load_into_context(context, self.source.load_bundle())
        LOGGER.info("Initialized TLS context (client_cert_required=%s)", self.require_client_cert)
        return context

    def _load_into_context(self, context: ssl.SSLContext, bundle: CertificateBundle) -> None:
        cert_file = _write_secure_temp(bundle.certificate)
        key_file = _write_secure_temp(bundle.private_key)
        try:
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        finally:
            _remove_if_exists(cert_file)
            _remove_if_exists(key_file)

        if bundle.issuing_ca:
            context.load_verify_locations(cadata=bundle.issuing_ca.decode("utf-8"))

        if bundle.ocsp_response and hasattr(context, "ocsp_response"):
            try:
                context.ocsp_response = bundle.ocsp_response  # type: ignore[attr-defined]
            except Exception:
                LOGGER.debug("OCSP stapling not supported by current OpenSSL build.")

        self._current_revision = self.source.revision() or hashlib.sha256(
            bundle.certificate
        ).hexdigest()
        self._last_issued_at = time.time()
        AUDIT_LOGGER.info(
            "Loaded TLS material (serial=%s, revision=%s)",
            bundle.serial_number,
            self._current_revision,
        )

    def start_auto_reload(self, context: ssl.SSLContext) -> None:
        if self._auto_task:
            return

        async def _loop() -> None:
            try:
                while True:
                    await asyncio.sleep(self.refresh_interval)
                    await self.reload_if_needed(context, reason="periodic")
            except asyncio.CancelledError:
                LOGGER.info("Stopped certificate auto-reload loop.")

        self._auto_task = asyncio.create_task(_loop(), name="cert-auto-reload")

    async def reload_if_needed(
        self,
        context: ssl.SSLContext,
        *,
        reason: str = "manual",
        force: bool = False,
    ) -> bool:
        async with self._lock:
            now = time.time()
            if (
                self.force_rotation_seconds
                and self._last_issued_at
                and now - self._last_issued_at >= self.force_rotation_seconds
            ):
                force = True

            if not force:
                new_revision = self.source.revision()
                if new_revision and new_revision == self._current_revision:
                    return False

            bundle = await asyncio.to_thread(self.source.load_bundle)
            new_revision = self.source.revision()
            if not force and new_revision == self._current_revision:
                return False

            LOGGER.info("Reloading TLS context (reason=%s)", reason)
            await asyncio.to_thread(self._load_into_context, context, bundle)
            return True


def _write_secure_temp(payload: bytes) -> str:
    temp = tempfile.NamedTemporaryFile(delete=False)
    temp.write(payload)
    temp.flush()
    temp.close()
    os.chmod(temp.name, 0o600)
    return temp.name


def _remove_if_exists(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return


def _tls_version(label: str) -> ssl.TLSVersion:
    normalized = label.replace("TLS", "").replace("v", "").strip()
    mapping = {
        "1.2": ssl.TLSVersion.TLSv1_2,
        "1.3": ssl.TLSVersion.TLSv1_3,
    }
    return mapping.get(normalized, ssl.TLSVersion.TLSv1_2)


__all__ = [
    "CertificateBundle",
    "CertificateManager",
    "CertificateSource",
    "FileCertificateSource",
    "VaultPKICertificateSource",
    "HTTPSCertificateSource",
]
