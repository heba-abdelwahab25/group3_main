"""
Operational helper to rotate TLS certificates and private keys with backups.

Usage examples:

Rotate to newly issued files and keep a timestamped backup of the previous
material:

    python -m proxy.operations.key_rotation rotate --cert path/to/new.crt --key path/to/new.key

Rollback to a previous backup:

    python -m proxy.operations.key_rotation rollback --backup 20250101T120000Z
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import sys
from pathlib import Path

from config import CERT_BACKUP_DIR, CERT_FILE_PATH, KEY_FILE_PATH


CERT_PATH = Path(CERT_FILE_PATH)
KEY_PATH = Path(KEY_FILE_PATH)
BACKUP_ROOT = Path(CERT_BACKUP_DIR)


def _ensure_backup_root() -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    return BACKUP_ROOT


def _timestamp() -> str:
    return dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def create_backup() -> Path:
    root = _ensure_backup_root()
    backup_dir = root / _timestamp()
    backup_dir.mkdir(parents=True, exist_ok=False)
    if not CERT_PATH.exists() or not KEY_PATH.exists():
        raise FileNotFoundError("Current certificate or key does not exist.")
    shutil.copy2(CERT_PATH, backup_dir / "server.crt")
    shutil.copy2(KEY_PATH, backup_dir / "server.key")
    return backup_dir


def rotate(new_cert: Path, new_key: Path) -> str:
    if not new_cert.exists() or not new_key.exists():
        raise FileNotFoundError("New certificate or key file missing.")

    backup_dir = create_backup()
    shutil.copy2(new_cert, CERT_PATH)
    shutil.copy2(new_key, KEY_PATH)
    KEY_PATH.chmod(0o600)
    CERT_PATH.chmod(0o644)
    return backup_dir.name


def rollback(backup_id: str) -> None:
    candidate = BACKUP_ROOT / backup_id
    if not candidate.exists():
        raise FileNotFoundError(f"Backup {backup_id} not found.")
    shutil.copy2(candidate / "server.crt", CERT_PATH)
    shutil.copy2(candidate / "server.key", KEY_PATH)
    KEY_PATH.chmod(0o600)
    CERT_PATH.chmod(0o644)


def list_backups() -> list[str]:
    if not BACKUP_ROOT.exists():
        return []
    return sorted([p.name for p in BACKUP_ROOT.iterdir() if p.is_dir()])


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Certificate rotation helper.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    rotate_parser = subparsers.add_parser("rotate", help="Rotate to new cert/key pair.")
    rotate_parser.add_argument("--cert", required=True, type=Path)
    rotate_parser.add_argument("--key", required=True, type=Path)

    rollback_parser = subparsers.add_parser("rollback", help="Restore a previous backup.")
    rollback_parser.add_argument("--backup", required=True, help="Backup folder name.")

    subparsers.add_parser("list", help="List available backups.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    if args.command == "list":
        for name in list_backups():
            print(name)
        return 0

    if args.command == "rotate":
        backup_id = rotate(args.cert, args.key)
        print(f"Rotation complete. Backup stored as {backup_id}")
        return 0

    if args.command == "rollback":
        rollback(args.backup)
        print(f"Rollback to {args.backup} finished.")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())


