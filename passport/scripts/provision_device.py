#!/usr/bin/env python3
"""Provision, inspect, rotate, or revoke Passport devices without modifying firmware.

Stores only SHA-256 digests of per-device OTA secrets in devices.yaml with 0600
atomic writes, and outputs a device-specific OTA URL (/xiaozhi/ota/d/<secret>/)
that can be pasted directly into the unmodified xiaozhi-esp32 Wi-Fi portal
(wifi/ota_url).
"""

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from passport_server.device_auth import hash_ota_secret, normalize_device_id
from passport_server.fs_utils import atomic_write_private, locked_file

DEFAULT_DEVICES_FILE = ROOT / "runtime" / "devices.yaml"


def _load_registry(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not data:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        raise SystemExit(f"Invalid devices registry format in {path}")
    return [dict(item) for item in data["devices"] if isinstance(item, dict)]


def _save_registry(path: Path, devices: List[Dict[str, Any]]) -> None:
    header = (
        "# Passport provisioned device registry. Contains SHA-256 hashes only.\n"
        "# Managed by passport/scripts/provision_device.py (mode 0600).\n"
    )
    rendered = header + yaml.safe_dump(
        {"devices": devices}, allow_unicode=True, sort_keys=False
    )
    atomic_write_private(path, rendered, mode=0o600)


def _format_ota_url(ota_base: str, ota_secret: str) -> str:
    return f"{ota_base.rstrip('/')}/xiaozhi/ota/d/{ota_secret}/"


def _cmd_add(args: argparse.Namespace) -> None:
    devices_file = Path(args.devices_file)
    dev_id = normalize_device_id(args.device_id)
    if not dev_id:
        raise SystemExit("--device-id must be non-empty")

    ota_secret = args.secret.strip() if args.secret else secrets.token_urlsafe(24)
    entry: Dict[str, Any] = {
        "device_id": dev_id,
        "ota_secret_sha256": hash_ota_secret(ota_secret),
        "enabled": True,
    }
    if args.client_id:
        entry["client_id"] = args.client_id.strip()
    if args.name:
        entry["name"] = args.name.strip()

    with locked_file(devices_file):
        devices = _load_registry(devices_file)
        if any(normalize_device_id(str(d.get("device_id") or "")) == dev_id for d in devices):
            raise SystemExit(
                f"Device {dev_id} already exists in {devices_file}; use 'rotate' to replace its secret."
            )
        devices.append(entry)
        _save_registry(devices_file, devices)

    ota_url = _format_ota_url(args.ota_base, ota_secret)
    if args.json:
        print(
            json.dumps(
                {
                    "device_id": dev_id,
                    "client_id": entry.get("client_id"),
                    "ota_secret": ota_secret,
                    "ota_url": ota_url,
                    "devices_file": str(devices_file),
                },
                ensure_ascii=False,
            )
        )
    else:
        print(f"Provisioned device: {dev_id}")
        if entry.get("client_id"):
            print(f"Bound client_id:   {entry['client_id']}")
        print(f"Registry file:     {devices_file} (0600, SHA-256 hash stored)")
        print(f"Device OTA URL:    {ota_url}")
        print(
            "Paste the Device OTA URL into the device portal wifi/ota_url setting. "
            "The raw secret is shown only once and is not saved in plaintext."
        )


def _cmd_rotate(args: argparse.Namespace) -> None:
    devices_file = Path(args.devices_file)
    dev_id = normalize_device_id(args.device_id)
    ota_secret = args.secret.strip() if args.secret else secrets.token_urlsafe(24)

    with locked_file(devices_file):
        devices = _load_registry(devices_file)
        target = None
        for entry in devices:
            if normalize_device_id(str(entry.get("device_id") or "")) == dev_id:
                target = entry
                break
        if target is None:
            raise SystemExit(f"Device {dev_id} not found in {devices_file}")

        target["ota_secret_sha256"] = hash_ota_secret(ota_secret)
        target.pop("ota_secret", None)
        target["enabled"] = True
        _save_registry(devices_file, devices)

    ota_url = _format_ota_url(args.ota_base, ota_secret)
    if args.json:
        print(
            json.dumps(
                {
                    "device_id": dev_id,
                    "ota_secret": ota_secret,
                    "ota_url": ota_url,
                    "devices_file": str(devices_file),
                },
                ensure_ascii=False,
            )
        )
    else:
        print(f"Rotated secret for device: {dev_id}")
        print(f"New Device OTA URL:        {ota_url}")


def _cmd_revoke(args: argparse.Namespace) -> None:
    devices_file = Path(args.devices_file)
    dev_id = normalize_device_id(args.device_id)
    with locked_file(devices_file):
        devices = _load_registry(devices_file)
        updated = False
        for entry in devices:
            if normalize_device_id(str(entry.get("device_id") or "")) == dev_id:
                entry["enabled"] = False
                updated = True
                break
        if not updated:
            raise SystemExit(f"Device {dev_id} not found in {devices_file}")
        _save_registry(devices_file, devices)
    print(f"Revoked device: {dev_id}")


def _cmd_list(args: argparse.Namespace) -> None:
    devices_file = Path(args.devices_file)
    with locked_file(devices_file):
        devices = _load_registry(devices_file)
    if not devices:
        print(f"No devices provisioned in {devices_file}")
        return
    for entry in devices:
        dev_id = normalize_device_id(str(entry.get("device_id") or ""))
        client_id = entry.get("client_id") or "*"
        enabled = bool(entry.get("enabled", True))
        name = entry.get("name") or ""
        digest_prefix = str(entry.get("ota_secret_sha256") or "")[:12]
        print(
            f"device_id={dev_id} client_id={client_id} enabled={enabled} "
            f"sha256={digest_prefix}... name={name!r}"
        )


def main() -> None:
    default_file = os.environ.get("PASSPORT_DEVICES_FILE") or str(DEFAULT_DEVICES_FILE)
    parser = argparse.ArgumentParser(
        description="Manage Passport provisioned devices without modifying device firmware."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--devices-file",
        default=default_file,
        help="Path to devices.yaml (default: PASSPORT_DEVICES_FILE or passport/runtime/devices.yaml)",
    )

    p_add = sub.add_parser("add", parents=[common], help="Provision a new device")
    p_add.add_argument("--device-id", required=True, help="Device MAC address (Device-Id)")
    p_add.add_argument("--client-id", default="", help="Optional Client-Id UUID binding")
    p_add.add_argument("--name", default="", help="Human-readable label")
    p_add.add_argument(
        "--ota-base",
        default="https://your-passport-host.example.com",
        help="External OTA base URL (e.g. https://passport.example.com)",
    )
    p_add.add_argument("--secret", default="", help="Optional explicit secret (for tests)")
    p_add.add_argument("--json", action="store_true", help="Emit JSON output")
    p_add.set_defaults(func=_cmd_add)

    p_rot = sub.add_parser("rotate", parents=[common], help="Rotate a device OTA secret")
    p_rot.add_argument("--device-id", required=True, help="Device MAC address (Device-Id)")
    p_rot.add_argument(
        "--ota-base",
        default="https://your-passport-host.example.com",
        help="External OTA base URL",
    )
    p_rot.add_argument("--secret", default="", help="Optional explicit secret (for tests)")
    p_rot.add_argument("--json", action="store_true", help="Emit JSON output")
    p_rot.set_defaults(func=_cmd_rotate)

    p_rev = sub.add_parser("revoke", parents=[common], help="Disable a provisioned device")
    p_rev.add_argument("--device-id", required=True, help="Device MAC address (Device-Id)")
    p_rev.set_defaults(func=_cmd_revoke)

    p_ls = sub.add_parser("list", parents=[common], help="List provisioned devices")
    p_ls.set_defaults(func=_cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
