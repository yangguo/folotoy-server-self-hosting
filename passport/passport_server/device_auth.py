"""Provisioned device registry and strict OTA/WebSocket authentication.

Fixes Blocker #1:
- OTA only issues WebSocket tokens to provisioned, enabled devices that present a
  valid device-specific OTA secret (via /xiaozhi/ota/d/<secret>/, X-OTA-Secret,
  or Authorization: Bearer <secret>) and matching Device-Id / Client-Id.
- WebSocket authentication ALWAYS verifies provisioned device status, Device-Id,
  Client-Id binding (when configured), token expiration, and HMAC signature.
- Upstream ``allowed_devices`` bypass (skipping token verification when a device
  self-reports a listed Device-Id) is completely eliminated.
"""

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

import yaml

DEFAULT_EXPIRE_SECONDS = 60 * 60 * 24 * 30
MAX_FUTURE_SKEW_SECONDS = 60
PLACEHOLDER_PREFIXES = ("replace-with-", "your-", "<")


def normalize_device_id(value: str) -> str:
    """Normalize MAC/device identifiers for consistent lookup and HMAC binding."""
    return (value or "").strip().lower()


def hash_ota_secret(secret: str) -> str:
    """Return lowercase SHA-256 hex digest of an OTA device secret."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _is_valid_sha256_hex(digest: str) -> bool:
    if not isinstance(digest, str) or len(digest) != 64:
        return False
    try:
        int(digest, 16)
    except ValueError:
        return False
    return True


def _is_placeholder(value: str) -> bool:
    lower = value.strip().lower()
    return not lower or any(lower.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def validate_runtime_auth_config(config: dict, mode: Optional[str] = None) -> None:
    """Fail closed if device authentication is missing, disabled, or misconfigured."""
    effective_mode = (mode or os.environ.get("PASSPORT_MODE") or "real").strip().lower()
    if effective_mode not in ("real", "demo"):
        raise RuntimeError(
            f"Invalid PASSPORT_MODE={effective_mode!r}; expected 'real' or 'demo'."
        )
    if not isinstance(config, dict) or not isinstance(config.get("server"), dict):
        raise RuntimeError("Passport configuration must define a 'server' mapping.")

    server_cfg = config["server"]
    auth_cfg = server_cfg.get("auth")
    if not isinstance(auth_cfg, dict) or auth_cfg.get("enabled") is not True:
        raise RuntimeError(
            "Passport requires server.auth.enabled: true; refusing to start with "
            "device authentication disabled or missing."
        )

    auth_key = str(server_cfg.get("auth_key") or "").strip()
    if not auth_key or _is_placeholder(auth_key) or "你" in auth_key:
        raise RuntimeError("Passport requires a valid non-placeholder server.auth_key.")
    if effective_mode == "real" and len(auth_key) < 32:
        raise RuntimeError(
            "PASSPORT_MODE=real requires server.auth_key to be at least 32 characters."
        )

    devices_file = auth_cfg.get("devices_file")
    inline_devices = auth_cfg.get("devices")
    has_devices_file = isinstance(devices_file, str) and bool(devices_file.strip())
    has_inline_devices = isinstance(inline_devices, list) and len(inline_devices) > 0
    if not has_devices_file and not has_inline_devices:
        raise RuntimeError(
            "Passport requires server.auth.devices_file or non-empty server.auth.devices."
        )


@dataclass(frozen=True)
class DeviceRecord:
    """Provisioned Passport device entry."""

    device_id: str
    ota_secret_sha256: str
    client_id: Optional[str] = None
    enabled: bool = True
    name: str = ""


class PassportDeviceAuth:
    """Device registry + HMAC token issuer/verifier bound to provisioned devices."""

    def __init__(self, config: dict):
        server_cfg = config.get("server", {})
        auth_cfg = server_cfg.get("auth", {}) or {}
        self.secret_key = str(server_cfg.get("auth_key") or "")
        if not self.secret_key:
            raise ValueError("server.auth_key must be non-empty")

        raw_expire = auth_cfg.get("expire_seconds")
        if raw_expire is None:
            self.expire_seconds = DEFAULT_EXPIRE_SECONDS
        else:
            expire_val = int(raw_expire)
            self.expire_seconds = (
                expire_val if expire_val > 0 else DEFAULT_EXPIRE_SECONDS
            )

        devices_file_raw = auth_cfg.get("devices_file")
        self.devices_file = Path(devices_file_raw) if devices_file_raw else None
        self._inline_devices = self._parse_devices_mapping(
            {"devices": auth_cfg.get("devices") or []}, source="inline"
        )
        self._file_sig: Optional[Tuple[int, int, int]] = None
        self._file_devices: Dict[str, DeviceRecord] = {}
        self._reload_if_needed(force=True)

    @staticmethod
    def _parse_devices_mapping(
        payload: Optional[dict], source: str
    ) -> Dict[str, DeviceRecord]:
        records: Dict[str, DeviceRecord] = {}
        if not isinstance(payload, dict):
            return records
        items = payload.get("devices") or []
        if not isinstance(items, list):
            raise ValueError(f"{source} devices registry must contain a list under 'devices'")
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            dev_id = normalize_device_id(str(item.get("device_id") or ""))
            if not dev_id:
                raise ValueError(f"{source} devices[{idx}] missing device_id")

            digest = str(item.get("ota_secret_sha256") or "").strip().lower()
            raw_secret = str(item.get("ota_secret") or "").strip()
            if not digest and raw_secret and not _is_placeholder(raw_secret):
                digest = hash_ota_secret(raw_secret)
            if not _is_valid_sha256_hex(digest):
                raise ValueError(
                    f"{source} devices[{idx}] ({dev_id}) missing valid ota_secret_sha256"
                )

            client_id_raw = item.get("client_id")
            client_id = str(client_id_raw).strip() if client_id_raw else None
            enabled = bool(item.get("enabled", True))
            name = str(item.get("name") or "").strip()
            records[dev_id] = DeviceRecord(
                device_id=dev_id,
                ota_secret_sha256=digest,
                client_id=client_id or None,
                enabled=enabled,
                name=name,
            )
        return records

    def _reload_if_needed(self, force: bool = False) -> None:
        if self.devices_file is None:
            return
        if not self.devices_file.is_file():
            if force or self._file_sig is not None:
                self._file_devices = {}
                self._file_sig = None
            return
        stat = self.devices_file.stat()
        sig = (stat.st_mtime_ns, stat.st_ino, stat.st_size)
        if not force and sig == self._file_sig:
            return
        loaded = yaml.safe_load(self.devices_file.read_text(encoding="utf-8"))
        self._file_devices = self._parse_devices_mapping(
            loaded, source=str(self.devices_file)
        )
        self._file_sig = sig

    def get_device(self, device_id: str) -> Optional[DeviceRecord]:
        """Look up a normalized device record, reloading devices_file on changes."""
        self._reload_if_needed()
        norm_id = normalize_device_id(device_id)
        if not norm_id:
            return None
        if norm_id in self._file_devices:
            return self._file_devices[norm_id]
        return self._inline_devices.get(norm_id)

    def _sign_token(
        self, client_id: str, device_id: str, ts: int, secret_sha256: str
    ) -> str:
        content = f"v1|{client_id}|{device_id}|{ts}|{secret_sha256}"
        sig = hmac.new(
            self.secret_key.encode("utf-8"),
            content.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

    def generate_ws_token(
        self,
        entry: DeviceRecord,
        client_id: str,
        device_id: str,
        ts: Optional[int] = None,
    ) -> str:
        """Issue an HMAC-SHA256 WebSocket token bound to device, client, and secret digest."""
        norm_device = normalize_device_id(device_id)
        norm_client = (client_id or "").strip()
        issued_at = int(time.time()) if ts is None else int(ts)
        signature = self._sign_token(
            norm_client, norm_device, issued_at, entry.ota_secret_sha256
        )
        return f"{signature}.{issued_at}"

    def authenticate_ota(
        self, device_id: str, client_id: str, ota_secret: str
    ) -> Tuple[bool, Optional[DeviceRecord], str]:
        """Validate OTA identity + provisioned per-device secret before issuing tokens."""
        norm_device = normalize_device_id(device_id)
        norm_client = (client_id or "").strip()
        secret = (ota_secret or "").strip()

        if not norm_device or not norm_client:
            return False, None, "missing_device_or_client_id"
        if not secret:
            return False, None, "missing_credential"

        entry = self.get_device(norm_device)
        if entry is None or not entry.enabled:
            return False, None, "device_not_provisioned"

        if not hmac.compare_digest(hash_ota_secret(secret), entry.ota_secret_sha256):
            return False, None, "invalid_credential"

        if entry.client_id and not hmac.compare_digest(norm_client, entry.client_id):
            return False, None, "client_id_mismatch"

        return True, entry, "ok"

    def authenticate_ws(
        self,
        device_id: str,
        client_id: str,
        token: str,
        now: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Strictly validate a WebSocket connection.

        Never skips token verification for ``allowed_devices``.
        """
        norm_device = normalize_device_id(device_id)
        norm_client = (client_id or "").strip()
        raw_token = (token or "").strip()

        if not norm_device or not norm_client or not raw_token:
            return False, "missing_credentials"

        entry = self.get_device(norm_device)
        if entry is None or not entry.enabled:
            return False, "device_not_provisioned"

        if entry.client_id and not hmac.compare_digest(norm_client, entry.client_id):
            return False, "client_id_mismatch"

        parts = raw_token.split(".")
        if len(parts) != 2:
            return False, "malformed_token"
        sig_part, ts_str = parts
        try:
            issued_at = int(ts_str)
        except ValueError:
            return False, "malformed_token"

        current = int(time.time()) if now is None else int(now)
        if current - issued_at > self.expire_seconds:
            return False, "token_expired"
        if issued_at - current > MAX_FUTURE_SKEW_SECONDS:
            return False, "token_from_future"

        expected_sig = self._sign_token(
            norm_client, norm_device, issued_at, entry.ota_secret_sha256
        )
        if not hmac.compare_digest(sig_part, expected_sig):
            return False, "invalid_signature"

        return True, "ok"
