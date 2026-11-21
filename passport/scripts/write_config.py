#!/usr/bin/env python3
"""Render upstream data/.config.yaml with explicit real vs. demo mode separation.

Fixes Blocker #4 and non-blocking #9:
- Default mode is PASSPORT_MODE=real: reads PASSPORT_CONFIG_FILE (default
  passport/config/server.config.yaml), preserves all user-configured ASR/LLM/TTS
  providers across restarts, and fails closed if the real config is missing
  instead of silently falling back to fake_provider.py.
- Demo mode requires explicit PASSPORT_MODE=demo and uses config/demo.config.yaml
  with PASSPORT_FAKE_BASE.
- All secrets and generated config files are written atomically with 0600 mode.
"""

import os
import secrets
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from passport_server.fs_utils import atomic_write_private

REAL_DEFAULT_CONFIG = ROOT / "config" / "server.config.yaml"
DEMO_DEFAULT_CONFIG = ROOT / "config" / "demo.config.yaml"
PLACEHOLDER = "replace-with-a-long-random-string"


def _is_valid_auth_key(value: str) -> bool:
    if not value:
        return False
    stripped = value.strip()
    if (
        len(stripped) < 32
        or stripped == PLACEHOLDER
        or stripped.startswith("replace-with-")
        or "你" in stripped
    ):
        return False
    return True


def _resolve_auth_key(config_auth_key: str) -> str:
    env_key = os.environ.get("PASSPORT_AUTH_KEY", "").strip()
    if env_key:
        if not _is_valid_auth_key(env_key):
            sys.exit(
                "PASSPORT_AUTH_KEY must be at least 32 characters and not a placeholder"
            )
        return env_key

    if _is_valid_auth_key(config_auth_key):
        return config_auth_key.strip()

    key_file = Path(
        os.environ.get("PASSPORT_AUTH_FILE") or (ROOT / "runtime" / "auth_key")
    )
    if key_file.is_file():
        auth_key = key_file.read_text(encoding="utf-8").strip()
        if not _is_valid_auth_key(auth_key):
            sys.exit(f"Existing auth_key file {key_file} is invalid or shorter than 32 chars")
        return auth_key

    auth_key = secrets.token_hex(32)
    atomic_write_private(key_file, auth_key + "\n", mode=0o600)
    return auth_key


def _apply_common_server_overrides(config: dict, mode: str) -> None:
    server = config.setdefault("server", {})
    if os.environ.get("PASSPORT_BIND", "").strip():
        server["ip"] = os.environ["PASSPORT_BIND"].strip()
    if os.environ.get("PASSPORT_WS_BIND_PORT", "").strip():
        server["port"] = int(os.environ["PASSPORT_WS_BIND_PORT"].strip())
    if os.environ.get("PASSPORT_HTTP_BIND_PORT", "").strip():
        server["http_port"] = int(os.environ["PASSPORT_HTTP_BIND_PORT"].strip())
    if os.environ.get("PASSPORT_PUBLIC_WS", "").strip():
        server["websocket"] = os.environ["PASSPORT_PUBLIC_WS"].strip()
    if os.environ.get("PASSPORT_PUBLIC_HTTP", "").strip():
        server["vision_explain"] = os.environ["PASSPORT_PUBLIC_HTTP"].strip()

    auth = server.setdefault("auth", {})
    if "enabled" not in auth:
        auth["enabled"] = True
    if not auth.get("enabled"):
        print(
            "WARNING: server.auth.enabled is false; OTA and WebSocket endpoints will not verify device credentials.",
            file=sys.stderr,
        )

    devices_file_env = os.environ.get("PASSPORT_DEVICES_FILE", "").strip()
    if devices_file_env:
        auth["devices_file"] = devices_file_env
    elif not auth.get("devices_file") and not auth.get("devices"):
        auth["devices_file"] = str(ROOT / "runtime" / "devices.yaml")

    if os.environ.get("PASSPORT_AUTH_EXPIRE_SECONDS", "").strip():
        auth["expire_seconds"] = int(os.environ["PASSPORT_AUTH_EXPIRE_SECONDS"].strip())

    # Allow testing that allowlisted device IDs never bypass token verification.
    if mode == "demo" and os.environ.get("PASSPORT_TEST_ALLOWED_DEVICES", "").strip():
        auth["allowed_devices"] = [
            item.strip()
            for item in os.environ["PASSPORT_TEST_ALLOWED_DEVICES"].split(",")
            if item.strip()
        ]


def _apply_demo_providers(config: dict) -> None:
    fake = os.environ.get("PASSPORT_FAKE_BASE", "http://127.0.0.1:18019").strip().rstrip("/")
    asr_cfg = config.setdefault("ASR", {}).setdefault("PassportLocalASR", {})
    llm_cfg = config.setdefault("LLM", {}).setdefault("PassportLocalLLM", {})
    tts_cfg = config.setdefault("TTS", {}).setdefault("PassportLocalTTS", {})

    asr_cfg["base_url"] = fake + "/v1/audio/transcriptions"
    llm_cfg["base_url"] = fake + "/v1"
    tts_cfg["api_url"] = fake + "/v1/audio/speech"

    asr_timeout_env = os.environ.get("PASSPORT_ASR_TIMEOUT", "").strip()
    if asr_timeout_env:
        timeout_val = float(asr_timeout_env)
        asr_cfg["connect_timeout"] = min(2.0, timeout_val)
        asr_cfg["read_timeout"] = timeout_val
        asr_cfg["write_timeout"] = max(2.0, timeout_val)
        asr_cfg["pool_timeout"] = min(2.0, timeout_val)
        asr_cfg["total_timeout"] = timeout_val + 0.5


def main() -> None:
    if "XIAOZHI_HOME" not in os.environ or not os.environ["XIAOZHI_HOME"].strip():
        sys.exit("XIAOZHI_HOME must be set to the xiaozhi-server directory")
    server_home = Path(os.environ["XIAOZHI_HOME"]).resolve()

    mode = os.environ.get("PASSPORT_MODE", "real").strip().lower()
    if mode not in ("real", "demo"):
        sys.exit(f"Invalid PASSPORT_MODE={mode!r}; expected 'real' or 'demo'")

    config_file_env = os.environ.get("PASSPORT_CONFIG_FILE", "").strip()
    if mode == "real":
        source_path = Path(config_file_env) if config_file_env else REAL_DEFAULT_CONFIG
        if not source_path.is_file():
            sys.exit(
                f"PASSPORT_MODE=real requires a real configuration file at {source_path}.\n"
                f"Copy {ROOT / 'config' / 'server.config.example.yaml'} to {REAL_DEFAULT_CONFIG} "
                f"and configure your real ASR/LLM/TTS providers, or set PASSPORT_MODE=demo "
                f"explicitly for fake-provider contract testing."
            )
        if os.environ.get("PASSPORT_FAKE_BASE", "").strip():
            print(
                "WARNING: Ignoring PASSPORT_FAKE_BASE because PASSPORT_MODE=real.",
                file=sys.stderr,
            )
    else:
        source_path = Path(config_file_env) if config_file_env else DEMO_DEFAULT_CONFIG
        if not source_path.is_file():
            sys.exit(f"Demo configuration file not found: {source_path}")
        print(
            "WARNING: PASSPORT_MODE=demo — configuring fake providers for isolated testing only.",
            file=sys.stderr,
        )

    config = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        sys.exit(f"Configuration file {source_path} did not parse to a YAML mapping")

    existing_auth_key = str(config.get("server", {}).get("auth_key") or "")
    config.setdefault("server", {})["auth_key"] = _resolve_auth_key(existing_auth_key)
    _apply_common_server_overrides(config, mode)

    if mode == "demo":
        _apply_demo_providers(config)

    header = (
        f"# Generated by passport/scripts/write_config.py from {source_path} (mode={mode}).\n"
        "# Do not edit this generated file directly; edit your source config and restart.\n"
    )
    rendered = header + yaml.safe_dump(config, allow_unicode=True, sort_keys=False)

    target = server_home / "data" / ".config.yaml"
    atomic_write_private(target, rendered, mode=0o600)
    print(f"wrote {target} (mode={mode}, source={source_path})")


if __name__ == "__main__":
    main()
