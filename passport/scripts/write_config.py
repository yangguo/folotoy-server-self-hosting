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

from passport_server.fs_utils import atomic_write_private, ensure_private_secret_file

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


def _assert_not_real_runtime_path(path_value: Path, label: str) -> None:
    real_runtime = (ROOT / "runtime").resolve()
    candidate = Path(path_value).resolve()
    if candidate == real_runtime or real_runtime in candidate.parents:
        sys.exit(
            f"Refusing demo-mode access to real runtime directory for {label}: {candidate}"
        )


def _resolve_auth_key(config_auth_key: str, mode: str) -> str:
    env_key = os.environ.get("PASSPORT_AUTH_KEY", "").strip()
    if env_key:
        if not _is_valid_auth_key(env_key):
            sys.exit(
                "PASSPORT_AUTH_KEY must be at least 32 characters and not a placeholder"
            )
        return env_key

    if _is_valid_auth_key(config_auth_key):
        return config_auth_key.strip()

    default_dir = ROOT / ("runtime-demo" if mode == "demo" else "runtime")
    key_file = Path(os.environ.get("PASSPORT_AUTH_FILE") or (default_dir / "auth_key"))
    if mode == "demo":
        _assert_not_real_runtime_path(key_file, "PASSPORT_AUTH_FILE")
    try:
        return ensure_private_secret_file(
            key_file,
            lambda: secrets.token_hex(32),
            _is_valid_auth_key,
            mode=0o600,
        )
    except ValueError as exc:
        sys.exit(f"Existing auth_key file {key_file} is invalid or shorter than 32 chars ({exc})")


def _apply_common_server_overrides(config: dict, mode: str) -> None:
    server = config.get("server")
    if not isinstance(server, dict):
        if mode == "real":
            sys.exit("PASSPORT_MODE=real requires a 'server' mapping in configuration.")
        server = {}
        config["server"] = server

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

    auth = server.get("auth")
    if mode == "real":
        if not isinstance(auth, dict) or auth.get("enabled") is not True:
            sys.exit(
                "PASSPORT_MODE=real requires server.auth.enabled: true; refusing to start "
                "with device authentication disabled or omitted."
            )
    else:
        if auth is None:
            auth = {}
            server["auth"] = auth
        elif not isinstance(auth, dict):
            sys.exit("server.auth must be a YAML mapping")
        if "enabled" in auth and auth.get("enabled") is not True:
            sys.exit(
                "PASSPORT_MODE=demo requires server.auth.enabled: true; refusing to "
                "disable device authentication."
            )
        auth.setdefault("enabled", True)

    default_devices = ROOT / ("runtime-demo" if mode == "demo" else "runtime") / "devices.yaml"
    devices_file_env = os.environ.get("PASSPORT_DEVICES_FILE", "").strip()
    if devices_file_env:
        auth["devices_file"] = devices_file_env
    elif not auth.get("devices_file") and not auth.get("devices"):
        auth["devices_file"] = str(default_devices)

    if mode == "demo" and auth.get("devices_file"):
        _assert_not_real_runtime_path(Path(str(auth["devices_file"])), "devices_file")

    if os.environ.get("PASSPORT_AUTH_EXPIRE_SECONDS", "").strip():
        auth["expire_seconds"] = int(os.environ["PASSPORT_AUTH_EXPIRE_SECONDS"].strip())

    log_level_env = os.environ.get("PASSPORT_LOG_LEVEL", "").strip()
    if log_level_env:
        config.setdefault("log", {})["log_level"] = log_level_env

    log_dir_env = os.environ.get("PASSPORT_LOG_DIR", "").strip()
    if log_dir_env:
        if mode == "demo":
            _assert_not_real_runtime_path(Path(log_dir_env), "PASSPORT_LOG_DIR")
        config.setdefault("log", {})["log_dir"] = log_dir_env

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

    _apply_common_server_overrides(config, mode)

    if mode == "demo":
        _assert_not_real_runtime_path(server_home / "data" / ".config.yaml", "XIAOZHI_HOME")
        log_dir_cfg = config.get("log", {}).get("log_dir")
        if isinstance(log_dir_cfg, str) and log_dir_cfg.strip():
            _assert_not_real_runtime_path(server_home / log_dir_cfg.strip(), "log.log_dir")

    existing_auth_key = str(config.get("server", {}).get("auth_key") or "")
    config["server"]["auth_key"] = _resolve_auth_key(existing_auth_key, mode)

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
