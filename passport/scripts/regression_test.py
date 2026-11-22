#!/usr/bin/env python3
"""Comprehensive regression tests for all 4 blockers and related non-blockers.

Runs against the real xiaozhi-server Python process (via passport_server/runner.py)
and local passport/fake_provider.py. Does not require Docker or real API keys, and
never logs or prints raw experimental tokens/secrets.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

import websockets
import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from contract_test import (
    opus_frames,
    post_json,
    post_ota,
    run_turn,
    send_hello,
    set_fake_control,
    validate_abort_metrics,
)
from passport_server.device_auth import PassportDeviceAuth, hash_ota_secret
from passport_server.fs_utils import atomic_write_private, locked_file
from passport_server.redaction import (
    clear_registered_secrets,
    has_sensitive_query_params,
    install_stdlib_redaction,
    redact_text,
    register_redacted_secret,
    register_secrets_from_config,
    safe_endpoint_label,
    sanitize_headers,
    sanitize_url_or_path,
)

PROXY_SENSITIVE_QUERY_RE = re.compile(
    r"(^|&)(authorization|token|access_token|refresh_token|id_token|secret|ota_secret|key|api_key|apikey|password|sig|signature|auth)=",
    re.IGNORECASE,
)


def _base_env(**overrides: str) -> dict[str, str]:
    """Return a clean environment stripped of inherited PASSPORT_* and XIAOZHI_HOME vars."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("PASSPORT_") and k != "XIAOZHI_HOME"
    }
    env.update(overrides)
    return env


def _make_srv_home(server_home: Path, dst: Path) -> Path:
    """Create an isolated XIAOZHI_HOME directory symlinked to the pinned upstream code."""
    (dst / "data").mkdir(parents=True, exist_ok=True)
    (dst / "tmp").mkdir(parents=True, exist_ok=True)
    for item in ("app.py", "config", "core", "models", "plugins_func", "config.yaml"):
        src = server_home / item
        target = dst / item
        if src.exists() and not target.exists():
            target.symlink_to(src)
    return dst


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _wait_for_http_ready(url: str, proc: subprocess.Popen, log_path: Path, timeout_s: float = 45.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:] if log_path.is_file() else ""
            raise RuntimeError(f"Process exited prematurely ({proc.returncode}):\n{tail}")
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:] if log_path.is_file() else ""
    raise TimeoutError(f"Timed out waiting for {url}:\n{tail}")


def _wait_for_log_substring(paths: list[Path], needle: str, timeout_s: float = 8.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for path in paths:
            if path.is_file() and needle in path.read_text(encoding="utf-8", errors="replace"):
                return
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for log marker {needle!r} in {[str(p) for p in paths]}")


def _stop_process_gracefully(proc: subprocess.Popen, label: str, timeout_s: float = 8.0) -> float:
    if proc.poll() is not None:
        return 0.0
    t0 = time.monotonic()
    proc.send_signal(signal.SIGTERM)
    try:
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise AssertionError(f"{label} did not terminate within {timeout_s}s on SIGTERM")
    elapsed = time.monotonic() - t0
    if rc not in (0, -signal.SIGTERM, 143):
        raise AssertionError(f"{label} exited with unexpected status {rc} on SIGTERM")
    return elapsed


def _snapshot_files(paths: list[Path]) -> dict[Path, Optional[bytes]]:
    return {p: (p.read_bytes() if p.is_file() else None) for p in paths}


def _assert_files_unchanged(before: dict[Path, Optional[bytes]], context: str) -> None:
    for path, old_bytes in before.items():
        new_bytes = path.read_bytes() if path.is_file() else None
        assert new_bytes == old_bytes, (
            f"{context}: state file {path} changed (before={len(old_bytes) if old_bytes is not None else None} bytes, "
            f"after={len(new_bytes) if new_bytes is not None else None} bytes)"
        )


def assert_logs_redacted(
    required_server_logs: list[Path],
    forbidden_literals: set[str],
    extra_logs: Optional[list[Path]] = None,
    required_markers: Optional[list[str]] = None,
    require_conn_headers: bool = True,
) -> None:
    """Blocker #3: require both stdout and file logs to exist and verify zero credential leakage."""
    assert required_server_logs, "required_server_logs must not be empty"

    for path in required_server_logs:
        assert path.is_file(), f"Required server log file is missing: {path}"
        content = path.read_text(encoding="utf-8", errors="replace")
        assert len(content) > 100, f"Required server log {path} unexpectedly empty ({len(content)} bytes)"
        if require_conn_headers:
            assert "conn - Headers:" in content, f"Expected INFO connection log line in {path}"
        if required_markers:
            for marker in required_markers:
                assert marker in content, f"Expected log marker {marker!r} missing in {path}"

    all_logs = list(required_server_logs) + list(extra_logs or [])
    for path in all_logs:
        assert path.is_file(), f"Required log file is missing: {path}"
        content = path.read_text(encoding="utf-8", errors="replace")

        for secret in forbidden_literals:
            if secret and len(secret) >= 6:
                assert secret not in content, f"Secret literal leaked into {path}!"

        unredacted_bearer = re.findall(
            r"Bearer\s+(?!\[REDACTED\])([A-Za-z0-9._~+/=-]{6,})", content
        )
        assert not unredacted_bearer, (
            f"Found {len(unredacted_bearer)} unredacted Bearer token(s) in {path}"
        )

        unredacted_jwt = re.findall(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])",
            content,
        )
        assert not unredacted_jwt, (
            f"Found {len(unredacted_jwt)} unredacted JWT(s) in {path}"
        )

        unredacted_userinfo = re.findall(
            r"(?i)\b(?:https?|wss?)://(?!\[REDACTED\]@)[^/\s@\"'<>]+@",
            content,
        )
        assert not unredacted_userinfo, (
            f"Found {len(unredacted_userinfo)} unredacted URL userinfo value(s) in {path}"
        )

        for match in re.finditer(r"conn - Headers:\s*(\{[^\n]+\})", content):
            line = match.group(1).lower()
            assert "'authorization':" not in line and '"authorization":' not in line, (
                f"Authorization header present in conn - Headers in {path}: {line}"
            )


def test_unit_redaction_permissions_and_strict_abort() -> None:
    # 1. Redaction helpers
    secret_a = "exp_ota_" + secrets.token_hex(12)
    bearer_tok = "exp_ws_" + secrets.token_urlsafe(18) + ".1700000000"
    query_tok = "exp_q_" + secrets.token_hex(10)
    userinfo_user = "exp_usr_" + secrets.token_hex(6)
    userinfo_pass = "exp_pwd_" + secrets.token_hex(8)
    jwt_tok = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJkYXRhIjoiZXhwX3BheWxvYWRf" + secrets.token_hex(6) + "In0."
        "sig_" + secrets.token_hex(12) + "_"
    )
    bare_cfg_secret = "exp_bare_" + secrets.token_hex(10)

    sample_log = (
        f"GET /xiaozhi/ota/d/{secret_a}/?token={query_tok}&foo=bar "
        f"Authorization: Bearer {bearer_tok} "
        f"https://{userinfo_user}:{userinfo_pass}@asr.example.com:8443/v1/audio?api_key={query_tok} "
        f'{{"type":"mcp","payload":{{"params":{{"capabilities":{{"vision":{{"token":"{jwt_tok}"}}}}}}}}}} '
        f"{{'device-id': 'aa:bb', 'authorization': 'Bearer {bearer_tok}', 'x-ota-secret': '{secret_a}'}}"
    )
    redacted = redact_text(sample_log)
    for forbidden in (secret_a, bearer_tok, query_tok, userinfo_user, userinfo_pass, jwt_tok):
        assert forbidden not in redacted, f"Secret leaked after redact_text: {redacted}"
    assert "[REDACTED]" in redacted

    clean_url = sanitize_url_or_path(
        f"https://{userinfo_user}:{userinfo_pass}@example.com:8443/xiaozhi/ota/d/{secret_a}/?authorization=Bearer+{bearer_tok}&v=1"
    )
    for forbidden in (secret_a, bearer_tok, userinfo_user, userinfo_pass):
        assert forbidden not in clean_url
    assert "/xiaozhi/ota/d/[REDACTED]/" in clean_url
    assert "[REDACTED]@example.com:8443" in clean_url

    endpoint_lbl = safe_endpoint_label(
        f"https://{userinfo_user}:{userinfo_pass}@asr.example.com:8443/v1/audio/transcriptions?api_key={query_tok}"
    )
    assert endpoint_lbl == "https://asr.example.com:8443/v1/audio/transcriptions", endpoint_lbl

    try:
        register_secrets_from_config(
            {
                "server": {"auth_key": bare_cfg_secret},
                "ASR": {"CustomASR": {"api_key": bare_cfg_secret}},
            }
        )
        register_redacted_secret(bare_cfg_secret)
        assert bare_cfg_secret not in redact_text(f"upstream echoed {bare_cfg_secret}")
    finally:
        clear_registered_secrets()

    # Verify stdlib child logger propagation to root handlers is also redacted.
    install_stdlib_redaction()
    root_logger = logging.getLogger()
    captured_records: list[str] = []

    class _ListHandler(logging.Handler):
        def emit(self, record):
            captured_records.append(self.format(record))

    list_handler = _ListHandler()
    root_logger.addHandler(list_handler)
    child_logger = logging.getLogger("httpcore.http11")
    old_level = child_logger.level
    child_logger.setLevel(logging.DEBUG)
    try:
        child_logger.debug("send_request_headers https://%s:%s@asr.example/v1 Authorization: Bearer %s", userinfo_user, userinfo_pass, bearer_tok)
    finally:
        child_logger.setLevel(old_level)
        root_logger.removeHandler(list_handler)
    joined_child = "\n".join(captured_records)
    for forbidden in (userinfo_user, userinfo_pass, bearer_tok):
        assert forbidden not in joined_child, "Propagated stdlib DEBUG log leaked credential!"

    assert has_sensitive_query_params("/xiaozhi/v1/?token=abc")
    assert not has_sensitive_query_params("/xiaozhi/v1/?from=mqtt_gateway")

    clean_headers = sanitize_headers(
        {
            "Device-Id": "aa:bb:cc:dd:ee:01",
            "Authorization": f"Bearer {bearer_tok}",
            "X-OTA-Secret": secret_a,
        }
    )
    assert bearer_tok not in json.dumps(clean_headers)
    assert secret_a not in json.dumps(clean_headers)
    assert clean_headers["authorization"] == "[REDACTED]"

    # Negative check: assert_logs_redacted MUST fail if a required log file is missing.
    with tempfile.TemporaryDirectory() as tmpdir:
        missing_log = Path(tmpdir) / "missing-server.log"
        present_log = Path(tmpdir) / "stdout.log"
        present_log.write_text("x" * 120 + "\nconn - Headers: {'device-id': 'aa:bb'}\n", encoding="utf-8")
        try:
            assert_logs_redacted([present_log, missing_log], set())
        except AssertionError:
            pass
        else:
            raise AssertionError("assert_logs_redacted must fail when a required log file is missing")

    # 2. Strict abort assertion MUST fail on unaborted playback, short baseline, or short observation window
    synthetic_unaborted = {
        "aborted": True,
        "tts_states": ["start", "stop"],
        "opus_frame_count": 100,
        "tail_frames_after_abort": 98,
        "frames_after_stop": 0,
        "post_stop_observed_s": 0.5,
        "abort_stop_latency_s": 5.8,
    }
    assert validate_abort_metrics(synthetic_unaborted, baseline_long_frames=100), (
        "validate_abort_metrics must fail when full audio plays to natural stop"
    )
    synthetic_short = {
        "aborted": True,
        "tts_states": ["start", "stop"],
        "opus_frame_count": 12,
        "tail_frames_after_abort": 10,
        "frames_after_stop": 0,
        "post_stop_observed_s": 0.5,
        "abort_stop_latency_s": 0.2,
    }
    assert validate_abort_metrics(synthetic_short, baseline_long_frames=12), (
        "validate_abort_metrics must fail when baseline audio is not long"
    )
    synthetic_early_drain = {
        "aborted": True,
        "tts_states": ["start", "stop"],
        "opus_frame_count": 5,
        "tail_frames_after_abort": 3,
        "frames_after_stop": 0,
        "post_stop_observed_s": 0.1,
        "abort_stop_latency_s": 0.1,
    }
    assert validate_abort_metrics(synthetic_early_drain, baseline_long_frames=95), (
        "validate_abort_metrics must fail when post-stop observation window stops early"
    )
    assert not validate_abort_metrics(
        {**synthetic_early_drain, "post_stop_observed_s": 0.5},
        baseline_long_frames=95,
    )

    # 3. Atomic 0600 file creation even under permissive 0022 umask
    with tempfile.TemporaryDirectory() as tmpdir:
        old_umask = os.umask(0o022)
        try:
            priv_path = Path(tmpdir) / "secret_test.yaml"
            atomic_write_private(priv_path, "test: 1\n", mode=0o600)
            assert stat.S_IMODE(priv_path.stat().st_mode) == 0o600
        finally:
            os.umask(old_umask)
    print("[PASS] unit tests: redaction, stdlib propagation, missing-log fail gate, strict abort gate, atomic 0600 write")


def test_concurrent_registry_locking_and_auth_key() -> None:
    """Non-blocker #7: cross-process flock prevents lost revocations and duplicate auth_key creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        devices_file = tmp / "devices.yaml"

        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "provision_device.py"),
                "add",
                "--devices-file",
                str(devices_file),
                "--device-id",
                "aa:bb:cc:dd:ee:11",
                "--client-id",
                "lock-client-1",
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        dev2_initial = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "add",
                    "--devices-file",
                    str(devices_file),
                    "--device-id",
                    "aa:bb:cc:dd:ee:12",
                    "--client-id",
                    "lock-client-2",
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )

        # 1. Hold sidecar lock briefly while revoke + add contend concurrently.
        with locked_file(devices_file):
            p_rev = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "revoke",
                    "--devices-file",
                    str(devices_file),
                    "--device-id",
                    "aa:bb:cc:dd:ee:11",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            p_add = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "add",
                    "--devices-file",
                    str(devices_file),
                    "--device-id",
                    "aa:bb:cc:dd:ee:99",
                    "--client-id",
                    "lock-client-99",
                    "--json",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.3)
            # Neither CLI command may finish while the lock is held.
            assert p_rev.poll() is None and p_add.poll() is None, (
                "provision_device.py proceeded without acquiring devices.yaml flock"
            )

        out_rev, err_rev = p_rev.communicate(timeout=10)
        out_add, err_add = p_add.communicate(timeout=10)
        assert p_rev.returncode == 0, f"concurrent revoke failed: {out_rev} {err_rev}"
        assert p_add.returncode == 0, f"concurrent add failed: {out_add} {err_add}"

        # 2. Launch 10 concurrent writers (1 revoke + 1 rotate + 8 adds).
        procs = []
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "revoke",
                    "--devices-file",
                    str(devices_file),
                    "--device-id",
                    "aa:bb:cc:dd:ee:99",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
        rotated_secret = "rot_" + secrets.token_urlsafe(18)
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "rotate",
                    "--devices-file",
                    str(devices_file),
                    "--device-id",
                    "aa:bb:cc:dd:ee:12",
                    "--secret",
                    rotated_secret,
                    "--json",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
        added_ids = []
        for idx in range(8):
            dev_id = f"aa:bb:cc:dd:ff:{idx:02x}"
            added_ids.append(dev_id)
            procs.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "provision_device.py"),
                        "add",
                        "--devices-file",
                        str(devices_file),
                        "--device-id",
                        dev_id,
                        "--client-id",
                        f"burst-client-{idx}",
                        "--json",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        for p in procs:
            out, err = p.communicate(timeout=15)
            assert p.returncode == 0, f"concurrent CLI update failed: {out} {err}"

        parsed = yaml.safe_load(devices_file.read_text(encoding="utf-8"))
        by_id = {entry["device_id"]: entry for entry in parsed["devices"]}
        assert by_id["aa:bb:cc:dd:ee:11"]["enabled"] is False
        assert by_id["aa:bb:cc:dd:ee:99"]["enabled"] is False
        assert by_id["aa:bb:cc:dd:ee:12"]["ota_secret_sha256"] == hash_ota_secret(rotated_secret)
        assert by_id["aa:bb:cc:dd:ee:12"]["ota_secret_sha256"] != hash_ota_secret(dev2_initial["ota_secret"])
        for dev_id in added_ids:
            assert dev_id in by_id and by_id[dev_id]["enabled"] is True, f"lost concurrent add for {dev_id}"
        assert stat.S_IMODE(devices_file.stat().st_mode) == 0o600

        # 3. Concurrent first-time auth_key creation across 6 processes.
        shared_auth_file = tmp / "shared_auth_key"
        shared_devices_file = tmp / "shared_devices.yaml"
        key_procs = []
        homes = []
        for idx in range(6):
            h = tmp / f"home_{idx}"
            (h / "data").mkdir(parents=True)
            homes.append(h)
            env = _base_env(
                XIAOZHI_HOME=str(h),
                PASSPORT_MODE="demo",
                PASSPORT_AUTH_FILE=str(shared_auth_file),
                PASSPORT_DEVICES_FILE=str(shared_devices_file),
            )
            key_procs.append(
                subprocess.Popen(
                    [sys.executable, str(ROOT / "scripts" / "write_config.py")],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        for p in key_procs:
            out, err = p.communicate(timeout=15)
            assert p.returncode == 0, f"concurrent write_config failed: {out} {err}"

        final_key = shared_auth_file.read_text(encoding="utf-8").strip()
        assert len(final_key) >= 32
        assert stat.S_IMODE(shared_auth_file.stat().st_mode) == 0o600
        for h in homes:
            cfg = yaml.safe_load((h / "data" / ".config.yaml").read_text(encoding="utf-8"))
            assert cfg["server"]["auth_key"] == final_key, "concurrent write_config saw mismatched auth_key"
    print("[PASS] non-blocker #7: cross-process flock preserves concurrent revocations/adds/rotates and auth_key")


def test_real_mode_refuses_disabled_or_missing_auth(server_home: Path) -> None:
    """Blocker #4: real mode MUST refuse startup when server.auth.enabled is false or omitted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        devices_file = tmp / "devices.yaml"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "provision_device.py"),
                "add",
                "--devices-file",
                str(devices_file),
                "--device-id",
                "aa:bb:cc:dd:ee:55",
                "--client-id",
                "real-auth-check",
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        def _write_cfg(path: Path, auth_obj, include_auth: bool = True, auth_key: Optional[str] = None) -> None:
            server_block = {
                "ip": "127.0.0.1",
                "port": _free_port(),
                "http_port": _free_port(),
                "websocket": "wss://passport.real.example/xiaozhi/v1/",
                "vision_explain": "https://passport.real.example/mcp/vision/explain",
            }
            if auth_key:
                server_block["auth_key"] = auth_key
            if include_auth:
                server_block["auth"] = auth_obj
            payload = {
                "server": server_block,
                "log": {"log_dir": str(tmp / "logs")},
                "selected_module": {
                    "VAD": "SileroVAD",
                    "ASR": "CustomRealASR",
                    "LLM": "CustomRealLLM",
                    "TTS": "CustomRealTTS",
                    "Memory": "nomem",
                    "Intent": "nointent",
                },
                "ASR": {
                    "CustomRealASR": {
                        "type": "openai",
                        "api_key": "real-asr-placeholder-for-auth-check",
                        "base_url": "https://asr.real.example/v1/audio/transcriptions",
                        "model_name": "whisper-real",
                        "output_dir": "tmp/",
                    }
                },
                "LLM": {
                    "CustomRealLLM": {
                        "type": "openai",
                        "api_key": "real-llm-placeholder-for-auth-check",
                        "base_url": "https://llm.real.example/v1",
                        "model_name": "gpt-real",
                    }
                },
                "TTS": {
                    "CustomRealTTS": {
                        "type": "openai",
                        "api_key": "real-tts-placeholder-for-auth-check",
                        "api_url": "https://tts.real.example/v1/audio/speech",
                        "model": "tts-real",
                        "voice": "alloy",
                        "format": "wav",
                        "output_dir": "tmp/",
                    }
                },
            }
            path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

        cases = [
            ("auth_disabled", {"enabled": False, "devices_file": str(devices_file)}, True),
            ("auth_omitted", None, False),
            ("auth_enabled_missing", {"devices_file": str(devices_file)}, True),
        ]
        for idx, (label, auth_obj, include_auth) in enumerate(cases):
            home_dir = _make_srv_home(server_home, tmp / f"home_{idx}")
            cfg_path = tmp / f"cfg_{idx}.yaml"
            _write_cfg(cfg_path, auth_obj, include_auth=include_auth)
            env = _base_env(
                XIAOZHI_HOME=str(home_dir),
                PASSPORT_MODE="real",
                PASSPORT_CONFIG_FILE=str(cfg_path),
                PASSPORT_AUTH_FILE=str(tmp / f"auth_key_{idx}"),
                PASSPORT_DEVICES_FILE=str(devices_file),
                PASSPORT_PYTHON=sys.executable,
            )
            res = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "write_config.py")],
                env=env,
                capture_output=True,
                text=True,
            )
            assert res.returncode != 0, f"write_config.py accepted {label} in real mode!"
            assert not (home_dir / "data" / ".config.yaml").exists(), (
                f"write_config.py wrote data/.config.yaml on {label}"
            )

        # Also check entrypoint.sh refuses disabled auth in real mode.
        entry_home = _make_srv_home(server_home, tmp / "entry_disabled_home")
        entry_cfg = tmp / "entry_disabled.yaml"
        _write_cfg(entry_cfg, {"enabled": False, "devices_file": str(devices_file)}, include_auth=True)
        entry_res = subprocess.run(
            ["sh", str(ROOT / "scripts" / "entrypoint.sh")],
            env=_base_env(
                XIAOZHI_HOME=str(entry_home),
                PASSPORT_MODE="real",
                PASSPORT_CONFIG_FILE=str(entry_cfg),
                PASSPORT_AUTH_FILE=str(tmp / "entry_auth_key"),
                PASSPORT_DEVICES_FILE=str(devices_file),
                PASSPORT_PYTHON=sys.executable,
            ),
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert entry_res.returncode != 0, "entrypoint.sh must fail when server.auth.enabled is false"

        # Bypass write_config.py and run runner.py directly on rendered data/.config.yaml.
        valid_hex_key = secrets.token_hex(32)
        for idx, (label, auth_obj, include_auth) in enumerate(cases[:2]):
            direct_home = _make_srv_home(server_home, tmp / f"direct_{idx}")
            _write_cfg(
                direct_home / "data" / ".config.yaml",
                auth_obj,
                include_auth=include_auth,
                auth_key=valid_hex_key,
            )
            direct_res = subprocess.run(
                [sys.executable, str(ROOT / "passport_server" / "runner.py")],
                env=_base_env(
                    XIAOZHI_HOME=str(direct_home),
                    PASSPORT_MODE="real",
                    PASSPORT_LOG_DIR=str(direct_home / "tmp"),
                ),
                capture_output=True,
                text=True,
                timeout=20,
            )
            assert direct_res.returncode != 0, f"runner.py allowed {label} in real mode!"
            combined_out = direct_res.stdout + direct_res.stderr
            assert "server.auth.enabled: true" in combined_out, (
                f"runner.py exited for {label} without auth validation error: {combined_out}"
            )
    print("[PASS] blocker #4 startup failure: real mode refuses server.auth.enabled=false and missing auth")


def test_real_vs_demo_config_persistence(server_home: Path) -> None:
    """Blocker #4: real config must not be overwritten by fake providers and must survive restarts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        home_copy = tmp / "server_home"
        (home_copy / "data").mkdir(parents=True)

        # 4a. PASSPORT_MODE=real fails closed when config file does not exist.
        missing_cfg = tmp / "nonexistent.yaml"
        env_missing = _base_env(
            XIAOZHI_HOME=str(home_copy),
            PASSPORT_MODE="real",
            PASSPORT_CONFIG_FILE=str(missing_cfg),
            PASSPORT_AUTH_FILE=str(tmp / "auth_key"),
            PASSPORT_DEVICES_FILE=str(tmp / "devices.yaml"),
        )
        res_missing = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write_config.py")],
            env=env_missing,
            capture_output=True,
            text=True,
        )
        assert res_missing.returncode != 0, "PASSPORT_MODE=real must fail when real config is missing"

        # 4b. PASSPORT_MODE=real preserves real providers even if PASSPORT_FAKE_BASE is set, and across restarts.
        real_cfg = tmp / "server.config.yaml"
        real_cfg.write_text(
            yaml.safe_dump(
                {
                    "server": {
                        "ip": "127.0.0.1",
                        "port": 18910,
                        "http_port": 18913,
                        "websocket": "wss://passport.real.example/xiaozhi/v1/",
                        "vision_explain": "https://passport.real.example/mcp/vision/explain",
                        "auth": {"enabled": True, "allowed_devices": []},
                    },
                    "selected_module": {
                        "VAD": "SileroVAD",
                        "ASR": "CustomRealASR",
                        "LLM": "CustomRealLLM",
                        "TTS": "CustomRealTTS",
                        "Memory": "nomem",
                        "Intent": "nointent",
                    },
                    "ASR": {
                        "CustomRealASR": {
                            "type": "openai",
                            "api_key": "real-asr-placeholder-for-config-test",
                            "base_url": "https://asr.real.example/v1/audio/transcriptions",
                            "model_name": "whisper-real",
                            "output_dir": "tmp/",
                        }
                    },
                    "LLM": {
                        "CustomRealLLM": {
                            "type": "openai",
                            "api_key": "real-llm-placeholder-for-config-test",
                            "base_url": "https://llm.real.example/v1",
                            "model_name": "gpt-real",
                        }
                    },
                    "TTS": {
                        "CustomRealTTS": {
                            "type": "openai",
                            "api_key": "real-tts-placeholder-for-config-test",
                            "api_url": "https://tts.real.example/v1/audio/speech",
                            "model": "tts-real",
                            "voice": "alloy",
                            "format": "wav",
                            "output_dir": "tmp/",
                        }
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        auth_file = tmp / "auth_key"
        devices_file = tmp / "devices.yaml"
        env_real = _base_env(
            XIAOZHI_HOME=str(home_copy),
            PASSPORT_MODE="real",
            PASSPORT_CONFIG_FILE=str(real_cfg),
            PASSPORT_AUTH_FILE=str(auth_file),
            PASSPORT_DEVICES_FILE=str(devices_file),
            PASSPORT_FAKE_BASE="http://127.0.0.1:18019",
        )
        old_umask = os.umask(0o022)
        try:
            for restart_round in range(2):
                res_real = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / "write_config.py")],
                    env=env_real,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                assert "mode=real" in res_real.stdout
                rendered_path = home_copy / "data" / ".config.yaml"
                rendered = yaml.safe_load(rendered_path.read_text(encoding="utf-8"))
                assert rendered["selected_module"]["ASR"] == "CustomRealASR", f"round {restart_round}"
                assert rendered["selected_module"]["LLM"] == "CustomRealLLM"
                assert rendered["selected_module"]["TTS"] == "CustomRealTTS"
                assert rendered["ASR"]["CustomRealASR"]["base_url"] == "https://asr.real.example/v1/audio/transcriptions"
                assert "PassportLocalASR" not in (rendered.get("ASR") or {})
                assert stat.S_IMODE(rendered_path.stat().st_mode) == 0o600
                assert stat.S_IMODE(auth_file.stat().st_mode) == 0o600
        finally:
            os.umask(old_umask)

        # Verify upstream config_loader loads the exact real providers across simulated restarts.
        probe_script = (
            "import asyncio, json, os, sys; "
            f"os.chdir({str(server_home)!r}); "
            "from config.config_loader import read_config, merge_configs; "
            "d = read_config('config.yaml'); "
            f"c = read_config({str(home_copy / 'data' / '.config.yaml')!r}); "
            "m = merge_configs(d, c); "
            "print(json.dumps({'selected': m['selected_module'], 'asr_url': m['ASR']['CustomRealASR']['base_url']}))"
        )
        probe = subprocess.run(
            [sys.executable, "-c", probe_script],
            env=_base_env(),
            capture_output=True,
            text=True,
            check=True,
        )
        loaded_real = json.loads(probe.stdout)
        assert loaded_real["selected"]["ASR"] == "CustomRealASR"
        assert loaded_real["asr_url"] == "https://asr.real.example/v1/audio/transcriptions"

        # 4c. Explicit PASSPORT_MODE=demo uses fake providers.
        env_demo = _base_env(
            XIAOZHI_HOME=str(home_copy),
            PASSPORT_MODE="demo",
            PASSPORT_AUTH_FILE=str(auth_file),
            PASSPORT_DEVICES_FILE=str(devices_file),
            PASSPORT_FAKE_BASE="http://127.0.0.1:19999",
        )
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write_config.py")],
            env=env_demo,
            capture_output=True,
            text=True,
            check=True,
        )
        demo_rendered = yaml.safe_load((home_copy / "data" / ".config.yaml").read_text(encoding="utf-8"))
        assert demo_rendered["selected_module"]["ASR"] == "PassportLocalASR"
        assert demo_rendered["ASR"]["PassportLocalASR"]["base_url"] == "http://127.0.0.1:19999/v1/audio/transcriptions"

        # 4d. End-to-end real-mode launch via entrypoint.sh -> SIGTERM -> restart keeps real providers.
        e2e_provider_port = _free_port()
        e2e_ws_port = _free_port()
        e2e_http_port = _free_port()
        e2e_home = _make_srv_home(server_home, tmp / "e2e_real_home")

        e2e_devices = tmp / "e2e_devices.yaml"
        e2e_auth = tmp / "e2e_auth_key"
        e2e_dev = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "add",
                    "--devices-file",
                    str(e2e_devices),
                    "--device-id",
                    "aa:bb:cc:dd:ee:44",
                    "--client-id",
                    "passport-real-mode-client",
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        e2e_real_cfg = tmp / "e2e_server.config.yaml"
        e2e_real_cfg.write_text(
            yaml.safe_dump(
                {
                    "server": {
                        "ip": "127.0.0.1",
                        "port": e2e_ws_port,
                        "http_port": e2e_http_port,
                        "websocket": f"ws://127.0.0.1:{e2e_ws_port}/xiaozhi/v1/",
                        "vision_explain": f"http://127.0.0.1:{e2e_http_port}/mcp/vision/explain",
                        "auth": {"enabled": True, "allowed_devices": []},
                    },
                    "read_config_from_api": False,
                    "enable_wakeup_words_response_cache": False,
                    "enable_greeting": False,
                    "end_prompt": {"enable": False},
                    "xiaozhi": {
                        "type": "hello",
                        "version": 1,
                        "transport": "websocket",
                        "audio_params": {
                            "format": "opus",
                            "sample_rate": 16000,
                            "channels": 1,
                            "frame_duration": 60,
                        },
                    },
                    "selected_module": {
                        "VAD": "SileroVAD",
                        "ASR": "CustomRealASR",
                        "LLM": "CustomRealLLM",
                        "TTS": "CustomRealTTS",
                        "Memory": "nomem",
                        "Intent": "nointent",
                    },
                    "VAD": {
                        "SileroVAD": {
                            "type": "silero",
                            "threshold": 0.5,
                            "threshold_low": 0.3,
                            "model_dir": "models/snakers4_silero-vad",
                            "min_silence_duration_ms": 200,
                        }
                    },
                    "ASR": {
                        "CustomRealASR": {
                            "type": "openai",
                            "api_key": "local-fake-provider",
                            "base_url": f"http://127.0.0.1:{e2e_provider_port}/v1/audio/transcriptions",
                            "model_name": "custom-real-asr",
                            "output_dir": "tmp/",
                        }
                    },
                    "LLM": {
                        "CustomRealLLM": {
                            "type": "openai",
                            "api_key": "local-fake-provider",
                            "base_url": f"http://127.0.0.1:{e2e_provider_port}/v1",
                            "model_name": "custom-real-llm",
                        }
                    },
                    "TTS": {
                        "CustomRealTTS": {
                            "type": "openai",
                            "api_key": "local-fake-provider",
                            "api_url": f"http://127.0.0.1:{e2e_provider_port}/v1/audio/speech",
                            "model": "custom-real-tts",
                            "voice": "alloy",
                            "format": "wav",
                            "output_dir": "tmp/",
                        }
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        e2e_provider_log = tmp / "e2e-provider.log"
        with open(e2e_provider_log, "w", encoding="utf-8") as pout:
            e2e_provider_proc = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "fake_provider.py"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(e2e_provider_port),
                ],
                stdout=pout,
                stderr=subprocess.STDOUT,
            )
        try:
            _wait_for_http_ready(
                f"http://127.0.0.1:{e2e_provider_port}/_stats",
                e2e_provider_proc,
                e2e_provider_log,
            )
            post_json(
                f"http://127.0.0.1:{e2e_provider_port}/_control",
                {},
                {"transcript": "真实模式配置校验"},
            )
            e2e_env = _base_env(
                XIAOZHI_HOME=str(e2e_home),
                PASSPORT_MODE="real",
                PASSPORT_CONFIG_FILE=str(e2e_real_cfg),
                PASSPORT_AUTH_FILE=str(e2e_auth),
                PASSPORT_DEVICES_FILE=str(e2e_devices),
                PASSPORT_LOG_DIR=str(e2e_home / "tmp"),
                PASSPORT_PYTHON=sys.executable,
                PASSPORT_FAKE_BASE="http://127.0.0.1:18019",
            )
            issued_tokens = {e2e_dev["ota_secret"]}
            for round_idx in range(2):
                entry_log = tmp / f"e2e-entrypoint-{round_idx}.log"
                with open(entry_log, "w", encoding="utf-8") as eout:
                    entry_proc = subprocess.Popen(
                        ["sh", str(ROOT / "scripts" / "entrypoint.sh")],
                        env=e2e_env,
                        stdout=eout,
                        stderr=subprocess.STDOUT,
                    )
                try:
                    _wait_for_http_ready(
                        f"http://127.0.0.1:{e2e_http_port}/xiaozhi/ota/",
                        entry_proc,
                        entry_log,
                    )
                    rendered_e2e = yaml.safe_load(
                        (e2e_home / "data" / ".config.yaml").read_text(encoding="utf-8")
                    )
                    assert rendered_e2e["selected_module"]["ASR"] == "CustomRealASR"
                    assert "PassportLocalASR" not in (rendered_e2e.get("ASR") or {})

                    st_e2e, ota_e2e = post_ota(
                        f"http://127.0.0.1:{e2e_http_port}",
                        {"Device-Id": e2e_dev["device_id"], "Client-Id": e2e_dev["client_id"]},
                        secret=e2e_dev["ota_secret"],
                    )
                    assert st_e2e == 200
                    tok_e2e = ota_e2e["websocket"]["token"]
                    issued_tokens.add(tok_e2e)

                    async def _one_real_turn() -> dict:
                        hdrs = {
                            "Device-Id": e2e_dev["device_id"],
                            "Client-Id": e2e_dev["client_id"],
                            "Protocol-Version": "1",
                            "Authorization": f"Bearer {tok_e2e}",
                        }
                        async with websockets.connect(
                            ota_e2e["websocket"]["url"], additional_headers=hdrs
                        ) as ws:
                            hello = await send_hello(ws)
                            return await run_turn(ws, hello["session_id"])

                    turn_e2e = asyncio.run(_one_real_turn())
                    assert "真实模式配置校验" in "".join(turn_e2e["stt"]), turn_e2e
                finally:
                    _stop_process_gracefully(entry_proc, f"entrypoint-real-{round_idx}")
                log_txt = entry_log.read_text(encoding="utf-8", errors="replace")
                assert "服务器已关闭，程序退出。" in log_txt, (
                    f"entrypoint.sh round {round_idx} did not exec/forward SIGTERM cleanly"
                )
            assert_logs_redacted(
                [tmp / "e2e-entrypoint-1.log", e2e_home / "tmp" / "server.log"],
                issued_tokens,
            )
        finally:
            e2e_provider_proc.terminate()
            e2e_provider_proc.wait(timeout=5)
    print("[PASS] blocker #4: real config preserved across entrypoint.sh restarts and separated from demo mode")


def _tree_signature(root: Path) -> dict[str, tuple[int, int]]:
    """Name/size/mtime signature of a tree (ignoring __pycache__) to detect installs."""
    sig: dict[str, tuple[int, int]] = {}
    base = root.resolve()
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in dirnames:
            sig[str(Path(dirpath, name).relative_to(base)) + "/"] = (0, 0)
        for name in filenames:
            path = Path(dirpath, name)
            st = path.lstat()
            sig[str(path.relative_to(base))] = (st.st_size, st.st_mtime_ns)
    return sig


def _compose_env_dict(value) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): ("" if v is None else str(v)) for k, v in value.items()}
    out: dict[str, str] = {}
    for item in value or []:
        key, _, val = str(item).partition("=")
        out[key] = val
    return out


def _compose_merge(base: dict, override: dict) -> dict:
    """Model of `docker compose -f base -f override` merge rules for the fields we use."""
    import copy

    merged = copy.deepcopy(base)
    if "name" in override:
        merged["name"] = override["name"]
    services = merged.setdefault("services", {})
    for svc_name, o_cfg in (override.get("services") or {}).items():
        b_cfg = services.setdefault(svc_name, {})
        for key, val in o_cfg.items():
            if key == "environment":
                env = _compose_env_dict(b_cfg.get("environment"))
                env.update(_compose_env_dict(val))
                b_cfg[key] = env
            elif key == "volumes":
                by_target: dict[str, str] = {}
                for vol in list(b_cfg.get("volumes") or []) + list(val or []):
                    by_target[str(vol).split(":")[1]] = str(vol)
                b_cfg[key] = list(by_target.values())
            elif key == "ports":
                b_cfg[key] = list(dict.fromkeys([str(p) for p in (b_cfg.get("ports") or []) + list(val or [])]))
            elif isinstance(val, dict) and isinstance(b_cfg.get(key), dict):
                b_cfg[key] = {**b_cfg[key], **val}
            else:
                b_cfg[key] = copy.deepcopy(val)
    for svc in services.values():
        if "environment" in svc:
            svc["environment"] = _compose_env_dict(svc["environment"])
    return merged


def _compose_project_name(argv: list[str], env: dict[str, str], file_name: str) -> str:
    """Compose precedence: -p/--project-name > COMPOSE_PROJECT_NAME > top-level name."""
    for idx, arg in enumerate(argv):
        if arg in ("-p", "--project-name") and idx + 1 < len(argv):
            return argv[idx + 1]
        if arg.startswith("--project-name="):
            return arg.split("=", 1)[1]
    if env.get("COMPOSE_PROJECT_NAME"):
        return env["COMPOSE_PROJECT_NAME"]
    return file_name


def test_demo_isolation_preserves_real_state(server_home: Path) -> None:
    """Blocker #1: run_isolated.sh & demo Compose MUST NOT delete or alter real devices.yaml / auth_key / config."""
    real_files = [
        ROOT / "runtime" / "devices.yaml",
        ROOT / "runtime" / "auth_key",
        server_home / "data" / ".config.yaml",
        ROOT / "config" / "server.config.yaml",
    ]
    real_before = _snapshot_files(real_files)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        passport_copy = tmp / "passport_copy"
        passport_copy.mkdir(parents=True)

        ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
        for subdir in ("config", "passport_server", "scripts"):
            shutil.copytree(ROOT / subdir, passport_copy / subdir, ignore=ignore)
        for file_name in ("fake_provider.py", "requirements-runtime.txt"):
            shutil.copy2(ROOT / file_name, passport_copy / file_name)

        copy_runtime = passport_copy / "runtime"
        copy_runtime.mkdir(parents=True)
        (copy_runtime / "venv").symlink_to(ROOT / "runtime" / "venv")
        (copy_runtime / "xiaozhi-esp32-server").symlink_to(ROOT / "runtime" / "xiaozhi-esp32-server")

        copy_devices = copy_runtime / "devices.yaml"
        for mac, cid in (("aa:bb:cc:dd:ee:81", "real-sim-1"), ("aa:bb:cc:dd:ee:82", "real-sim-2")):
            subprocess.run(
                [
                    sys.executable,
                    str(passport_copy / "scripts" / "provision_device.py"),
                    "add",
                    "--devices-file",
                    str(copy_devices),
                    "--device-id",
                    mac,
                    "--client-id",
                    cid,
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        copy_auth = copy_runtime / "auth_key"
        atomic_write_private(copy_auth, secrets.token_hex(32) + "\n", mode=0o600)
        copy_before = _snapshot_files([copy_devices, copy_auth])

        # Pre-seed every demo output path as a link to a "real" state file: shell
        # `>` redirections and writers must unlink, never truncate/rewrite targets.
        demo_root = passport_copy / "runtime-demo"
        (demo_root / "xiaozhi-home" / "tmp").mkdir(parents=True)
        (demo_root / "xiaozhi-home" / "data").mkdir(parents=True)
        real_srv_log = copy_runtime / "real-server.log"
        real_cfg_yaml = copy_runtime / "real-config.yaml"
        real_fake_log = copy_runtime / "real-fake.log"
        for real_path in (real_srv_log, real_cfg_yaml, real_fake_log):
            real_path.write_text(f"real-state-{real_path.name}\n", encoding="utf-8")
        symlinked_outputs = {
            demo_root / "xiaozhi-server.log": copy_devices,
            demo_root / "auth_key": copy_auth,
            demo_root / "devices.yaml": copy_devices,
            demo_root / "xiaozhi-home" / "tmp" / "server.log": real_srv_log,
            demo_root / "xiaozhi-home" / "data" / ".config.yaml": real_cfg_yaml,
        }
        for link_path, target in symlinked_outputs.items():
            link_path.symlink_to(target)
        hardlinked_output = demo_root / "fake-provider.log"
        os.link(real_fake_log, hardlinked_output)
        linked_before = _snapshot_files([real_srv_log, real_cfg_yaml, real_fake_log])
        copy_entries_before = sorted(p.name for p in copy_runtime.iterdir())
        real_entries_before = sorted(p.name for p in (ROOT / "runtime").iterdir())
        shared_venv_before = _tree_signature(ROOT / "runtime" / "venv")
        # Synthetic stand-in for an operator's real signing key left in the env.
        synthetic_real_key = secrets.token_hex(32)

        # Exercise default $ROOT/runtime-demo by leaving PASSPORT_DEMO_RUNTIME unset.
        # pip runs (offline "already satisfied" via the read-only shared venv) so
        # the test proves dependency installation never writes the shared venv.
        demo_res = subprocess.run(
            ["sh", str(passport_copy / "scripts" / "run_isolated.sh")],
            env=_base_env(
                PASSPORT_SKIP_REGRESSION="1",
                PASSPORT_PYTHON=sys.executable,
                PASSPORT_AUTH_KEY=synthetic_real_key,
                PASSPORT_WS_BIND_PORT=str(_free_port()),
                PASSPORT_HTTP_BIND_PORT=str(_free_port()),
                PASSPORT_FAKE_PORT=str(_free_port()),
            ),
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert demo_res.returncode == 0, (
            f"isolated run_isolated.sh failed ({demo_res.returncode}):\n"
            f"{redact_text(demo_res.stdout)}\n{redact_text(demo_res.stderr)}"
        )
        assert "PASSED tightened upstream websocket contract with local fake providers" in demo_res.stdout

        _assert_files_unchanged(copy_before, "isolated copy runtime/")
        _assert_files_unchanged(real_before, "real passport/runtime/")
        _assert_files_unchanged(linked_before, "demo output link targets")
        for link_path in list(symlinked_outputs) + [hardlinked_output]:
            assert link_path.is_file() and not link_path.is_symlink(), (
                f"demo output {link_path} still a link after run_isolated.sh"
            )
        assert os.stat(hardlinked_output).st_ino != os.stat(real_fake_log).st_ino, (
            "demo fake-provider.log still hard-linked to a real file"
        )
        assert sorted(p.name for p in copy_runtime.iterdir()) == copy_entries_before, (
            "run_isolated.sh created/removed entries in the copy's real runtime/"
        )
        assert sorted(p.name for p in (ROOT / "runtime").iterdir()) == real_entries_before, (
            "run_isolated.sh created/removed entries in real passport/runtime/"
        )
        assert _tree_signature(ROOT / "runtime" / "venv") == shared_venv_before, (
            "run_isolated.sh dependency install modified the shared runtime/venv"
        )
        demo_venv = demo_root / "venv"
        assert (demo_venv / "bin" / "python").exists() and not demo_venv.is_symlink()
        assert (ROOT / "runtime").resolve() not in demo_venv.resolve().parents

        # Demo must use its own key source, never the inherited PASSPORT_AUTH_KEY.
        assert synthetic_real_key not in demo_res.stdout + demo_res.stderr
        demo_rendered = yaml.safe_load(
            (demo_root / "xiaozhi-home" / "data" / ".config.yaml").read_text(encoding="utf-8")
        )
        demo_key = (demo_root / "auth_key").read_text(encoding="utf-8").strip()
        assert demo_rendered["server"]["auth_key"] == demo_key != synthetic_real_key
        for dirpath, dirnames, filenames in os.walk(demo_root):
            dirnames[:] = [d for d in dirnames if Path(dirpath, d) != demo_venv]
            for fname in filenames:
                fpath = Path(dirpath, fname)
                if fpath.is_file():
                    assert synthetic_real_key.encode() not in fpath.read_bytes(), (
                        f"inherited PASSPORT_AUTH_KEY leaked into demo output {fpath.name}"
                    )

        # write_config.py demo mode directly: env key and config-embedded key ignored.
        wc_home = tmp / "wc_demo_home"
        (wc_home / "data").mkdir(parents=True)
        cfg_key = secrets.token_hex(32)
        wc_cfg_data = yaml.safe_load((ROOT / "config" / "demo.config.yaml").read_text(encoding="utf-8"))
        wc_cfg_data["server"]["auth_key"] = cfg_key
        wc_cfg = tmp / "wc_demo_cfg.yaml"
        wc_cfg.write_text(yaml.safe_dump(wc_cfg_data), encoding="utf-8")
        wc_res = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write_config.py")],
            env=_base_env(
                XIAOZHI_HOME=str(wc_home),
                PASSPORT_MODE="demo",
                PASSPORT_CONFIG_FILE=str(wc_cfg),
                PASSPORT_AUTH_KEY=synthetic_real_key,
                PASSPORT_AUTH_FILE=str(tmp / "wc_demo_auth"),
                PASSPORT_DEVICES_FILE=str(tmp / "wc_demo_devices.yaml"),
            ),
            capture_output=True,
            text=True,
        )
        assert wc_res.returncode == 0, f"demo write_config failed: {redact_text(wc_res.stderr)}"
        wc_text = (wc_home / "data" / ".config.yaml").read_text(encoding="utf-8")
        assert synthetic_real_key not in wc_text and cfg_key not in wc_text, (
            "demo write_config.py rendered an inherited/real signing key"
        )
        assert yaml.safe_load(wc_text)["server"]["auth_key"] == (tmp / "wc_demo_auth").read_text(
            encoding="utf-8"
        ).strip()

        demo_root = passport_copy / "runtime-demo"
        for expected_file in (
            demo_root / "devices.yaml",
            demo_root / "auth_key",
            demo_root / "xiaozhi-home" / "data" / ".config.yaml",
            demo_root / "xiaozhi-home" / "tmp" / "server.log",
        ):
            assert expected_file.is_file(), f"Missing isolated demo artifact: {expected_file}"

        # Guardrails: refuse running demo scripts targeting inside real runtime/.
        bad_demo_dir = copy_runtime / "bad-demo"
        bad_run = subprocess.run(
            ["sh", str(passport_copy / "scripts" / "run_isolated.sh")],
            env=_base_env(
                PASSPORT_DEMO_RUNTIME=str(bad_demo_dir),
                PASSPORT_SKIP_REGRESSION="1",
                PASSPORT_SKIP_PIP="1",
                PASSPORT_PYTHON=sys.executable,
            ),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert bad_run.returncode != 0, "run_isolated.sh must refuse PASSPORT_DEMO_RUNTIME inside runtime/"
        assert not bad_demo_dir.exists(), "run_isolated.sh created directory inside runtime/ before refusing!"

        guard_home = tmp / "guard_home"
        (guard_home / "data").mkdir(parents=True)
        for env_key, bad_val, xh in (
            ("PASSPORT_DEVICES_FILE", str(ROOT / "runtime" / "devices.yaml"), str(guard_home)),
            ("PASSPORT_AUTH_FILE", str(ROOT / "runtime" / "auth_key"), str(guard_home)),
            ("PASSPORT_DEVICES_FILE", str(tmp / "safe_devices.yaml"), str(ROOT / "runtime" / "bad_home")),
        ):
            guard_env = _base_env(
                XIAOZHI_HOME=xh,
                PASSPORT_MODE="demo",
                PASSPORT_AUTH_FILE=str(tmp / "safe_auth"),
                PASSPORT_DEVICES_FILE=str(tmp / "safe_devices.yaml"),
            )
            guard_env[env_key] = bad_val
            guard_res = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "write_config.py")],
                env=guard_env,
                capture_output=True,
                text=True,
            )
            assert guard_res.returncode != 0, f"write_config.py demo mode allowed {env_key}={bad_val}"

        _assert_files_unchanged(real_before, "post-guardrail real passport/runtime/")

    # Compose & demo config static isolation assertions.
    prod_compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    demo_compose = yaml.safe_load((ROOT / "docker-compose.demo.yml").read_text(encoding="utf-8"))
    demo_cfg = yaml.safe_load((ROOT / "config" / "demo.config.yaml").read_text(encoding="utf-8"))

    assert demo_compose.get("name") and demo_compose["name"] != prod_compose.get("name"), (
        "docker-compose.demo.yml must use a distinct Compose project name"
    )
    demo_srv = demo_compose["services"]["xiaozhi-server"]
    demo_env = demo_srv["environment"]
    assert demo_env.get("PASSPORT_MODE") == "demo"
    for env_name in ("PASSPORT_DEVICES_FILE", "PASSPORT_AUTH_FILE", "PASSPORT_LOG_DIR"):
        val = str(demo_env.get(env_name) or "")
        assert val.startswith("/opt/passport/runtime-compose-demo/"), (
            f"docker-compose.demo.yml {env_name}={val!r} must be under /opt/passport/runtime-compose-demo/"
        )
    demo_vols = [str(v) for v in demo_srv.get("volumes") or []]
    assert "./runtime-compose-demo:/opt/passport/runtime" in demo_vols
    assert "./runtime-compose-demo:/opt/passport/runtime-compose-demo" in demo_vols
    assert "./runtime-compose-demo/data:/opt/xiaozhi-esp32-server/data" in demo_vols
    for vol in demo_vols:
        src_part = vol.split(":", 1)[0]
        assert src_part != "./runtime" and not src_part.startswith("./runtime/"), (
            f"docker-compose.demo.yml mounts real runtime volume: {vol}"
        )
    assert "/opt/passport/runtime/" not in str(demo_cfg["server"]["auth"].get("devices_file") or "")

    # Effective (merged) Compose model for the documented demo command, evaluated
    # with COMPOSE_PROJECT_NAME already set to the REAL project name in the env.
    prod_name = str(prod_compose["name"])
    demo_name = str(demo_compose["name"])
    doc_cmds = []
    for doc in (ROOT / "README.zh_CN.md", ROOT / "docker-compose.yml", ROOT / "docker-compose.demo.yml"):
        for line in doc.read_text(encoding="utf-8").splitlines():
            if "docker compose" in line and "docker-compose.demo.yml" in line:
                doc_cmds.append(line.lstrip("# ").strip())
    assert doc_cmds, "No documented demo docker compose command found"
    for cmd in doc_cmds:
        argv = shlex.split(cmd)
        files = [argv[i + 1] for i, a in enumerate(argv) if a == "-f"]
        assert files == ["docker-compose.yml", "docker-compose.demo.yml"], f"Unexpected compose files in: {cmd}"
        eff_name = _compose_project_name(argv, {"COMPOSE_PROJECT_NAME": prod_name}, demo_name)
        assert eff_name == demo_name != prod_name, (
            f"Documented demo command resolves to project {eff_name!r} when COMPOSE_PROJECT_NAME={prod_name!r}: {cmd}"
        )
    merged = _compose_merge(prod_compose, demo_compose)
    assert set(merged["services"]) == {"xiaozhi-server", "fake-provider"}, merged["services"].keys()
    m_srv = merged["services"]["xiaozhi-server"]
    m_env = m_srv["environment"]
    assert m_env["PASSPORT_MODE"] == "demo"
    assert m_env["PASSPORT_CONFIG_FILE"] == "/opt/passport/config/demo.config.yaml"
    assert m_env.get("PASSPORT_AUTH_KEY") == "", "merged demo service must blank PASSPORT_AUTH_KEY"
    mounts = {str(v).split(":")[1]: str(v).split(":")[0] for v in m_srv["volumes"]}
    assert mounts["/opt/passport/runtime"] == "./runtime-compose-demo", mounts
    assert mounts["/opt/xiaozhi-esp32-server/data"] == "./runtime-compose-demo/data", mounts
    for src in mounts.values():
        assert src != "./runtime" and not src.startswith("./runtime/"), f"merged demo mounts real runtime: {src}"
    fake_svc = merged["services"]["fake-provider"]
    assert not fake_svc.get("ports"), "fake-provider must not publish host ports"
    assert [str(v) for v in fake_svc.get("volumes") or []] == ["./fake_provider.py:/opt/passport/fake_provider.py:ro"]

    docker_bin = shutil.which("docker")
    if docker_bin:
        cfg_cmd = shlex.split(doc_cmds[0])
        up_idx = cfg_cmd.index("up")
        cfg_res = subprocess.run(
            [docker_bin] + cfg_cmd[1:up_idx] + ["config", "--format", "json"],
            cwd=str(ROOT),
            env={**os.environ, "COMPOSE_PROJECT_NAME": prod_name, "PASSPORT_AUTH_KEY": secrets.token_hex(32)},
            capture_output=True,
            text=True,
        )
        if cfg_res.returncode == 0:
            real_cfg = json.loads(cfg_res.stdout)
            assert real_cfg.get("name") == demo_name
            assert real_cfg["services"]["xiaozhi-server"]["environment"].get("PASSPORT_AUTH_KEY") == ""
            print("[PASS] docker compose config confirms demo project name and blank PASSPORT_AUTH_KEY")
    else:
        print("[INFO] docker CLI unavailable; Compose merge verified with in-test merge model only")
    print("[PASS] blocker #1: demo script and Compose override strictly isolated; real runtime files byte-identical")


def _build_local_test_wheel(dest_dir: Path, pkg_name: str, version: str, marker: str) -> Path:
    """Create a minimal dependency-free pure-Python wheel on disk for offline pip install tests."""
    dist_info = f"{pkg_name}-{version}.dist-info"
    files = {
        f"{pkg_name}/__init__.py": f"MARKER = {marker!r}\n".encode("utf-8"),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {pkg_name.replace('_', '-')}\nVersion: {version}\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: passport-regression-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode("utf-8"),
        f"{dist_info}/top_level.txt": f"{pkg_name}\n".encode("utf-8"),
    }
    records = []
    for rel_path, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        records.append(f"{rel_path},sha256={digest},{len(content)}")
    records.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = ("\n".join(records) + "\n").encode("utf-8")

    wheel_path = dest_dir / f"{pkg_name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, content in files.items():
            zf.writestr(rel_path, content)
    return wheel_path


def test_demo_pip_controlled_install_isolation(server_home: Path) -> None:
    """Round-3 blocker #2: hostile user/site/PIP_CONFIG_FILE install.target cannot divert demo pip into shared venv."""
    real_files = [
        ROOT / "runtime" / "devices.yaml",
        ROOT / "runtime" / "auth_key",
        server_home / "data" / ".config.yaml",
        ROOT / "config" / "server.config.yaml",
    ]
    real_before = _snapshot_files(real_files)
    real_venv_before = _tree_signature(ROOT / "runtime" / "venv")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        probe_marker = "demo_probe_" + secrets.token_hex(8)
        wheel_path = _build_local_test_wheel(tmp, "passport_demo_probe", "0.1.0", probe_marker)

        # Negative control: unhardened pip honors PIP_CONFIG_FILE install.target and diverts writes out of venv.
        ctrl_venv = tmp / "ctrl_venv"
        ctrl_target = tmp / "ctrl_target"
        ctrl_target.mkdir(parents=True)
        subprocess.run([sys.executable, "-m", "venv", str(ctrl_venv)], check=True, capture_output=True)
        ctrl_pip_conf = tmp / "ctrl_pip.conf"
        ctrl_pip_conf.write_text(f"[install]\ntarget = {ctrl_target}\n", encoding="utf-8")
        ctrl_res = subprocess.run(
            [str(ctrl_venv / "bin" / "python"), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel_path)],
            env=_base_env(PIP_CONFIG_FILE=str(ctrl_pip_conf)),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert ctrl_res.returncode == 0, f"negative-control pip install failed: {ctrl_res.stderr}"
        assert (ctrl_target / "passport_demo_probe" / "__init__.py").is_file(), (
            "negative control failed: pip did not honor install.target in PIP_CONFIG_FILE"
        )

        # Build isolated passport copy with a writable simulated shared runtime/venv.
        passport_copy = tmp / "passport_copy"
        passport_copy.mkdir(parents=True)
        ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
        for subdir in ("config", "passport_server", "scripts"):
            shutil.copytree(ROOT / subdir, passport_copy / subdir, ignore=ignore)
        shutil.copy2(ROOT / "fake_provider.py", passport_copy / "fake_provider.py")
        req_text = (ROOT / "requirements-runtime.txt").read_text(encoding="utf-8").rstrip()
        (passport_copy / "requirements-runtime.txt").write_text(
            req_text + f"\n{wheel_path}\n", encoding="utf-8"
        )

        copy_runtime = passport_copy / "runtime"
        copy_runtime.mkdir(parents=True)
        (copy_runtime / "xiaozhi-esp32-server").symlink_to(ROOT / "runtime" / "xiaozhi-esp32-server")

        sim_shared_venv = copy_runtime / "venv"
        subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(sim_shared_venv)],
            check=True,
            capture_output=True,
        )
        sim_shared_site = Path(
            subprocess.check_output(
                [str(sim_shared_venv / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
                text=True,
            ).strip()
        )
        real_shared_site = Path(
            subprocess.check_output(
                [str(ROOT / "runtime" / "venv" / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
                text=True,
            ).strip()
        )
        (sim_shared_site / "zz_real_readonly.pth").write_text(
            f"import site; site.addsitedir({str(real_shared_site)!r})\n", encoding="utf-8"
        )
        sim_shared_before = _tree_signature(sim_shared_venv)

        # Pre-create demo venv and plant hostile site, user, XDG, and PIP_CONFIG_FILE configs
        # that all try to redirect `[install] target` into sim_shared_site.
        demo_root = passport_copy / "runtime-demo"
        demo_venv = demo_root / "venv"
        subprocess.run(
            [str(sim_shared_venv / "bin" / "python"), "-m", "venv", str(demo_venv)],
            check=True,
            capture_output=True,
        )
        hostile_cfg_body = f"[install]\ntarget = {sim_shared_site}\n"
        (demo_venv / "pip.conf").write_text(hostile_cfg_body, encoding="utf-8")

        fake_home = tmp / "fake_home"
        fake_xdg = tmp / "fake_xdg"
        for cfg_path in (
            fake_home / ".config" / "pip" / "pip.conf",
            fake_home / ".pip" / "pip.conf",
            fake_xdg / "pip" / "pip.conf",
            tmp / "hostile_pip.conf",
        ):
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            cfg_path.write_text(hostile_cfg_body, encoding="utf-8")

        demo_res = subprocess.run(
            ["sh", str(passport_copy / "scripts" / "run_isolated.sh")],
            env=_base_env(
                PASSPORT_SKIP_PIP="0",
                PASSPORT_SKIP_REGRESSION="1",
                PASSPORT_PYTHON=sys.executable,
                HOME=str(fake_home),
                XDG_CONFIG_HOME=str(fake_xdg),
                PIP_CONFIG_FILE=str(tmp / "hostile_pip.conf"),
                PIP_TARGET=str(sim_shared_site),
                PIP_PREFIX=str(sim_shared_venv),
                PIP_ROOT=str(sim_shared_venv),
                PIP_USER="1",
                PIP_PYTHON=str(sim_shared_venv / "bin" / "python"),
                PASSPORT_WS_BIND_PORT=str(_free_port()),
                PASSPORT_HTTP_BIND_PORT=str(_free_port()),
                PASSPORT_FAKE_PORT=str(_free_port()),
            ),
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert demo_res.returncode == 0, (
            f"controlled pip run_isolated.sh failed ({demo_res.returncode}):\n"
            f"{redact_text(demo_res.stdout)}\n{redact_text(demo_res.stderr)}"
        )
        assert "PASSED tightened upstream websocket contract with local fake providers" in demo_res.stdout

        # Verify actual write landed inside demo_venv and never touched sim_shared_venv or real runtime/venv.
        demo_site = Path(
            subprocess.check_output(
                [str(demo_venv / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
                text=True,
            ).strip()
        ).resolve()
        assert demo_venv.resolve() in demo_site.parents
        installed_init = demo_site / "passport_demo_probe" / "__init__.py"
        installed_meta = demo_site / "passport_demo_probe-0.1.0.dist-info" / "METADATA"
        assert installed_init.is_file() and installed_meta.is_file(), (
            f"expected demo probe package inside {demo_site}"
        )
        assert probe_marker in installed_init.read_text(encoding="utf-8")
        probe_check = subprocess.run(
            [
                str(demo_venv / "bin" / "python"),
                "-c",
                (
                    "import pathlib, passport_demo_probe; "
                    f"p = pathlib.Path(passport_demo_probe.__file__).resolve(); "
                    f"assert pathlib.Path({str(demo_venv.resolve())!r}) in p.parents, p; "
                    f"assert passport_demo_probe.MARKER == {probe_marker!r}"
                ),
            ],
            capture_output=True,
            text=True,
        )
        assert probe_check.returncode == 0, f"demo package import check failed: {probe_check.stderr}"

        assert not (sim_shared_site / "passport_demo_probe").exists(), (
            "demo pip wrote package into simulated shared runtime/venv"
        )
        assert _tree_signature(sim_shared_venv) == sim_shared_before, (
            "demo pip install modified simulated shared runtime/venv"
        )
        assert _tree_signature(ROOT / "runtime" / "venv") == real_venv_before, (
            "demo pip install modified real passport/runtime/venv"
        )

        # Guardrail: symlinked purelib inside demo_venv pointing to sim_shared_site must be rejected before writes.
        escaped_demo = passport_copy / "runtime-demo-escaped"
        escaped_venv = escaped_demo / "venv"
        subprocess.run(
            [str(sim_shared_venv / "bin" / "python"), "-m", "venv", "--without-pip", str(escaped_venv)],
            check=True,
            capture_output=True,
        )
        escaped_site = Path(
            subprocess.check_output(
                [str(escaped_venv / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
                text=True,
            ).strip()
        )
        shutil.rmtree(escaped_site)
        escaped_site.symlink_to(sim_shared_site)
        esc_res = subprocess.run(
            ["sh", str(passport_copy / "scripts" / "run_isolated.sh")],
            env=_base_env(
                PASSPORT_DEMO_RUNTIME=str(escaped_demo),
                PASSPORT_SKIP_PIP="0",
                PASSPORT_SKIP_REGRESSION="1",
                PASSPORT_PYTHON=sys.executable,
            ),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert esc_res.returncode != 0, "run_isolated.sh must refuse demo venv whose purelib symlinks outside demo_venv"
        assert _tree_signature(sim_shared_venv) == sim_shared_before, (
            "escaped purelib guardrail modified simulated shared runtime/venv before refusing"
        )

        _assert_files_unchanged(real_before, "post-controlled-pip real passport/runtime/")
    print("[PASS] round-3 blocker #2: controlled demo pip wrote test package into demo venv only; shared venv untouched")


def test_reverse_proxy_templates_and_forwarding(ota_base: str, dev_a: dict) -> None:
    """Blocker #2: validate Nginx/Caddy proxy templates and verify log-free OTA secret forwarding."""
    readme_text = (ROOT / "README.zh_CN.md").read_text(encoding="utf-8")
    nginx_path = ROOT / "proxy" / "nginx-passport.conf.example"
    caddy_path = ROOT / "proxy" / "Caddyfile.example"
    assert nginx_path.is_file() and caddy_path.is_file()
    assert "proxy/nginx-passport.conf.example" in readme_text
    assert "proxy/Caddyfile.example" in readme_text

    nginx_text = nginx_path.read_text(encoding="utf-8")
    caddy_text = caddy_path.read_text(encoding="utf-8")
    assert nginx_text.count("{") == nginx_text.count("}"), "Unbalanced braces in nginx-passport.conf.example"
    assert caddy_text.count("{") == caddy_text.count("}"), "Unbalanced braces in Caddyfile.example"
    active_nginx_lines = "\n".join(
        line for line in nginx_text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "error_log off" not in active_nginx_lines, (
        "Nginx does not support `error_log off;`; use `/dev/null emerg;`"
    )

    # Verify log_format passport_safe never emits unsafe raw request/header variables or Referer.
    log_fmt_match = re.search(r"log_format\s+passport_safe\s+(.*?);", nginx_text, re.DOTALL)
    assert log_fmt_match, "Missing log_format passport_safe in nginx template"
    fmt_body = log_fmt_match.group(1)
    fmt_vars = set(re.findall(r"\$[A-Za-z0-9_]+", fmt_body))
    forbidden_nginx_vars = {
        "$request",
        "$request_uri",
        "$args",
        "$query_string",
        "$http_authorization",
        "$http_x_ota_secret",
        "$http_cookie",
        "$http_referer",
        "$passport_safe_referer",
    }
    assert not (fmt_vars & forbidden_nginx_vars), f"Unsafe nginx log_format vars: {fmt_vars & forbidden_nginx_vars}"
    assert not any("referer" in v.lower() for v in fmt_vars), f"Referer var still in log_format: {fmt_vars}"
    assert '"-"' in fmt_body, "log_format passport_safe must emit literal \"-\" for Referer"
    assert not re.search(r"map\s+\$http_referer\s+\$passport_safe_referer\b", nginx_text), (
        "Obsolete $passport_safe_referer map should be removed when access log omits Referer"
    )
    assert "access_log /var/log/nginx/passport_access.log passport_safe;" in nginx_text

    _, uri_rules = _nginx_map_rules(nginx_text, "passport_safe_uri")
    _, query_rules = _nginx_map_rules(nginx_text, "passport_safe_query")
    ref_src, unsafe_ref_rules = _nginx_map_rules(nginx_text, "passport_unsafe_referer")
    assert ref_src == "http_referer"

    syn_secret = "proxy_ota_" + secrets.token_hex(12)
    syn_qtok = "proxy_qtok_" + secrets.token_hex(10)
    syn_user = "proxy_usr_" + secrets.token_hex(5)
    syn_pass = "proxy_pwd_" + secrets.token_hex(6)

    for test_uri, test_is_args in (
        (f"/xiaozhi/ota/d/{syn_secret}/", ""),
        (f"//xiaozhi/ota/d/{syn_secret}/", "?"),
        (f"/xiaozhi//ota///d/{syn_secret}/", "?"),
        (f"/xiaozhi/ota/d/{syn_secret}/extra", "?"),
        ("/xiaozhi/v1/", "?"),
    ):
        rendered_uri = _eval_nginx_map(uri_rules, test_uri) + _eval_nginx_map(query_rules, test_is_args)
        for forbidden in (syn_secret, syn_qtok, syn_user, syn_pass):
            assert forbidden not in rendered_uri, f"Nginx URI map leaked secret: {rendered_uri}"

    # Verify $passport_unsafe_referer strict allowlist allows empty/bare-origin and rejects
    # literal, slash-encoded, letter-percent-encoded, dot-segment, userinfo, query, and non-root paths.
    for safe_ref in ("", "https://proxy.example", "https://proxy.example/", "http://127.0.0.1:8443/", "https://[::1]:8443/"):
        assert _eval_nginx_map(unsafe_ref_rules, safe_ref) == "0", f"Safe Referer rejected: {safe_ref!r}"
    for bad_ref in (
        f"https://proxy.example/xiaozhi/ota/d/{syn_secret}/",
        f"https://proxy.example/xiaozhi%2Fota%2Fd%2F{syn_secret}%2F",
        f"https://proxy.example/%78iaozhi/%6fta/%64/{syn_secret}/",
        f"https://proxy.example/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn_secret}/",
        f"https://proxy.example/xiaozhi/./foo/../ota//d/{syn_secret}/",
        f"https://{syn_user}:{syn_pass}@proxy.example/",
        f"https://proxy.example/?token={syn_qtok}",
        "https://proxy.example/docs",
    ):
        assert _eval_nginx_map(unsafe_ref_rules, bad_ref) == "1", f"Unsafe Referer bypassed allowlist: {bad_ref!r}"

    # Verify /xiaozhi/ota/d/ location block order & directives.
    ota_prefix_match = re.search(r"location\s+\^~\s+/xiaozhi/ota/d/\s*\{(.*?)\n    \}", nginx_text, re.DOTALL)
    assert ota_prefix_match, "Missing location ^~ /xiaozhi/ota/d/ block"
    ota_block = ota_prefix_match.group(1)
    assert "access_log off;" in ota_block
    assert "error_log /dev/null emerg;" in ota_block
    assert "log_not_found off;" in ota_block
    assert "log_subrequest off;" in ota_block

    nested_match = re.search(
        r"location\s+~\s+\^/xiaozhi/ota/d/\(\?<ota_secret_cap>\[\^/\]\+\)/\?\$\s*\{(.*?)\n        \}",
        ota_block,
        re.DOTALL,
    )
    assert nested_match, "Missing named-capture nested OTA secret location"
    nested_block = nested_match.group(1)
    assert nested_block.count("access_log off;") >= 1
    assert nested_block.count("error_log /dev/null emerg;") >= 1
    idx_set = nested_block.find("set $passport_ota_secret $ota_secret_cap;")
    idx_if = nested_block.find("if ($args ~*")
    idx_rw = nested_block.find("rewrite ^ /xiaozhi/ota/? break;")
    assert 0 <= idx_set < idx_if < idx_rw, (
        "Nginx nested OTA block must capture $passport_ota_secret before `if ($args ~* ...)` and `rewrite`"
    )
    assert "proxy_set_header X-OTA-Secret $passport_ota_secret;" in nested_block
    for stripped in (
        'proxy_set_header Authorization "";',
        'proxy_set_header X-Original-URI "";',
        'proxy_set_header X-Original-URL "";',
        'proxy_set_header X-Rewrite-URL "";',
        'proxy_set_header X-Forwarded-Uri "";',
        'proxy_set_header X-Envoy-Original-Path "";',
        'proxy_set_header X-Request-URI "";',
        'proxy_set_header Referer "";',
    ):
        assert stripped in nested_block, f"Missing header scrub {stripped} in nginx OTA block"

    # Caddy template structural & regex assertions.
    assert "@ota_secret_prefix path /xiaozhi/ota/d/*" in caddy_text
    assert "log_skip @ota_secret_prefix" in caddy_text
    for caddy_field in (
        'request>uri replace "[REDACTED]"',
        'request>orig_uri replace "[REDACTED]"',
        'request>headers>Authorization replace "[REDACTED]"',
        'request>headers>X-Ota-Secret replace "[REDACTED]"',
        'request>headers>Cookie replace "[REDACTED]"',
        'request>headers>Referer replace "[REDACTED]"',
        'request>headers>X-Original-Uri replace "[REDACTED]"',
        'request>headers>X-Request-Uri replace "[REDACTED]"',
    ):
        assert caddy_field in caddy_text, f"Missing Caddy log filter {caddy_field}"
    caddy_re_match = re.search(r"path_regexp\s+ota\s+(\S+)", caddy_text)
    assert caddy_re_match, "Missing Caddy path_regexp ota"
    caddy_cap = re.match(caddy_re_match.group(1), f"/xiaozhi/ota/d/{syn_secret}/")
    assert caddy_cap and caddy_cap.group(1) == syn_secret
    assert "rewrite * /xiaozhi/ota/" in caddy_text
    assert "header_up X-OTA-Secret {re.ota.1}" in caddy_text
    assert "respond @credential_query 400" in caddy_text
    for caddy_strip in (
        "header_up -Authorization",
        "header_up -X-Original-URI",
        "header_up -X-Original-URL",
        "header_up -X-Rewrite-URL",
        "header_up -X-Forwarded-Uri",
        "header_up -X-Envoy-Original-Path",
        "header_up -X-Request-URI",
        "header_up -Referer",
    ):
        assert caddy_strip in caddy_text, f"Missing Caddy header scrub {caddy_strip}"

    # Behavioral forwarding & log-isolation test using an in-process proxy mimicking the Nginx template.
    proxy_access_logs: list[str] = []
    proxy_error_logs: list[str] = []
    proxy_lock = threading.Lock()
    ota_secret_route_re = re.compile(r"^/xiaozhi/ota/d/(?P<ota_secret_cap>[^/]+)/?$")

    class _TemplateProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            # Redirect all server-level messages under proxy control so raw URLs never leak.
            pass

        def _safe_log_line(self, method: str, norm_path: str, query: str, status: int, length: int) -> str:
            safe_uri = _eval_nginx_map(uri_rules, norm_path) + _eval_nginx_map(query_rules, "?" if query else "")
            return f'{self.address_string()} - "{method} {safe_uri} HTTP/1.1" {status} {length} "-"'

        def _handle(self, method: str) -> None:
            parsed = urlsplit(self.path)
            norm_path = _nginx_normalize_uri(parsed.path)
            query = parsed.query
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length > 0 else b""
            referer = self.headers.get("Referer", "")
            is_secret_prefix = norm_path.startswith("/xiaozhi/ota/d/")

            # Server-level guard (`if ($passport_unsafe_referer) { return 400; }`) runs before location matching.
            if _eval_nginx_map(unsafe_ref_rules, referer) not in ("", "0"):
                resp_body = b'{"success":false,"message":"unsafe referer"}'
                with proxy_lock:
                    proxy_access_logs.append(self._safe_log_line(method, norm_path, query, 400, len(resp_body)))
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

            if query and PROXY_SENSITIVE_QUERY_RE.search(query):
                resp_body = b'{"success":false,"message":"query credentials forbidden"}'
                # Record the access-log line before replying so the client never races the log.
                if not is_secret_prefix:
                    with proxy_lock:
                        proxy_access_logs.append(
                            self._safe_log_line(method, norm_path, query, 400, len(resp_body))
                        )
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

            forward_headers = {}
            for hk, hv in self.headers.items():
                lk = hk.lower()
                if lk in (
                    "host",
                    "content-length",
                    "connection",
                    "x-original-uri",
                    "x-original-url",
                    "x-rewrite-url",
                    "x-forwarded-uri",
                    "x-envoy-original-path",
                    "x-request-uri",
                    "referer",
                ):
                    continue
                forward_headers[hk] = hv

            target_path = norm_path
            secret_match = ota_secret_route_re.match(norm_path)
            if is_secret_prefix and not secret_match:
                resp_body = b"404 Not Found"
                self.send_response(404)
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

            if secret_match:
                forward_headers.pop("Authorization", None)
                forward_headers.pop("authorization", None)
                forward_headers["X-OTA-Secret"] = secret_match.group("ota_secret_cap")
                target_path = "/xiaozhi/ota/"

            req = urllib.request.Request(
                ota_base.rstrip("/") + target_path,
                data=raw_body if method == "POST" else None,
                headers=forward_headers,
                method=method,
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status = resp.status
                    resp_body = resp.read()
                    ctype = resp.headers.get("Content-Type", "application/json")
            except urllib.error.HTTPError as exc:
                status = exc.code
                resp_body = exc.read()
                ctype = exc.headers.get("Content-Type", "application/json")
                if not is_secret_prefix:
                    with proxy_lock:
                        proxy_error_logs.append(f"upstream HTTP {status} on {target_path}")
            if not is_secret_prefix:
                with proxy_lock:
                    proxy_access_logs.append(
                        self._safe_log_line(method, norm_path, query, status, len(resp_body))
                    )
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    proxy_port = _free_port()
    proxy_srv = ThreadingHTTPServer(("127.0.0.1", proxy_port), _TemplateProxyHandler)
    proxy_srv.daemon_threads = True
    proxy_thread = threading.Thread(target=proxy_srv.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        proxy_base = f"http://127.0.0.1:{proxy_port}"
        wrong_secret = "wrong_proxy_" + secrets.token_hex(8)
        q_sentinel = "q_proxy_" + secrets.token_hex(8)

        # 1a. Valid OTA secret path (literal) with bare-origin Referer & decoy tracing headers -> 200 + WS token.
        st_ok, body_ok = post_ota(
            proxy_base,
            {
                "Device-Id": dev_a["device_id"],
                "Client-Id": dev_a["client_id"],
                "X-Original-URI": f"/xiaozhi/ota/d/{dev_a['ota_secret']}/",
                "Referer": "https://proxy.example/",
            },
            secret=dev_a["ota_secret"],
        )
        assert st_ok == 200 and body_ok["websocket"]["token"], f"Proxy OTA forward failed: {st_ok} {body_ok}"
        issued_ws_token = body_ok["websocket"]["token"]

        # 1b. Equivalent fixed-segment letter-percent-encoded OTA path normalizes identically -> 200 + WS token.
        letter_encoded_ota_path = f"/%78iaozhi/%6fta/%64/{dev_a['ota_secret']}/"
        assert _nginx_normalize_uri(letter_encoded_ota_path) == f"/xiaozhi/ota/d/{dev_a['ota_secret']}/"
        st_enc, body_enc = post_json(
            f"{proxy_base}{letter_encoded_ota_path}",
            {
                "Device-Id": dev_a["device_id"],
                "Client-Id": dev_a["client_id"],
                "Referer": "https://proxy.example/",
            },
        )
        assert st_enc == 200 and body_enc["websocket"]["token"], (
            f"Letter-encoded OTA proxy forward failed: {st_enc} {body_enc}"
        )
        issued_ws_token_enc = body_enc["websocket"]["token"]

        # 1c. Secret-bearing literal & letter-percent-encoded Referers rejected with 400.
        for bad_ref in (
            f"https://proxy.example/xiaozhi/ota/d/{dev_a['ota_secret']}/",
            f"https://proxy.example/%78iaozhi/%6fta/%64/{dev_a['ota_secret']}/",
        ):
            for req_path in ("/xiaozhi/ota/", f"/xiaozhi/ota/d/{dev_a['ota_secret']}/"):
                st_ref, _ = post_json(
                    f"{proxy_base}{req_path}",
                    {
                        "Device-Id": dev_a["device_id"],
                        "Client-Id": dev_a["client_id"],
                        "Referer": bad_ref,
                    },
                )
                assert st_ref == 400, f"Unsafe Referer {bad_ref} on {req_path} returned {st_ref}"

        # 2. Query credential rejected with 400.
        st_q, _ = post_json(
            f"{proxy_base}/xiaozhi/ota/d/{dev_a['ota_secret']}/?token={q_sentinel}",
            {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
        )
        assert st_q == 400

        # 3. Wrong secret rejected with 403.
        st_bad, _ = post_ota(
            proxy_base,
            {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
            secret=wrong_secret,
        )
        assert st_bad == 403

        # 4. Safe GET /xiaozhi/ota/ & query-param GET /xiaozhi/ota/?token=... logged safely.
        with urllib.request.urlopen(f"{proxy_base}/xiaozhi/ota/", timeout=5) as r_get:
            assert r_get.status == 200
        st_get_q, _ = post_json(
            f"{proxy_base}/xiaozhi/ota/?token={q_sentinel}",
            {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
        )
        assert st_get_q == 400

        joined_proxy_logs = "\n".join(proxy_access_logs + proxy_error_logs)
        assert "/xiaozhi/ota/" in joined_proxy_logs
        assert "/xiaozhi/ota/?[REDACTED]" in joined_proxy_logs
        assert "/xiaozhi/ota/d/[REDACTED]/" in joined_proxy_logs
        for forbidden in (dev_a["ota_secret"], wrong_secret, q_sentinel, issued_ws_token, issued_ws_token_enc):
            assert forbidden not in joined_proxy_logs, "Proxy log leaked credential!"
    finally:
        proxy_srv.shutdown()
        proxy_srv.server_close()

    print("[PASS] blocker #2: Nginx/Caddy templates validated and proxy OTA forwarding logs zero secrets")


def _caddy_parse_blocks(text: str) -> list[dict]:
    """Minimal Caddyfile block parser: [{'tokens': [...], 'children': [...]|None}]."""
    root: dict = {"tokens": [], "children": []}
    stack = [root]
    for raw in text.splitlines():
        toks = shlex.split(raw, comments=True)
        if not toks:
            continue
        if toks == ["}"]:
            stack.pop()
            assert stack, "Unbalanced Caddyfile braces"
            continue
        opens = toks[-1] == "{"
        node = {"tokens": toks[:-1] if opens else toks, "children": [] if opens else None}
        stack[-1]["children"].append(node)
        if opens:
            stack.append(node)
    assert len(stack) == 1, "Unbalanced Caddyfile braces"
    return root["children"]


def _caddy_log_sinks(caddy_text: str) -> list[dict]:
    """Extract global `log` configs (include/exclude/filter fields) from a Caddyfile."""
    blocks = _caddy_parse_blocks(caddy_text)
    sinks: dict[str, dict] = {}
    if blocks and blocks[0]["tokens"] == []:
        for child in blocks[0]["children"] or []:
            if child["tokens"][:1] != ["log"]:
                continue
            name = child["tokens"][1] if len(child["tokens"]) > 1 else "default"
            cfg = {"name": name, "include": [], "exclude": [], "fields": [], "lines": []}
            for directive in child["children"] or []:
                toks = directive["tokens"]
                if toks[0] == "include":
                    cfg["include"] += toks[1:]
                elif toks[0] == "exclude":
                    cfg["exclude"] += toks[1:]
                elif toks[:2] == ["format", "filter"]:
                    for sub in directive["children"] or []:
                        if sub["tokens"] == ["fields"]:
                            cfg["fields"] += [f["tokens"] for f in sub["children"] or []]
                        elif sub["tokens"][0] != "wrap":
                            cfg["fields"].append(sub["tokens"])
            sinks[name] = cfg
    sinks.setdefault("default", {"name": "default", "include": [], "exclude": [], "fields": [], "lines": []})
    return list(sinks.values())


def _caddy_emit(sinks: list[dict], logger: str, entry: dict) -> None:
    """Route a log entry like Caddy's logging pipeline and apply `format filter` fields."""
    import copy

    def _matches(patterns: list[str]) -> bool:
        return any(logger == p or logger.startswith(p + ".") for p in patterns)

    for sink in sinks:
        if sink["include"] and not _matches(sink["include"]):
            continue
        if _matches(sink["exclude"]):
            continue
        data = copy.deepcopy(entry)
        data["logger"] = logger
        for field in sink["fields"]:
            path, action = field[0].split(">"), field[1] if len(field) > 1 else ""
            node = data
            for part in path[:-1]:
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    break
            if isinstance(node, dict) and path[-1] in node:
                if action == "replace":
                    node[path[-1]] = field[2] if len(field) > 2 else ""
                elif action == "delete":
                    node.pop(path[-1])
        sink["lines"].append(json.dumps(data))


def _nginx_server_guards(nginx_text: str) -> list[tuple[str, int]]:
    """Server-level `if (...) { return N; }` guards located before the first location."""
    server_m = re.search(r"^server\s*\{(.*?)^\s*location\b", nginx_text, re.DOTALL | re.MULTILINE)
    assert server_m, "nginx template has no server block with locations"
    preamble = "\n".join(
        line for line in server_m.group(1).splitlines() if not line.lstrip().startswith("#")
    )
    return [
        (cond.strip(), int(code))
        for cond, code in re.findall(r"if\s*\((.*?)\)\s*\{\s*return\s+(\d+);\s*\}", preamble, re.DOTALL)
    ]


def _nginx_normalize_uri(raw_path: str) -> str:
    """Model Nginx URI normalization: percent-decode, resolve dot-segments, merge slashes."""
    decoded = unquote(raw_path)
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    trailing_slash = decoded.endswith("/") or decoded.endswith("/.") or decoded.endswith("/..")
    parts: list[str] = []
    for seg in decoded.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
        else:
            parts.append(seg)
    normalized = "/" + "/".join(parts)
    if trailing_slash and normalized != "/":
        normalized += "/"
    return normalized


def _eval_nginx_map(rules: list[tuple[Optional[re.Pattern], str]], value: str) -> str:
    """Evaluate parsed Nginx `map` rules in exact-then-regex-then-default order."""
    for pat, out in rules:
        if pat is None:
            return value if out.startswith("$") else out
        if pat.search(value):
            return value if out.startswith("$") else out
    return ""


def _nginx_map_rules(nginx_text: str, var_name: str) -> tuple[str, list[tuple[Optional[re.Pattern], str]]]:
    m = re.search(rf"map\s+\$(\w+)\s+\${re.escape(var_name)}\s*\{{(.*?)\}}", nginx_text, re.DOTALL)
    assert m, f"Missing map ${var_name}"
    exact_rules: list[tuple[Optional[re.Pattern], str]] = []
    regex_rules: list[tuple[Optional[re.Pattern], str]] = []
    default_rules: list[tuple[Optional[re.Pattern], str]] = []
    for raw_line in m.group(2).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        assert line.endswith(";"), f"Malformed map rule: {line}"
        pat_raw, out_raw = line[:-1].strip().split(None, 1)
        out_raw = out_raw.strip().strip('"')
        if pat_raw == "default":
            default_rules.append((None, out_raw))
        elif pat_raw.startswith("~(?i)"):
            regex_rules.append((re.compile(pat_raw[5:], re.IGNORECASE), out_raw))
        elif pat_raw.startswith("~*"):
            regex_rules.append((re.compile(pat_raw[2:], re.IGNORECASE), out_raw))
        elif pat_raw.startswith("~"):
            regex_rules.append((re.compile(pat_raw[1:]), out_raw))
        else:
            exact_rules.append((re.compile("^" + re.escape(pat_raw.strip('"')) + "$"), out_raw))
    return m.group(1), exact_rules + regex_rules + default_rules


def test_proxy_runtime_error_logs_redacted() -> None:
    """Round-2/3 proxy log redaction: backend-failure (502) error & access logs never record OTA secrets.

    No nginx/caddy binaries are installed in this offline sandbox, so in-process HTTP
    stand-ins are driven directly by the parsed templates (explicitly not a substitute
    for real Nginx binary acceptance). On a dead upstream they emit error and access
    entries matching the real servers' semantics (Caddy: original pre-rewrite request
    + headers; nginx: normalized `$uri` for routing/`$uri` maps, raw request line +
    raw `referrer:` in error_log, and template-parsed `log_format passport_safe` in
    access_log). Negative controls prove both the Round-3 letter-percent-encoding
    bypass and guard-removal leak detection.
    """
    caddy_text = (ROOT / "proxy" / "Caddyfile.example").read_text(encoding="utf-8")
    nginx_text = (ROOT / "proxy" / "nginx-passport.conf.example").read_text(encoding="utf-8")
    syn = "errlog_ota_" + secrets.token_hex(12)
    dead_port = _free_port()  # nothing listens here -> connection refused

    def _upstream_fails() -> bool:
        try:
            socket.create_connection(("127.0.0.1", dead_port), timeout=1).close()
            return False
        except OSError:
            return True

    caddy_re_m = re.search(r"path_regexp\s+ota\s+(\S+)", caddy_text)
    assert caddy_re_m
    caddy_secret_re = re.compile(caddy_re_m.group(1))

    def _make_handler(flavor: str, template: str, sinks):
        guards = _nginx_server_guards(template) if flavor == "nginx" else []
        site_err_m = re.search(r"^    error_log\s+(\S+)\s+(\w+);", template, re.MULTILINE) if flavor == "nginx" else None
        site_acc_m = re.search(r"^    access_log\s+(\S+)\s+(\w+);", template, re.MULTILINE) if flavor == "nginx" else None
        ota_d_block_m = re.search(r"location\s+\^~\s+/xiaozhi/ota/d/\s*\{(.*?)\n    \}", template, re.DOTALL)
        fmt_vars: set[str] = set()
        if flavor == "nginx":
            log_fmt_m = re.search(r"log_format\s+passport_safe\s+(.*?);", template, re.DOTALL)
            assert log_fmt_m, "Missing log_format passport_safe in nginx template"
            fmt_vars = set(re.findall(r"\$[A-Za-z0-9_]+", log_fmt_m.group(1)))

        def _guard_hit(cond: str, norm_path: str, query: str, headers) -> bool:
            var_m = re.fullmatch(r"\$(\w+)", cond)
            if var_m:
                src, rules = _nginx_map_rules(template, var_m.group(1))
                src_val = {"http_referer": headers.get("Referer", ""), "args": query, "uri": norm_path}[src]
                return _eval_nginx_map(rules, src_val) not in ("", "0")
            args_m = re.fullmatch(r'\$args\s+~\*\s+"(.*)"', cond)
            if args_m:
                return bool(re.search(args_m.group(1), query, re.IGNORECASE))
            raise AssertionError(f"Unsupported nginx server guard: {cond}")

        def _render_nginx_access_line(method: str, norm_path: str, query: str, status: int, headers) -> str:
            _, uri_r = _nginx_map_rules(template, "passport_safe_uri")
            _, qry_r = _nginx_map_rules(template, "passport_safe_query")
            safe_uri = _eval_nginx_map(uri_r, norm_path) + _eval_nginx_map(qry_r, "?" if query else "")
            raw_ref = headers.get("Referer", "")
            if "$passport_safe_referer" in fmt_vars:
                _, ref_r = _nginx_map_rules(template, "passport_safe_referer")
                ref_field = _eval_nginx_map(ref_r, raw_ref)
            elif "$http_referer" in fmt_vars:
                ref_field = raw_ref
            else:
                ref_field = "-"
            return f'127.0.0.1 - "{method} {safe_uri} HTTP/1.1" {status} 2 "{ref_field}"'

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def _reply(self, status: int) -> None:
                body = b"{}"
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                parsed = urlsplit(self.path)
                norm_path = _nginx_normalize_uri(parsed.path)
                query = parsed.query
                if flavor == "nginx":
                    for cond, code in guards:
                        if _guard_hit(cond, norm_path, query, self.headers):
                            if site_acc_m:
                                sinks["access"].append(
                                    _render_nginx_access_line(self.command, norm_path, query, code, self.headers)
                                )
                            self._reply(code)  # `return` writes nothing to error_log
                            return
                    in_secret_loc = norm_path.startswith("/xiaozhi/ota/d/")
                    err_sink_null = in_secret_loc and ota_d_block_m and "error_log /dev/null emerg;" in ota_d_block_m.group(1)
                    acc_off = in_secret_loc and ota_d_block_m and "access_log off;" in ota_d_block_m.group(1)
                    if not _upstream_fails():
                        raise AssertionError("dead upstream port unexpectedly accepted")
                    if not err_sink_null and site_err_m:
                        line = (
                            f"[error] connect() failed (111: Connection refused) while connecting to upstream, "
                            f'client: 127.0.0.1, server: passport, request: "{self.requestline}", '
                            f'upstream: "http://127.0.0.1:{dead_port}/xiaozhi/ota/", host: "{self.headers.get("Host", "")}"'
                        )
                        if self.headers.get("Referer"):
                            line += f', referrer: "{self.headers["Referer"]}"'
                        sinks["err"].append(line)
                    if not acc_off and site_acc_m:
                        sinks["access"].append(
                            _render_nginx_access_line(self.command, norm_path, query, 502, self.headers)
                        )
                    self._reply(502)
                    return
                # Caddy: original request is captured before `rewrite` for error logs.
                original_request = {
                    "remote_ip": "127.0.0.1",
                    "method": self.command,
                    "host": self.headers.get("Host", ""),
                    "uri": self.path,
                    "headers": {k: [v] for k, v in self.headers.items()},
                }
                if caddy_secret_re.match(norm_path):
                    pass  # rewrite * /xiaozhi/ota/ happens on a copy; logs keep original
                if not _upstream_fails():
                    raise AssertionError("dead upstream port unexpectedly accepted")
                _caddy_emit(
                    sinks,
                    "http.handlers.reverse_proxy",
                    {"level": "error", "msg": "aborting with incomplete response", "request": original_request},
                )
                _caddy_emit(
                    sinks,
                    "http.log.error.log0",
                    {
                        "level": "error",
                        "msg": f"dial tcp 127.0.0.1:{dead_port}: connect: connection refused",
                        "request": original_request,
                        "status": 502,
                    },
                )
                self._reply(502)

            def do_GET(self):
                self._handle()

            def do_POST(self):
                self._handle()

        return _Handler

    def _drive(flavor: str, template: str, sinks, requests_spec) -> list[int]:
        srv = ThreadingHTTPServer(("127.0.0.1", _free_port()), _make_handler(flavor, template, sinks))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        statuses = []
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            for method, path, referer in requests_spec:
                headers = {"Content-Type": "application/json", "Device-Id": "aa:bb:cc:dd:ee:99"}
                if referer is not None:
                    headers["Referer"] = referer
                req = urllib.request.Request(
                    base + path, data=b"{}" if method == "POST" else None, headers=headers, method=method
                )
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        statuses.append(resp.status)
                except urllib.error.HTTPError as exc:
                    exc.read()
                    statuses.append(exc.code)
        finally:
            srv.shutdown()
            srv.server_close()
        return statuses

    secret_ref = f"https://passport.example/xiaozhi/ota/d/{syn}/"
    encoded_slash_ref = f"https://passport.example/xiaozhi%2Fota%2Fd%2F{syn}%2F"
    encoded_letter_1 = f"https://passport.example/%78iaozhi/ota/d/{syn}/"
    encoded_letter_2 = f"https://passport.example/xiaozhi/%6fta/%64/{syn}/"
    encoded_letter_3 = f"https://passport.example/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn}/"
    encoded_letter_4 = f"https://passport.example/xia%6fzhi/o%74a/%64/{syn}/"
    encoded_letter_mixed = f"https://passport.example/xia%4fzhi/O%54a/%44/{syn}/"
    dot_segment_ref = f"https://passport.example/xiaozhi/./foo/../ota//d/{syn}/"

    for eq_url in (
        secret_ref,
        encoded_slash_ref,
        encoded_letter_1,
        encoded_letter_2,
        encoded_letter_3,
        encoded_letter_4,
        dot_segment_ref,
    ):
        assert _nginx_normalize_uri(urlsplit(eq_url).path) == f"/xiaozhi/ota/d/{syn}/", eq_url
    assert _nginx_normalize_uri(urlsplit(encoded_letter_mixed).path).lower() == f"/xiaozhi/ota/d/{syn}/".lower()

    # --- Caddy: 502 backend failure on secret route and normal route ---
    caddy_sinks = _caddy_log_sinks(caddy_text)
    caddy_status = _drive(
        "caddy",
        caddy_text,
        caddy_sinks,
        [("POST", f"/xiaozhi/ota/d/{syn}/", secret_ref), ("POST", "/xiaozhi/ota/", secret_ref)],
    )
    assert caddy_status == [502, 502], caddy_status
    err_sink = [s for s in caddy_sinks if "http.log.error" in s["include"]]
    assert err_sink and len(err_sink[0]["lines"]) >= 4, "Caddy runtime error sink did not receive failure entries"
    assert any('"[REDACTED]"' in line for line in err_sink[0]["lines"])
    default_sink = [s for s in caddy_sinks if s["name"] == "default"][0]
    assert not any("http.log.error" in line or "reverse_proxy" in line for line in default_sink["lines"])
    for sink in caddy_sinks:
        for line in sink["lines"]:
            assert syn not in line, f"Caddy {sink['name']} log leaked OTA secret on backend failure"
    # Negative control: without the global log block the default (unfiltered) log leaks.
    caddy_no_global = re.sub(r"^\{\n.*?^\}\n", "", caddy_text, count=1, flags=re.DOTALL | re.MULTILINE)
    assert caddy_no_global != caddy_text
    ctrl_sinks = _caddy_log_sinks(caddy_no_global)
    _drive("caddy", caddy_no_global, ctrl_sinks, [("POST", f"/xiaozhi/ota/d/{syn}/", None)])
    assert any(syn in line for s in ctrl_sinks for line in s["lines"]), "Caddy negative control failed to detect leak"

    # --- Nginx: site error log and access log across literal & equivalent percent-encoded Referers ---
    guards = _nginx_server_guards(nginx_text)
    assert ("$passport_unsafe_referer", 400) in guards, f"Missing server-level Referer guard: {guards}"
    site_err = re.search(r"^    error_log\s+(\S+)\s+(\w+);", nginx_text, re.MULTILINE)
    assert site_err and site_err.group(1) != "/dev/null", "site error_log must remain a real diagnostic log"
    nginx_logs: dict[str, list[str]] = {"err": [], "access": []}
    nginx_status = _drive(
        "nginx",
        nginx_text,
        nginx_logs,
        [
            ("POST", "/xiaozhi/ota/", secret_ref),
            ("POST", "/xiaozhi/ota/", encoded_slash_ref),
            ("POST", "/xiaozhi/ota/", encoded_letter_1),
            ("POST", "/xiaozhi/ota/", encoded_letter_2),
            ("POST", "/xiaozhi/ota/", encoded_letter_3),
            ("POST", "/xiaozhi/ota/", encoded_letter_4),
            ("POST", "/xiaozhi/ota/", encoded_letter_mixed),
            ("POST", "/xiaozhi/ota/", dot_segment_ref),
            ("GET", "/xiaozhi/v1/", encoded_letter_3),
            ("POST", "/mcp/vision/explain", f"https://u:{syn}@passport.example/"),
            ("POST", "/xiaozhi/ota/", f"https://passport.example/?token={syn}"),
            ("POST", "/xiaozhi/ota/", "https://passport.example/docs"),
            ("POST", "/xiaozhi/ota/", "https://passport.example/"),
            ("POST", f"/xiaozhi/ota/d/{syn}/", None),
            ("POST", f"/%78iaozhi/%6fta/%64/{syn}/", None),
            ("POST", f"/%78iaozhi/%6fta/%64/{syn}/", encoded_letter_3),
        ],
    )
    assert nginx_status == [400] * 12 + [502, 502, 502, 400], nginx_status
    assert len(nginx_logs["err"]) == 1 and 'referrer: "https://passport.example/"' in nginx_logs["err"][0], (
        f"nginx stand-in error_log unexpected: {nginx_logs['err']}"
    )
    assert len(nginx_logs["access"]) == 14, f"expected 14 access log entries, got {len(nginx_logs['access'])}"
    assert "/xiaozhi/ota/d/[REDACTED]/" in nginx_logs["access"][-1]
    assert not any(syn in line for line in nginx_logs["err"] + nginx_logs["access"]), (
        "nginx template-driven stand-in leaked OTA secret into error_log or access_log"
    )

    # Negative control 1 (Round-3 bypass): reverting to Round-3 regex denylist + $passport_safe_referer
    # leaks fixed-segment letter-percent-encoded OTA URLs into BOTH error_log AND access_log.
    round3_maps = (
        "map $http_referer $passport_safe_referer {\n"
        "    ~(?i)xiaozhi(/|%2f)ota(/|%2f)d(/|%2f)  \"[REDACTED]\";\n"
        "    ~://[^/\\s]*@          \"[REDACTED]\";\n"
        "    ~\\?                   \"[REDACTED]\";\n"
        "    default               $http_referer;\n"
        "}\n"
        "map $http_referer $passport_unsafe_referer {\n"
        "    ~(?i)xiaozhi(/|%2f)ota(/|%2f)d(/|%2f)  1;\n"
        "    ~://[^/\\s]*@          1;\n"
        "    ~\\?                   1;\n"
        "    default               0;\n"
        "}\n"
    )
    nginx_round3 = re.sub(
        r"map \$http_referer \$passport_unsafe_referer \{.*?\}",
        lambda _m: round3_maps.rstrip(),
        nginx_text,
        count=1,
        flags=re.DOTALL,
    )
    nginx_round3 = nginx_round3.replace('$status $body_bytes_sent "-"', '$status $body_bytes_sent "$passport_safe_referer"')
    assert nginx_round3 != nginx_text
    r3_logs: dict[str, list[str]] = {"err": [], "access": []}
    r3_status = _drive(
        "nginx",
        nginx_round3,
        r3_logs,
        [("POST", "/xiaozhi/ota/", encoded_letter_1), ("POST", "/xiaozhi/ota/", encoded_letter_3)],
    )
    assert r3_status == [502, 502], f"Round-3 denylist unexpectedly blocked letter-encoded Referers: {r3_status}"
    assert any(syn in line for line in r3_logs["err"]), "Round-3 negative control failed to leak into error_log"
    assert any(syn in line for line in r3_logs["access"]), "Round-3 negative control failed to leak into access_log"

    # Negative control 2: removing the server-level guard leaks raw referrer into error_log while access_log stays clean.
    nginx_no_guard = re.sub(
        r"\n\s*if \(\$passport_unsafe_referer\) \{\s*return 400;\s*\}", "", nginx_text, count=1
    )
    assert nginx_no_guard != nginx_text
    ctrl_logs: dict[str, list[str]] = {"err": [], "access": []}
    ctrl_status = _drive("nginx", nginx_no_guard, ctrl_logs, [("POST", "/xiaozhi/ota/", encoded_letter_3)])
    assert ctrl_status == [502]
    assert any(syn in line for line in ctrl_logs["err"]), "nginx guard-removal negative control failed to detect error_log leak"
    assert not any(syn in line for line in ctrl_logs["access"]), "access_log should remain redacted even without guard"
    print(
        "[PASS] round-2/3: Caddy/Nginx template-driven stand-ins (no real nginx binary in sandbox) "
        "record zero OTA secrets across literal & letter-percent-encoded equivalents"
    )


def test_async_asr_nonblocking_disk_io(server_home: Path, fake_port: int) -> None:
    """Non-blocker #6: in-memory WAV upload skips disk I/O; slow disk archiving does not block event loop."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        srv_home = _make_srv_home(server_home, tmp / "asr_srv_home")
        devices_file = tmp / "devices.yaml"
        auth_file = tmp / "auth_key"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "provision_device.py"),
                "add",
                "--devices-file",
                str(devices_file),
                "--device-id",
                "aa:bb:cc:dd:ee:66",
                "--client-id",
                "asr-io-client",
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write_config.py")],
            env=_base_env(
                XIAOZHI_HOME=str(srv_home),
                PASSPORT_MODE="demo",
                PASSPORT_AUTH_FILE=str(auth_file),
                PASSPORT_DEVICES_FILE=str(devices_file),
                PASSPORT_LOG_DIR=str(srv_home / "tmp"),
                PASSPORT_FAKE_BASE=f"http://127.0.0.1:{fake_port}",
            ),
            check=True,
            capture_output=True,
            text=True,
        )

        probe_code = """
import asyncio, os, shutil, sys, time
from pathlib import Path
import httpx

os.chdir(os.environ["XIAOZHI_HOME"])
for p in (os.environ["PASSPORT_ROOT"], os.environ["XIAOZHI_HOME"]):
    if p not in sys.path:
        sys.path.insert(0, p)

from passport_server.patches import apply_all_patches
apply_all_patches()
from passport_server.async_openai_asr import AsyncOpenAIASRProvider

fake_port = int(os.environ["TEST_FAKE_PORT"])
cfg = {
    "api_key": "local-fake-provider",
    "base_url": f"http://127.0.0.1:{fake_port}/v1/audio/transcriptions",
    "model_name": "fake-asr",
    "output_dir": os.environ["TEST_AUDIO_OUT"],
    "connect_timeout": 2.0,
    "read_timeout": 5.0,
    "write_timeout": 2.0,
    "pool_timeout": 2.0,
    "total_timeout": 6.0,
    "max_audio_bytes": 1024,
}

async def main():
    pcm = [b"\\x01\\x00" * 400]

    # 1. delete_audio_file=True performs zero disk I/O (in-memory WAV buffer).
    p_mem = AsyncOpenAIASRProvider(cfg, delete_audio_file=True)
    orig_disk_usage = shutil.disk_usage
    def _forbid(*a, **kw):
        raise AssertionError("disk_usage/save_audio_to_file must not be called when delete_audio_file=True")
    shutil.disk_usage = _forbid
    p_mem.save_audio_to_file = _forbid
    try:
        text, fpath = await p_mem.speech_to_text_wrapper(pcm, "sess-mem")
        assert text == "合约测试", f"unexpected transcript: {text!r}"
        assert fpath is None
        # Oversized PCM rejected without hitting provider.
        big_text, big_path = await p_mem.speech_to_text_wrapper([b"\\x00" * 2048], "sess-big")
        assert big_text == "" and big_path is None
    finally:
        shutil.disk_usage = orig_disk_usage

    # 2. delete_audio_file=False with slow disk does not block concurrent event loop tasks.
    p_disk = AsyncOpenAIASRProvider({**cfg, "max_audio_bytes": 65536}, delete_audio_file=False)
    orig_save = p_disk.save_audio_to_file
    def slow_save(pcm_data, session_id):
        time.sleep(0.6)
        return orig_save(pcm_data, session_id)
    p_disk.save_audio_to_file = slow_save

    async def probe_loop():
        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=2.0) as client:
            for _ in range(3):
                r = await client.get(f"http://127.0.0.1:{fake_port}/_stats")
                assert r.status_code == 200
                await asyncio.sleep(0.02)
        return time.monotonic() - t0

    t_start = time.monotonic()
    asr_task = asyncio.create_task(p_disk.speech_to_text_wrapper(pcm, "sess-slow-disk"))
    await asyncio.sleep(0.05)
    probe_elapsed = await probe_loop()
    disk_text, disk_path = await asr_task
    total_elapsed = time.monotonic() - t_start

    assert probe_elapsed < 0.25, f"slow WAV disk I/O blocked event loop: probe took {probe_elapsed:.3f}s"
    assert total_elapsed >= 0.55, f"slow save stub did not run: {total_elapsed:.3f}s"
    assert disk_text == "合约测试", f"unexpected slow-disk transcript: {disk_text!r}"
    assert disk_path and Path(disk_path).is_file(), f"expected archived WAV file, got {disk_path!r}"

asyncio.run(main())
"""
        res = subprocess.run(
            [sys.executable, "-c", probe_code],
            env=_base_env(
                XIAOZHI_HOME=str(srv_home),
                PASSPORT_ROOT=str(ROOT),
                PASSPORT_LOG_DIR=str(srv_home / "tmp"),
                TEST_FAKE_PORT=str(fake_port),
                TEST_AUDIO_OUT=str(tmp / "asr_out"),
            ),
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert res.returncode == 0, (
            f"non-blocking ASR I/O test failed ({res.returncode}):\n{res.stdout}\n{res.stderr}"
        )
    print("[PASS] non-blocker #6: memory WAV skips disk I/O and slow disk archiving does not block event loop")


async def _ws_expect_rejected(ws_url: str, headers: dict, label: str) -> None:
    try:
        async with websockets.connect(ws_url, additional_headers=headers) as ws:
            try:
                raw = await asyncio.wait_for(ws.recv(), 4.0)
            except websockets.exceptions.ConnectionClosed:
                return
            text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
            assert "认证失败" in text, f"{label}: expected 认证失败, got {text!r}"
            try:
                msg = await asyncio.wait_for(ws.recv(), 2.0)
                raise AssertionError(f"{label}: expected closed WS after rejection, got {msg!r}")
            except websockets.exceptions.ConnectionClosed:
                return
    except websockets.exceptions.InvalidStatus:
        return


async def _run_live_server_regressions(
    ota_base: str,
    ws_url: str,
    fake_url: str,
    devices_file: Path,
    auth_key: str,
    dev_a: dict,
    dev_b: dict,
) -> dict:
    issued_secrets = {dev_a["ota_secret"], dev_b["ota_secret"], auth_key}
    query_sentinel_1 = "qsec_" + secrets.token_hex(8)
    query_sentinel_2 = "qtok_" + secrets.token_hex(8)
    issued_secrets.update({query_sentinel_1, query_sentinel_2})

    # --- Blocker #1: OTA rejections ---
    st, body = post_ota(
        ota_base,
        {"Device-Id": "de:ad:be:ef:00:99", "Client-Id": "unregistered-client"},
        secret="random-unregistered-secret",
    )
    assert st in (401, 403) and "websocket" not in body, f"unregistered OTA succeeded: {st} {body}"

    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
    )
    assert st == 401 and "websocket" not in body, f"OTA missing secret: {st} {body}"

    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
        secret="wrong-secret-" + secrets.token_hex(6),
    )
    assert st == 403 and "websocket" not in body, f"OTA wrong secret: {st} {body}"

    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_b["device_id"], "Client-Id": dev_b["client_id"]},
        secret=dev_a["ota_secret"],
    )
    assert st == 403 and "websocket" not in body, f"cross-device secret accepted: {st} {body}"

    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_a["device_id"], "Client-Id": "spoofed-client-id"},
        secret=dev_a["ota_secret"],
    )
    assert st == 403 and "websocket" not in body, f"wrong client_id accepted: {st} {body}"

    st, body = post_json(
        f"{ota_base}/xiaozhi/ota/?secret={query_sentinel_1}",
        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
    )
    assert st == 400 and "websocket" not in body, f"query secret OTA accepted: {st} {body}"

    st_a, ota_a = post_ota(
        ota_base,
        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
        secret=dev_a["ota_secret"],
    )
    assert st_a == 200 and ota_a["websocket"]["version"] == 1
    token_a = ota_a["websocket"]["token"]
    issued_secrets.add(token_a)

    st_b, ota_b = post_ota(
        ota_base,
        {"Device-Id": dev_b["device_id"], "Client-Id": dev_b["client_id"]},
        secret=dev_b["ota_secret"],
    )
    assert st_b == 200
    token_b = ota_b["websocket"]["token"]
    issued_secrets.add(token_b)

    # --- Blocker #1: WebSocket auth rejections & allowed_devices bypass closure ---
    await _ws_expect_rejected(
        ws_url,
        {
            "Device-Id": dev_a["device_id"],
            "Client-Id": dev_a["client_id"],
            "Protocol-Version": "1",
        },
        "allowlisted device without Authorization",
    )
    await _ws_expect_rejected(
        ws_url,
        {
            "Device-Id": dev_a["device_id"],
            "Client-Id": dev_a["client_id"],
            "Protocol-Version": "1",
            "Authorization": "Bearer bogus-token-for-allowlisted-device",
        },
        "allowlisted device with bogus token",
    )
    await _ws_expect_rejected(
        ws_url,
        {
            "Device-Id": "de:ad:be:ef:00:99",
            "Client-Id": "unregistered-client",
            "Protocol-Version": "1",
            "Authorization": f"Bearer {token_a}",
        },
        "unregistered WS device",
    )
    await _ws_expect_rejected(
        ws_url,
        {
            "Device-Id": dev_b["device_id"],
            "Client-Id": dev_b["client_id"],
            "Protocol-Version": "1",
            "Authorization": f"Bearer {token_a}",
        },
        "token A with device B",
    )
    await _ws_expect_rejected(
        ws_url,
        {
            "Device-Id": dev_a["device_id"],
            "Client-Id": "wrong-client-uuid",
            "Protocol-Version": "1",
            "Authorization": f"Bearer {token_a}",
        },
        "token A with wrong client_id",
    )

    auth_helper = PassportDeviceAuth(
        {
            "server": {
                "auth_key": auth_key,
                "auth": {"expire_seconds": 30, "devices_file": str(devices_file)},
            }
        }
    )
    rec_a = auth_helper.get_device(dev_a["device_id"])
    assert rec_a is not None
    expired_token_a = auth_helper.generate_ws_token(
        rec_a,
        client_id=dev_a["client_id"],
        device_id=dev_a["device_id"],
        ts=int(time.time()) - 200000,
    )
    issued_secrets.add(expired_token_a)
    await _ws_expect_rejected(
        ws_url,
        {
            "Device-Id": dev_a["device_id"],
            "Client-Id": dev_a["client_id"],
            "Protocol-Version": "1",
            "Authorization": f"Bearer {expired_token_a}",
        },
        "expired WS token",
    )
    await _ws_expect_rejected(
        f"{ws_url}?authorization=Bearer+{query_sentinel_1}&token={query_sentinel_2}",
        {
            "Device-Id": dev_a["device_id"],
            "Client-Id": dev_a["client_id"],
            "Protocol-Version": "1",
            "Authorization": f"Bearer {token_a}",
        },
        "WS query credential injection",
    )

    req_vision = urllib.request.Request(
        f"{ota_base}/mcp/vision/explain",
        data=b"",
        headers={"Client-Id": "web_test_client", "Device-Id": dev_a["device_id"]},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req_vision, timeout=5) as resp:
            raise AssertionError(f"vision bypass succeeded with status {resp.status}")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401, f"expected 401 on vision without token, got {exc.code}"

    # --- Non-blocker #5: Strict ASR concurrency, timeout, abort cancel, & disconnect cancel ---
    # Server is started with PASSPORT_ASR_TIMEOUT=4.0 (read=4.0s, total=4.5s).
    post_json(
        f"{fake_url}/_control",
        {},
        {"reset": True, "asr_delays": [12.0, 0.0]},
    )

    headers_a = {
        "Device-Id": dev_a["device_id"],
        "Client-Id": dev_a["client_id"],
        "Protocol-Version": "1",
        "Authorization": f"Bearer {token_a}",
    }
    headers_b = {
        "Device-Id": dev_b["device_id"],
        "Client-Id": dev_b["client_id"],
        "Protocol-Version": "1",
        "Authorization": f"Bearer {token_b}",
    }

    async with websockets.connect(ws_url, additional_headers=headers_a) as ws_a:
        hello_a = await send_hello(ws_a)
        sid_a = hello_a["session_id"]

        # Start slow ASR on Session A (manual listen stop)
        await ws_a.send(
            json.dumps({"session_id": sid_a, "type": "listen", "state": "start", "mode": "manual"})
        )
        for frame in opus_frames(8):
            await ws_a.send(frame)
        await asyncio.sleep(0.1)
        await ws_a.send(json.dumps({"session_id": sid_a, "type": "listen", "state": "stop"}))

        t_wait_inflight = time.monotonic()
        req_a_id = None
        while time.monotonic() - t_wait_inflight < 5.0:
            stats = _get_json(f"{fake_url}/_stats")
            if stats["asr_in_flight_ids"]:
                req_a_id = stats["asr_in_flight_ids"][-1]
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Session A ASR request never reached fake_provider")

        # Session B completes OTA + WS hello + full voice turn WHILE Session A's ASR is STILL in flight.
        t_b0 = time.monotonic()
        st_b2, ota_b2 = post_ota(
            ota_base,
            {"Device-Id": dev_b["device_id"], "Client-Id": dev_b["client_id"]},
            secret=dev_b["ota_secret"],
        )
        assert st_b2 == 200
        issued_secrets.add(ota_b2["websocket"]["token"])
        async with websockets.connect(
            ota_b2["websocket"]["url"],
            additional_headers={**headers_b, "Authorization": f"Bearer {ota_b2['websocket']['token']}"},
        ) as ws_b:
            hello_b = await send_hello(ws_b)
            turn_b = await run_turn(ws_b, hello_b["session_id"])
        b_elapsed = time.monotonic() - t_b0
        assert b_elapsed < 3.5, f"Session B was blocked by hung Session A ASR ({b_elapsed:.2f}s)"
        assert "合约测试" in "".join(turn_b["stt"])
        assert turn_b["decoded_pcm_bytes"] > 0 and "stop" in turn_b["tts_states"]

        stats_after_b = _get_json(f"{fake_url}/_stats")
        assert req_a_id in stats_after_b["asr_in_flight_ids"], (
            f"Session A ASR req_id={req_a_id} was no longer in flight when Session B finished: {stats_after_b}"
        )
        assert any(
            req["id"] > req_a_id and req["state"] == "completed"
            for req in stats_after_b["asr_requests"]
        ), f"Session B ASR completion not recorded after req_id={req_a_id}: {stats_after_b['asr_requests']}"

        # Wait for Session A's hung ASR to hit its ~4.0s/4.5s timeout (well under 12.0s delay).
        t_timeout_wait = time.monotonic()
        while time.monotonic() - t_timeout_wait < 7.0:
            stats = _get_json(f"{fake_url}/_stats")
            if req_a_id not in stats["asr_in_flight_ids"]:
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("Session A hung ASR did not time out within 7s")
        timeout_elapsed = time.monotonic() - t_wait_inflight
        assert 3.5 <= timeout_elapsed < 7.0, f"Unexpected ASR timeout duration: {timeout_elapsed:.2f}s"

        # Session A recovers cleanly on next fast turn.
        turn_a_after_timeout = await run_turn(ws_a, sid_a)
        assert "合约测试" in "".join(turn_a_after_timeout["stt"])
        assert "stop" in turn_a_after_timeout["tts_states"]

        # 3b. Abort cancels specific in-flight ASR request far faster than the 4.0s timeout.
        post_json(f"{fake_url}/_control", {}, {"asr_delays": [15.0]})
        await ws_a.send(
            json.dumps({"session_id": sid_a, "type": "listen", "state": "start", "mode": "manual"})
        )
        for frame in opus_frames(8):
            await ws_a.send(frame)
        await asyncio.sleep(0.1)
        await ws_a.send(json.dumps({"session_id": sid_a, "type": "listen", "state": "stop"}))

        t_inflight2 = time.monotonic()
        req_abort_id = None
        while time.monotonic() - t_inflight2 < 5.0:
            stats = _get_json(f"{fake_url}/_stats")
            newer = [rid for rid in stats["asr_in_flight_ids"] if rid > req_a_id]
            if newer:
                req_abort_id = newer[-1]
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Second slow ASR request never started")
        t_abort_req_started = time.monotonic()

        t_abort_sent = time.monotonic()
        await ws_a.send(
            json.dumps({"session_id": sid_a, "type": "abort", "reason": "wake_word_detected"})
        )
        msg = json.loads(await asyncio.wait_for(ws_a.recv(), 1.5))
        assert msg.get("type") == "tts" and msg.get("state") == "stop"

        while time.monotonic() - t_abort_sent < 1.2:
            stats = _get_json(f"{fake_url}/_stats")
            rec = next((r for r in stats["asr_requests"] if r["id"] == req_abort_id), None)
            if rec is not None and rec["state"] == "aborted" and req_abort_id not in stats["asr_in_flight_ids"]:
                break
            await asyncio.sleep(0.03)
        else:
            raise AssertionError(f"Aborted ASR req_id={req_abort_id} did not disconnect within 1.2s")
        assert time.monotonic() - t_abort_req_started < 2.2, (
            "Aborted ASR elapsed too close to 4.0s ASR timeout"
        )

        # Recover again after cancelling slow ASR.
        turn_a_after_cancel = await run_turn(ws_a, sid_a)
        assert "合约测试" in "".join(turn_a_after_cancel["stt"])

    # 3c. Abrupt WebSocket disconnect also cancels in-flight ASR request far faster than 4.0s timeout.
    post_json(f"{fake_url}/_control", {}, {"asr_delays": [15.0]})
    ws_disc = await websockets.connect(ws_url, additional_headers=headers_a)
    try:
        hello_disc = await send_hello(ws_disc)
        sid_disc = hello_disc["session_id"]
        await ws_disc.send(
            json.dumps({"session_id": sid_disc, "type": "listen", "state": "start", "mode": "manual"})
        )
        for frame in opus_frames(8):
            await ws_disc.send(frame)
        await asyncio.sleep(0.1)
        await ws_disc.send(json.dumps({"session_id": sid_disc, "type": "listen", "state": "stop"}))

        t_disc_wait = time.monotonic()
        req_disc_id = None
        while time.monotonic() - t_disc_wait < 5.0:
            stats = _get_json(f"{fake_url}/_stats")
            newer = [rid for rid in stats["asr_in_flight_ids"] if rid > req_abort_id]
            if newer:
                req_disc_id = newer[-1]
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Disconnect-test ASR request never started")
        t_disc_started = time.monotonic()

        t_dropped = time.monotonic()
        if ws_disc.transport is not None:
            ws_disc.transport.abort()
        else:
            await ws_disc.close()
    finally:
        if ws_disc.transport is not None and not ws_disc.transport.is_closing():
            ws_disc.transport.abort()

    while time.monotonic() - t_dropped < 1.5:
        stats = _get_json(f"{fake_url}/_stats")
        rec = next((r for r in stats["asr_requests"] if r["id"] == req_disc_id), None)
        if rec is not None and rec["state"] == "aborted" and req_disc_id not in stats["asr_in_flight_ids"]:
            break
        await asyncio.sleep(0.03)
    else:
        raise AssertionError(f"Disconnected WS ASR req_id={req_disc_id} did not abort within 1.5s")
    assert time.monotonic() - t_disc_started < 2.5, (
        "WebSocket disconnect cancel elapsed too close to 4.0s ASR timeout"
    )

    async with websockets.connect(ws_url, additional_headers=headers_a) as ws_rec:
        hello_rec = await send_hello(ws_rec)
        turn_rec = await run_turn(ws_rec, hello_rec["session_id"])
        assert "合约测试" in "".join(turn_rec["stt"])

    # --- Live device revocation ---
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "provision_device.py"),
            "revoke",
            "--devices-file",
            str(devices_file),
            "--device-id",
            dev_b["device_id"],
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    st_rev, body_rev = post_ota(
        ota_base,
        {"Device-Id": dev_b["device_id"], "Client-Id": dev_b["client_id"]},
        secret=dev_b["ota_secret"],
    )
    assert st_rev == 403 and "websocket" not in body_rev
    await _ws_expect_rejected(ws_url, headers_b, "revoked device with previously issued token")

    print(
        f"[PASS] blockers #1 & non-blocker #5: OTA/WS device auth, allowlist bypass closed, "
        f"Session B ({b_elapsed:.2f}s) completed while Session A still in flight, "
        f"timeout, abort cancel, & disconnect cancel verified"
    )
    return {"secrets_to_check": issued_secrets}


def test_real_ttl_expiration(server_home: Path, fake_port: int) -> set[str]:
    """Verify a naturally issued token expires once expire_seconds elapses."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ws_port = _free_port()
        http_port = _free_port()
        auth_file = tmp / "auth_key"
        devices_file = tmp / "devices.yaml"
        log_dir = tmp / "logs"
        log_dir.mkdir(parents=True)
        srv_home = _make_srv_home(server_home, tmp / "srv_home")

        dev_raw = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "provision_device.py"),
                "add",
                "--devices-file",
                str(devices_file),
                "--device-id",
                "aa:bb:cc:dd:ee:77",
                "--client-id",
                "ttl-client-77",
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        dev = json.loads(dev_raw.stdout)

        env = _base_env(
            XIAOZHI_HOME=str(srv_home),
            PASSPORT_MODE="demo",
            PASSPORT_AUTH_FILE=str(auth_file),
            PASSPORT_DEVICES_FILE=str(devices_file),
            PASSPORT_LOG_DIR=str(srv_home / "tmp"),
            PASSPORT_BIND="127.0.0.1",
            PASSPORT_WS_BIND_PORT=str(ws_port),
            PASSPORT_HTTP_BIND_PORT=str(http_port),
            PASSPORT_PUBLIC_WS=f"ws://127.0.0.1:{ws_port}/xiaozhi/v1/",
            PASSPORT_PUBLIC_HTTP=f"http://127.0.0.1:{http_port}/mcp/vision/explain",
            PASSPORT_FAKE_BASE=f"http://127.0.0.1:{fake_port}",
            PASSPORT_AUTH_EXPIRE_SECONDS="2",
        )
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write_config.py")],
            env=env,
            check=True,
            capture_output=True,
        )
        stdout_log = log_dir / "ttl-server.log"
        with open(stdout_log, "w", encoding="utf-8") as out:
            proc = subprocess.Popen(
                [sys.executable, str(ROOT / "passport_server" / "runner.py")],
                env=env,
                stdout=out,
                stderr=subprocess.STDOUT,
            )
        try:
            ota_base = f"http://127.0.0.1:{http_port}"
            _wait_for_http_ready(f"{ota_base}/xiaozhi/ota/", proc, stdout_log)
            st, ota = post_ota(
                ota_base,
                {"Device-Id": dev["device_id"], "Client-Id": dev["client_id"]},
                secret=dev["ota_secret"],
            )
            assert st == 200
            token = ota["websocket"]["token"]
            ws_url = ota["websocket"]["url"]
            time.sleep(3.2)
            asyncio.run(
                _ws_expect_rejected(
                    ws_url,
                    {
                        "Device-Id": dev["device_id"],
                        "Client-Id": dev["client_id"],
                        "Protocol-Version": "1",
                        "Authorization": f"Bearer {token}",
                    },
                    "naturally expired WS token",
                )
            )
        finally:
            _stop_process_gracefully(proc, "ttl-server")
        assert_logs_redacted(
            [stdout_log, srv_home / "tmp" / "server.log"],
            {dev["ota_secret"], token, auth_file.read_text(encoding="utf-8").strip()},
            required_markers=["拒绝WebSocket连接"],
            require_conn_headers=False,
        )
        print("[PASS] blocker #1 natural TTL token expiration rejected (both stdout & file logs verified)")
        return {dev["ota_secret"], token}


def test_debug_and_provider_error_log_redaction(server_home: Path, fake_port: int) -> None:
    """Blocker #3: verify stdout & server.log contain zero leaks under DEBUG, MCP JWT, and provider errors."""
    fake_url = f"http://127.0.0.1:{fake_port}"

    async def _exercise_mcp_and_turn(
        ws_url: str,
        headers: dict,
        send_audio: bool,
    ) -> str:
        vision_jwt = ""
        async with websockets.connect(ws_url, additional_headers=headers) as ws:
            await send_hello(ws)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                raw = await asyncio.wait_for(ws.recv(), 3.0)
                if isinstance(raw, bytes):
                    continue
                msg = json.loads(raw)
                if msg.get("type") == "mcp":
                    payload = msg.get("payload") or {}
                    if payload.get("method") == "initialize":
                        vision_jwt = (
                            payload.get("params", {})
                            .get("capabilities", {})
                            .get("vision", {})
                            .get("token", "")
                        )
                        break
            assert vision_jwt.startswith("eyJ") and vision_jwt.count(".") == 2, (
                "Server did not emit MCP initialize Vision JWT"
            )
            if send_audio:
                sid = ""
                await ws.send(
                    json.dumps({"session_id": sid, "type": "listen", "state": "start", "mode": "manual"})
                )
                for frame in opus_frames(8):
                    await ws.send(frame)
                await asyncio.sleep(0.1)
                await ws.send(json.dumps({"session_id": sid, "type": "listen", "state": "stop"}))
                await asyncio.sleep(0.8)
        return vision_jwt

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # --- Sub-run 1: Live DEBUG server hitting MCP JWT + ASR 500 echoed body + LLM + TTS 500 echoed body ---
            ws_port_1 = _free_port()
            http_port_1 = _free_port()
            srv_home_1 = _make_srv_home(server_home, tmp / "srv_home_1")
            devices_1 = tmp / "devices_1.yaml"
            auth_1 = tmp / "auth_key_1"
            dev_1 = json.loads(
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "provision_device.py"),
                        "add",
                        "--devices-file",
                        str(devices_1),
                        "--device-id",
                        "aa:bb:cc:dd:ee:31",
                        "--client-id",
                        "debug-mcp-client-1",
                        "--json",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            )
            exp_asr_key = "exp_asr_" + secrets.token_hex(10)
            exp_llm_key = "exp_llm_" + secrets.token_hex(10)
            exp_tts_key = "exp_tts_" + secrets.token_hex(10)
            unreg_asr_secret = "exp_unreg_asr_" + secrets.token_hex(10)
            unreg_tts_secret = "exp_unreg_tts_" + secrets.token_hex(10)
            asr_qkey = "exp_aq_" + secrets.token_hex(8)
            tts_qkey = "exp_tq_" + secrets.token_hex(8)

            cfg_1 = tmp / "debug_cfg_1.yaml"
            cfg_1.write_text(
                yaml.safe_dump(
                    {
                        "server": {
                            "ip": "127.0.0.1",
                            "port": ws_port_1,
                            "http_port": http_port_1,
                            "websocket": f"ws://127.0.0.1:{ws_port_1}/xiaozhi/v1/",
                            "vision_explain": f"http://127.0.0.1:{http_port_1}/mcp/vision/explain",
                            "auth": {"enabled": True, "allowed_devices": []},
                        },
                        "log": {"log_level": "DEBUG", "log_dir": str(srv_home_1 / "tmp")},
                        "read_config_from_api": False,
                        "enable_wakeup_words_response_cache": False,
                        "enable_greeting": False,
                        "tts_timeout": 5,
                        "end_prompt": {"enable": False},
                        "xiaozhi": {
                            "type": "hello",
                            "version": 1,
                            "transport": "websocket",
                            "audio_params": {
                                "format": "opus",
                                "sample_rate": 16000,
                                "channels": 1,
                                "frame_duration": 60,
                            },
                        },
                        "selected_module": {
                            "VAD": "SileroVAD",
                            "ASR": "DbgASR",
                            "LLM": "DbgLLM",
                            "TTS": "DbgTTS",
                            "Memory": "nomem",
                            "Intent": "nointent",
                        },
                        "VAD": {
                            "SileroVAD": {
                                "type": "silero",
                                "threshold": 0.5,
                                "threshold_low": 0.3,
                                "model_dir": "models/snakers4_silero-vad",
                                "min_silence_duration_ms": 200,
                            }
                        },
                        "ASR": {
                            "DbgASR": {
                                "type": "openai",
                                "api_key": exp_asr_key,
                                "base_url": f"http://127.0.0.1:{fake_port}/v1/audio/transcriptions?api_key={asr_qkey}",
                                "model_name": "fake-asr",
                                "output_dir": "tmp/",
                                "connect_timeout": 3,
                                "read_timeout": 5,
                                "write_timeout": 3,
                                "pool_timeout": 3,
                                "total_timeout": 6,
                            }
                        },
                        "LLM": {
                            "DbgLLM": {
                                "type": "openai",
                                "api_key": exp_llm_key,
                                "base_url": f"http://127.0.0.1:{fake_port}/v1",
                                "model_name": "fake-llm",
                                "timeout": {"connect": 3, "read": 5, "write": 3, "pool": 3},
                            }
                        },
                        "TTS": {
                            "DbgTTS": {
                                "type": "openai",
                                "api_key": exp_tts_key,
                                "api_url": f"http://127.0.0.1:{fake_port}/v1/audio/speech?token={tts_qkey}",
                                "model": "fake-tts",
                                "voice": "alloy",
                                "format": "wav",
                                "output_dir": "tmp/",
                            }
                        },
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            env_1 = _base_env(
                XIAOZHI_HOME=str(srv_home_1),
                PASSPORT_MODE="real",
                PASSPORT_CONFIG_FILE=str(cfg_1),
                PASSPORT_AUTH_FILE=str(auth_1),
                PASSPORT_DEVICES_FILE=str(devices_1),
                PASSPORT_LOG_LEVEL="DEBUG",
                PASSPORT_LOG_DIR=str(srv_home_1 / "tmp"),
            )
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "write_config.py")],
                env=env_1,
                check=True,
                capture_output=True,
            )
            set_fake_control(
                fake_url,
                {
                    "reset": True,
                    "accepted_api_keys": [exp_asr_key, exp_llm_key, exp_tts_key],
                    "asr_status": 500,
                    "asr_error_body": f"upstream echoed {unreg_asr_secret} and Bearer {exp_asr_key}",
                },
            )
            stdout_1 = tmp / "dbg_stdout_1.log"
            file_log_1 = srv_home_1 / "tmp" / "server.log"
            with open(stdout_1, "w", encoding="utf-8") as out1:
                proc_1 = subprocess.Popen(
                    [sys.executable, str(ROOT / "passport_server" / "runner.py")],
                    env=env_1,
                    stdout=out1,
                    stderr=subprocess.STDOUT,
                )
            try:
                ota_1 = f"http://127.0.0.1:{http_port_1}"
                _wait_for_http_ready(f"{ota_1}/xiaozhi/ota/", proc_1, stdout_1)
                st_1, ota_resp_1 = post_ota(
                    ota_1,
                    {"Device-Id": dev_1["device_id"], "Client-Id": dev_1["client_id"]},
                    secret=dev_1["ota_secret"],
                )
                assert st_1 == 200
                ws_tok_1 = ota_resp_1["websocket"]["token"]
                hdrs_1 = {
                    "Device-Id": dev_1["device_id"],
                    "Client-Id": dev_1["client_id"],
                    "Protocol-Version": "1",
                    "Authorization": f"Bearer {ws_tok_1}",
                }
                # Turn 1: trigger MCP initialize + ASR 500 error body.
                vision_jwt_1 = asyncio.run(
                    _exercise_mcp_and_turn(ota_resp_1["websocket"]["url"], hdrs_1, send_audio=True)
                )
                _wait_for_log_substring([stdout_1, file_log_1], "ASR API请求失败: status=500")

                # Turn 2: ASR 200 -> LLM 200 -> TTS 500 error body.
                prev_tts_total = _get_json(f"{fake_url}/_stats")["tts_total"]
                set_fake_control(
                    fake_url,
                    {
                        "asr_status": 200,
                        "tts_status": 500,
                        "tts_error_body": f"tts echoed {unreg_tts_secret} and Bearer {exp_tts_key}",
                    },
                )

                async def _turn_tts_err() -> None:
                    async with websockets.connect(ota_resp_1["websocket"]["url"], additional_headers=hdrs_1) as ws:
                        hello = await send_hello(ws)
                        sid = hello["session_id"]
                        await ws.send(
                            json.dumps({"session_id": sid, "type": "listen", "state": "start", "mode": "manual"})
                        )
                        for frame in opus_frames(8):
                            await ws.send(frame)
                        await asyncio.sleep(0.1)
                        await ws.send(json.dumps({"session_id": sid, "type": "listen", "state": "stop"}))
                        deadline = time.monotonic() + 8.0
                        while time.monotonic() < deadline:
                            if _get_json(f"{fake_url}/_stats")["tts_total"] >= prev_tts_total + 5:
                                break
                            await asyncio.sleep(0.1)
                        else:
                            raise AssertionError("TTS 500 error path was not triggered 5 times")
                        await asyncio.sleep(0.3)

                asyncio.run(_turn_tts_err())
                _wait_for_log_substring([stdout_1, file_log_1], "OpenAI TTS请求失败: status=500")
            finally:
                _stop_process_gracefully(proc_1, "debug-redaction-server-1")

            forbidden_1 = {
                vision_jwt_1,
                exp_asr_key,
                exp_llm_key,
                exp_tts_key,
                unreg_asr_secret,
                unreg_tts_secret,
                asr_qkey,
                tts_qkey,
                dev_1["ota_secret"],
                ws_tok_1,
                auth_1.read_text(encoding="utf-8").strip(),
            }
            assert_logs_redacted(
                [stdout_1, file_log_1],
                forbidden_1,
                required_markers=[
                    "conn - Headers:",
                    "成功发送MCP消息: method=initialize, id=1",
                    "ASR API请求失败: status=500",
                    "OpenAI TTS请求失败: status=500",
                ],
            )

            # --- Sub-run 2: Live DEBUG server with URL userinfo on ASR/LLM/TTS + direct LLM/TTS probe ---
            ws_port_2 = _free_port()
            http_port_2 = _free_port()
            srv_home_2 = _make_srv_home(server_home, tmp / "srv_home_2")
            devices_2 = tmp / "devices_2.yaml"
            auth_2 = tmp / "auth_key_2"
            dev_2 = json.loads(
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "provision_device.py"),
                        "add",
                        "--devices-file",
                        str(devices_2),
                        "--device-id",
                        "aa:bb:cc:dd:ee:32",
                        "--client-id",
                        "debug-userinfo-client-2",
                        "--json",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            )
            asr_user = "exp_au_" + secrets.token_hex(5)
            asr_pass = "exp_ap_" + secrets.token_hex(6)
            asr_qkey2 = "exp_aq2_" + secrets.token_hex(6)
            llm_user = "exp_lu_" + secrets.token_hex(5)
            llm_pass = "exp_lp_" + secrets.token_hex(6)
            tts_user = "exp_tu_" + secrets.token_hex(5)
            tts_pass = "exp_tp_" + secrets.token_hex(6)
            exp_asr_key2 = "exp_asr2_" + secrets.token_hex(8)
            exp_llm_key2 = "exp_llm2_" + secrets.token_hex(8)
            exp_tts_key2 = "exp_tts2_" + secrets.token_hex(8)

            cfg_2 = tmp / "debug_cfg_2.yaml"
            cfg_2.write_text(
                yaml.safe_dump(
                    {
                        "server": {
                            "ip": "127.0.0.1",
                            "port": ws_port_2,
                            "http_port": http_port_2,
                            "websocket": f"ws://127.0.0.1:{ws_port_2}/xiaozhi/v1/",
                            "vision_explain": f"http://127.0.0.1:{http_port_2}/mcp/vision/explain",
                            "auth": {"enabled": True, "allowed_devices": []},
                        },
                        "log": {"log_level": "DEBUG", "log_dir": str(srv_home_2 / "tmp")},
                        "read_config_from_api": False,
                        "enable_wakeup_words_response_cache": False,
                        "enable_greeting": False,
                        "tts_timeout": 5,
                        "end_prompt": {"enable": False},
                        "xiaozhi": {
                            "type": "hello",
                            "version": 1,
                            "transport": "websocket",
                            "audio_params": {
                                "format": "opus",
                                "sample_rate": 16000,
                                "channels": 1,
                                "frame_duration": 60,
                            },
                        },
                        "selected_module": {
                            "VAD": "SileroVAD",
                            "ASR": "UiASR",
                            "LLM": "UiLLM",
                            "TTS": "UiTTS",
                            "Memory": "nomem",
                            "Intent": "nointent",
                        },
                        "VAD": {
                            "SileroVAD": {
                                "type": "silero",
                                "threshold": 0.5,
                                "threshold_low": 0.3,
                                "model_dir": "models/snakers4_silero-vad",
                                "min_silence_duration_ms": 200,
                            }
                        },
                        "ASR": {
                            "UiASR": {
                                "type": "openai",
                                "api_key": exp_asr_key2,
                                "base_url": f"http://{asr_user}:{asr_pass}@127.0.0.1:{fake_port}/v1/audio/transcriptions?api_key={asr_qkey2}",
                                "model_name": "fake-asr",
                                "output_dir": "tmp/",
                                "connect_timeout": 3,
                                "read_timeout": 5,
                                "write_timeout": 3,
                                "pool_timeout": 3,
                                "total_timeout": 6,
                            }
                        },
                        "LLM": {
                            "UiLLM": {
                                "type": "openai",
                                "api_key": exp_llm_key2,
                                "base_url": f"http://{llm_user}:{llm_pass}@127.0.0.1:{fake_port}/v1",
                                "model_name": "fake-llm",
                                "timeout": {"connect": 3, "read": 5, "write": 3, "pool": 3},
                            }
                        },
                        "TTS": {
                            "UiTTS": {
                                "type": "openai",
                                "api_key": exp_tts_key2,
                                "api_url": f"http://{tts_user}:{tts_pass}@127.0.0.1:{fake_port}/v1/audio/speech",
                                "model": "fake-tts",
                                "voice": "alloy",
                                "format": "wav",
                                "output_dir": "tmp/",
                            }
                        },
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            env_2 = _base_env(
                XIAOZHI_HOME=str(srv_home_2),
                PASSPORT_MODE="real",
                PASSPORT_CONFIG_FILE=str(cfg_2),
                PASSPORT_AUTH_FILE=str(auth_2),
                PASSPORT_DEVICES_FILE=str(devices_2),
                PASSPORT_LOG_LEVEL="DEBUG",
                PASSPORT_LOG_DIR=str(srv_home_2 / "tmp"),
            )
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "write_config.py")],
                env=env_2,
                check=True,
                capture_output=True,
            )
            set_fake_control(fake_url, {"reset": True})
            stdout_2 = tmp / "dbg_stdout_2.log"
            file_log_2 = srv_home_2 / "tmp" / "server.log"
            with open(stdout_2, "w", encoding="utf-8") as out2:
                proc_2 = subprocess.Popen(
                    [sys.executable, str(ROOT / "passport_server" / "runner.py")],
                    env=env_2,
                    stdout=out2,
                    stderr=subprocess.STDOUT,
                )
            try:
                ota_2 = f"http://127.0.0.1:{http_port_2}"
                _wait_for_http_ready(f"{ota_2}/xiaozhi/ota/", proc_2, stdout_2)
                st_2, ota_resp_2 = post_ota(
                    ota_2,
                    {"Device-Id": dev_2["device_id"], "Client-Id": dev_2["client_id"]},
                    secret=dev_2["ota_secret"],
                )
                assert st_2 == 200
                ws_tok_2 = ota_resp_2["websocket"]["token"]
                hdrs_2 = {
                    "Device-Id": dev_2["device_id"],
                    "Client-Id": dev_2["client_id"],
                    "Protocol-Version": "1",
                    "Authorization": f"Bearer {ws_tok_2}",
                }
                vision_jwt_2 = asyncio.run(
                    _exercise_mcp_and_turn(ota_resp_2["websocket"]["url"], hdrs_2, send_audio=True)
                )
                _wait_for_log_substring([stdout_2, file_log_2], "ASR API请求失败: status=401")
            finally:
                _stop_process_gracefully(proc_2, "debug-redaction-server-2")

            forbidden_2 = {
                vision_jwt_2,
                asr_user,
                asr_pass,
                asr_qkey2,
                llm_user,
                llm_pass,
                tts_user,
                tts_pass,
                exp_asr_key2,
                exp_llm_key2,
                exp_tts_key2,
                dev_2["ota_secret"],
                ws_tok_2,
                auth_2.read_text(encoding="utf-8").strip(),
            }
            assert_logs_redacted(
                [stdout_2, file_log_2],
                forbidden_2,
                required_markers=[
                    "conn - Headers:",
                    "成功发送MCP消息: method=initialize, id=1",
                    "ASR API请求失败: status=401",
                ],
            )

            # Direct isolated probe of LLMProvider._apply_thinking_disabled and TTSProvider.text_to_speak userinfo redaction.
            unused_port = _free_port()
            probe_code = """
import asyncio, os, sys
os.chdir(os.environ["XIAOZHI_HOME"])
for p in (os.environ["PASSPORT_ROOT"], os.environ["XIAOZHI_HOME"]):
    if p not in sys.path:
        sys.path.insert(0, p)

from passport_server.patches import apply_all_patches
apply_all_patches()
from core.providers.llm.openai.openai import LLMProvider
from core.providers.tts.openai import TTSProvider

llm_user = os.environ["PROBE_LLM_U"]
llm_pass = os.environ["PROBE_LLM_P"]
tts_user = os.environ["PROBE_TTS_U"]
tts_pass = os.environ["PROBE_TTS_P"]
fake_port = int(os.environ["PROBE_FAKE_PORT"])
unused_port = int(os.environ["PROBE_UNUSED_PORT"])

llm = LLMProvider({"api_key": "probe-llm-key", "base_url": f"http://{llm_user}:{llm_pass}@dashscope.aliyuncs.com/compatible-mode/v1", "model_name": "qwen"})
params = {}
llm._apply_thinking_disabled(params)
assert "extra_body" in params

tts = TTSProvider({"api_key": "probe-tts-key", "api_url": f"http://{tts_user}:{tts_pass}@127.0.0.1:{fake_port}/v1/audio/speech", "model": "m", "voice": "alloy", "format": "wav", "output_dir": "tmp/"}, delete_audio_file=True)
try:
    asyncio.run(tts.text_to_speak("hi", None))
except Exception as exc:
    msg = str(exc)
    assert "status=401" in msg and f"127.0.0.1:{fake_port}" in msg
    assert tts_user not in msg and tts_pass not in msg
else:
    raise AssertionError("Expected 401 exception from TTSProvider")

tts_conn_err = TTSProvider({"api_key": "probe-tts-key", "api_url": f"http://{tts_user}:{tts_pass}@127.0.0.1:{unused_port}/v1/audio/speech", "model": "m", "voice": "alloy", "format": "wav", "output_dir": "tmp/"}, delete_audio_file=True)
try:
    asyncio.run(tts_conn_err.text_to_speak("hi", None))
except Exception as exc:
    msg = str(exc)
    assert f"127.0.0.1:{unused_port}" in msg
    assert tts_user not in msg and tts_pass not in msg
else:
    raise AssertionError("Expected connection exception from TTSProvider")
from loguru import logger
logger.complete()
"""
            probe_res = subprocess.run(
                [sys.executable, "-c", probe_code],
                env=_base_env(
                    XIAOZHI_HOME=str(srv_home_2),
                    PASSPORT_ROOT=str(ROOT),
                    PASSPORT_LOG_DIR=str(srv_home_2 / "tmp"),
                    PROBE_LLM_U=llm_user,
                    PROBE_LLM_P=llm_pass,
                    PROBE_TTS_U=tts_user,
                    PROBE_TTS_P=tts_pass,
                    PROBE_FAKE_PORT=str(fake_port),
                    PROBE_UNUSED_PORT=str(unused_port),
                ),
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert probe_res.returncode == 0, (
                f"LLM/TTS userinfo probe failed: {probe_res.stdout}\n{probe_res.stderr}"
            )
            assert "dashscope.aliyuncs.com" in (probe_res.stdout + probe_res.stderr)
            for forbidden in (llm_user, llm_pass, tts_user, tts_pass):
                assert forbidden not in probe_res.stdout and forbidden not in probe_res.stderr
            assert_logs_redacted(
                [file_log_2],
                forbidden_2,
                required_markers=["dashscope.aliyuncs.com"],
            )
    finally:
        set_fake_control(fake_url, {"reset": True})

    print("[PASS] blocker #3: DEBUG logs, real MCP Vision JWT, ASR/TTS 500 bodies, & URL userinfo verified zero-leak across stdout & server.log")


def main() -> None:
    server_home = Path(
        os.environ.get(
            "XIAOZHI_HOME",
            ROOT / "runtime" / "xiaozhi-esp32-server" / "main" / "xiaozhi-server",
        )
    ).resolve()
    if not (server_home / "app.py").is_file():
        sys.exit(f"Upstream checkout not found at {server_home}; run run_isolated.sh or set XIAOZHI_HOME")

    test_unit_redaction_permissions_and_strict_abort()
    test_concurrent_registry_locking_and_auth_key()
    test_real_mode_refuses_disabled_or_missing_auth(server_home)
    test_real_vs_demo_config_persistence(server_home)
    test_demo_isolation_preserves_real_state(server_home)
    test_demo_pip_controlled_install_isolation(server_home)
    test_proxy_runtime_error_logs_redacted()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        fake_port = _free_port()
        ws_port = _free_port()
        http_port = _free_port()

        srv_home = _make_srv_home(server_home, tmp / "srv_home")
        auth_file = tmp / "auth_key"
        devices_file = tmp / "devices.yaml"
        fake_log = tmp / "fake-provider.log"
        server_stdout_log = tmp / "xiaozhi-server.log"

        dev_a = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "add",
                    "--devices-file",
                    str(devices_file),
                    "--device-id",
                    "AA:BB:CC:DD:EE:01",
                    "--client-id",
                    "passport-reg-client-a",
                    "--name",
                    "reg-device-a",
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        dev_b = json.loads(
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "provision_device.py"),
                    "add",
                    "--devices-file",
                    str(devices_file),
                    "--device-id",
                    "aa:bb:cc:dd:ee:02",
                    "--client-id",
                    "passport-reg-client-b",
                    "--name",
                    "reg-device-b",
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )

        reg_text = devices_file.read_text(encoding="utf-8")
        assert dev_a["ota_secret"] not in reg_text
        assert hash_ota_secret(dev_a["ota_secret"]) in reg_text
        assert stat.S_IMODE(devices_file.stat().st_mode) == 0o600

        env = _base_env(
            XIAOZHI_HOME=str(srv_home),
            PASSPORT_MODE="demo",
            PASSPORT_AUTH_FILE=str(auth_file),
            PASSPORT_DEVICES_FILE=str(devices_file),
            PASSPORT_LOG_DIR=str(srv_home / "tmp"),
            PASSPORT_BIND="127.0.0.1",
            PASSPORT_WS_BIND_PORT=str(ws_port),
            PASSPORT_HTTP_BIND_PORT=str(http_port),
            PASSPORT_PUBLIC_WS=f"ws://127.0.0.1:{ws_port}/xiaozhi/v1/",
            PASSPORT_PUBLIC_HTTP=f"http://127.0.0.1:{http_port}/mcp/vision/explain",
            PASSPORT_FAKE_BASE=f"http://127.0.0.1:{fake_port}",
            PASSPORT_ASR_TIMEOUT="4.0",
            PASSPORT_AUTH_EXPIRE_SECONDS="120",
            PASSPORT_TEST_ALLOWED_DEVICES=dev_a["device_id"],
        )
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write_config.py")],
            env=env,
            check=True,
            capture_output=True,
        )
        auth_key = auth_file.read_text(encoding="utf-8").strip()

        with open(fake_log, "w", encoding="utf-8") as fout:
            fake_proc = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "fake_provider.py"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(fake_port),
                ],
                stdout=fout,
                stderr=subprocess.STDOUT,
            )
        server_proc = None
        try:
            _wait_for_http_ready(f"http://127.0.0.1:{fake_port}/_stats", fake_proc, fake_log)
            test_async_asr_nonblocking_disk_io(server_home, fake_port)

            with open(server_stdout_log, "w", encoding="utf-8") as sout:
                server_proc = subprocess.Popen(
                    [sys.executable, str(ROOT / "passport_server" / "runner.py")],
                    env=env,
                    stdout=sout,
                    stderr=subprocess.STDOUT,
                )
            ota_base = f"http://127.0.0.1:{http_port}"
            ws_url = f"ws://127.0.0.1:{ws_port}/xiaozhi/v1/"
            _wait_for_http_ready(f"{ota_base}/xiaozhi/ota/", server_proc, server_stdout_log)

            test_reverse_proxy_templates_and_forwarding(ota_base, dev_a)

            res = asyncio.run(
                _run_live_server_regressions(
                    ota_base=ota_base,
                    ws_url=ws_url,
                    fake_url=f"http://127.0.0.1:{fake_port}",
                    devices_file=devices_file,
                    auth_key=auth_key,
                    dev_a=dev_a,
                    dev_b=dev_b,
                )
            )
            ttl_secrets = test_real_ttl_expiration(server_home, fake_port)
            res["secrets_to_check"].update(ttl_secrets)
            sigterm_elapsed = _stop_process_gracefully(server_proc, "xiaozhi-server")
            server_proc = None
            print(f"[PASS] SIGTERM graceful shutdown completed in {sigterm_elapsed:.2f}s")

            assert_logs_redacted(
                [server_stdout_log, srv_home / "tmp" / "server.log"],
                res["secrets_to_check"],
                extra_logs=[fake_log],
            )
            test_debug_and_provider_error_log_redaction(server_home, fake_port)
        finally:
            if server_proc is not None:
                _stop_process_gracefully(server_proc, "xiaozhi-server")
            fake_proc.terminate()
            fake_proc.wait(timeout=5)

    print("PASSED ALL PASSPORT REGRESSION CHECKS")


if __name__ == "__main__":
    main()
