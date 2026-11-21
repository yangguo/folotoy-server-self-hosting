#!/usr/bin/env python3
"""Comprehensive regression tests for all 4 blockers and related non-blockers.

Runs against the real xiaozhi-server Python process (via passport_server/runner.py)
and local passport/fake_provider.py. Does not require Docker or real API keys, and
never logs or prints raw experimental tokens/secrets.
"""

import asyncio
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import opuslib_next
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
    validate_abort_metrics,
)
from passport_server.device_auth import PassportDeviceAuth, hash_ota_secret
from passport_server.fs_utils import atomic_write_private
from passport_server.redaction import (
    has_sensitive_query_params,
    redact_text,
    sanitize_headers,
    sanitize_url_or_path,
)


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
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RuntimeError(f"Process exited prematurely ({proc.returncode}):\n{tail}")
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
    raise TimeoutError(f"Timed out waiting for {url}:\n{tail}")


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


def test_unit_redaction_permissions_and_strict_abort() -> None:
    # 1. Redaction helpers
    secret_a = "exp_ota_" + secrets.token_hex(12)
    bearer_tok = "exp_ws_" + secrets.token_urlsafe(18) + ".1700000000"
    query_tok = "exp_q_" + secrets.token_hex(10)

    sample_log = (
        f"GET /xiaozhi/ota/d/{secret_a}/?token={query_tok}&foo=bar "
        f"Authorization: Bearer {bearer_tok} "
        f"{{'device-id': 'aa:bb', 'authorization': 'Bearer {bearer_tok}', 'x-ota-secret': '{secret_a}'}}"
    )
    redacted = redact_text(sample_log)
    for forbidden in (secret_a, bearer_tok, query_tok):
        assert forbidden not in redacted, f"Secret leaked after redact_text: {redacted}"
    assert "[REDACTED]" in redacted

    clean_url = sanitize_url_or_path(f"/xiaozhi/ota/d/{secret_a}/?authorization=Bearer+{bearer_tok}&v=1")
    assert secret_a not in clean_url and bearer_tok not in clean_url
    assert "/xiaozhi/ota/d/[REDACTED]/" in clean_url
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

    # 2. Strict abort assertion MUST fail if server ignores abort and completes 100 frames
    synthetic_unaborted = {
        "aborted": True,
        "tts_states": ["start", "stop"],
        "opus_frame_count": 100,
        "tail_frames_after_abort": 98,
        "frames_after_stop": 0,
        "abort_stop_latency_s": 5.8,
    }
    failures = validate_abort_metrics(synthetic_unaborted)
    assert failures, "validate_abort_metrics must fail when full audio plays to natural stop"

    # 3. Atomic 0600 file creation even under permissive 0022 umask
    with tempfile.TemporaryDirectory() as tmpdir:
        old_umask = os.umask(0o022)
        try:
            priv_path = Path(tmpdir) / "secret_test.yaml"
            atomic_write_private(priv_path, "test: 1\n", mode=0o600)
            assert stat.S_IMODE(priv_path.stat().st_mode) == 0o600
        finally:
            os.umask(old_umask)
    print("[PASS] unit tests: redaction, strict abort gate, atomic 0600 write")


def test_real_vs_demo_config_persistence(server_home: Path) -> None:
    """Blocker #4: real config must not be overwritten by fake providers and must survive restarts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        home_copy = tmp / "server_home"
        (home_copy / "data").mkdir(parents=True)

        # 4a. PASSPORT_MODE=real fails closed when config file does not exist.
        missing_cfg = tmp / "nonexistent.yaml"
        env_missing = {
            **os.environ,
            "XIAOZHI_HOME": str(home_copy),
            "PASSPORT_MODE": "real",
            "PASSPORT_CONFIG_FILE": str(missing_cfg),
            "PASSPORT_AUTH_FILE": str(tmp / "auth_key"),
            "PASSPORT_DEVICES_FILE": str(tmp / "devices.yaml"),
        }
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
        env_real = {
            **os.environ,
            "XIAOZHI_HOME": str(home_copy),
            "PASSPORT_MODE": "real",
            "PASSPORT_CONFIG_FILE": str(real_cfg),
            "PASSPORT_AUTH_FILE": str(auth_file),
            "PASSPORT_DEVICES_FILE": str(devices_file),
            "PASSPORT_FAKE_BASE": "http://127.0.0.1:18019",
        }
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
            capture_output=True,
            text=True,
            check=True,
        )
        loaded_real = json.loads(probe.stdout)
        assert loaded_real["selected"]["ASR"] == "CustomRealASR"
        assert loaded_real["asr_url"] == "https://asr.real.example/v1/audio/transcriptions"

        # 4c. Explicit PASSPORT_MODE=demo uses fake providers.
        env_demo = {
            **os.environ,
            "XIAOZHI_HOME": str(home_copy),
            "PASSPORT_MODE": "demo",
            "PASSPORT_AUTH_FILE": str(auth_file),
            "PASSPORT_DEVICES_FILE": str(devices_file),
            "PASSPORT_FAKE_BASE": "http://127.0.0.1:19999",
        }
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
        e2e_home = tmp / "e2e_real_home"
        (e2e_home / "data").mkdir(parents=True)
        for item in ("app.py", "config", "core", "models", "plugins_func", "config.yaml"):
            src = server_home / item
            if src.exists():
                (e2e_home / item).symlink_to(src)

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
            e2e_env = {
                **{
                    k: v
                    for k, v in os.environ.items()
                    if k
                    not in (
                        "PASSPORT_BIND",
                        "PASSPORT_WS_BIND_PORT",
                        "PASSPORT_HTTP_BIND_PORT",
                        "PASSPORT_PUBLIC_WS",
                        "PASSPORT_PUBLIC_HTTP",
                        "PASSPORT_AUTH_EXPIRE_SECONDS",
                    )
                },
                "XIAOZHI_HOME": str(e2e_home),
                "PASSPORT_MODE": "real",
                "PASSPORT_CONFIG_FILE": str(e2e_real_cfg),
                "PASSPORT_AUTH_FILE": str(e2e_auth),
                "PASSPORT_DEVICES_FILE": str(e2e_devices),
                "PASSPORT_PYTHON": sys.executable,
                "PASSPORT_FAKE_BASE": "http://127.0.0.1:18019",
            }
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
        finally:
            e2e_provider_proc.terminate()
            e2e_provider_proc.wait(timeout=5)
    print("[PASS] blocker #4: real config preserved across entrypoint.sh restarts and separated from demo mode")


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
    # 1a. Unregistered device without/with random secret
    st, body = post_ota(
        ota_base,
        {"Device-Id": "de:ad:be:ef:00:99", "Client-Id": "unregistered-client"},
        secret="random-unregistered-secret",
    )
    assert st in (401, 403) and "websocket" not in body, f"unregistered OTA succeeded: {st} {body}"

    # 1b. Provisioned device A without secret
    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
    )
    assert st == 401 and "websocket" not in body, f"OTA missing secret: {st} {body}"

    # 1c. Provisioned device A with wrong secret
    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
        secret="wrong-secret-" + secrets.token_hex(6),
    )
    assert st == 403 and "websocket" not in body, f"OTA wrong secret: {st} {body}"

    # 1d. Device A secret used while claiming Device B Device-Id
    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_b["device_id"], "Client-Id": dev_b["client_id"]},
        secret=dev_a["ota_secret"],
    )
    assert st == 403 and "websocket" not in body, f"cross-device secret accepted: {st} {body}"

    # 1e. Device A valid secret with wrong Client-Id
    st, body = post_ota(
        ota_base,
        {"Device-Id": dev_a["device_id"], "Client-Id": "spoofed-client-id"},
        secret=dev_a["ota_secret"],
    )
    assert st == 403 and "websocket" not in body, f"wrong client_id accepted: {st} {body}"

    # 1f. Credentials in query string rejected
    st, body = post_json(
        f"{ota_base}/xiaozhi/ota/?secret={query_sentinel_1}",
        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
    )
    assert st == 400 and "websocket" not in body, f"query secret OTA accepted: {st} {body}"

    # 1g. Valid OTA for A and B
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
    # 1h. Device A IS in server.auth.allowed_devices, yet NO token & BAD token MUST be rejected.
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

    # 1i. Unregistered device WS rejected
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

    # 1j. Valid token of A paired with spoofed Device-Id or Client-Id rejected
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

    # 1k. Expired token (crafted with valid key/binding but backdated timestamp)
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

    # 1l. Query credentials on WS URL rejected
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

    # 1m. Vision endpoint hardcoded web_test_client bypass closed
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

    # --- Blocker #3: Slow/hung ASR does not block other sessions + explicit timeout + abort cancel ---
    post_json(
        f"{fake_url}/_control",
        {},
        {"reset": True, "asr_delays": [10.0, 0.0]},
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

        # Wait until fake_provider confirms Session A's ASR HTTP call is actively in flight.
        t_wait_inflight = time.monotonic()
        while time.monotonic() - t_wait_inflight < 5.0:
            stats = _get_json(f"{fake_url}/_stats")
            if stats["asr_in_flight"] >= 1:
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Session A ASR request never reached fake_provider")

        # While Session A's ASR is hung, Session B MUST complete OTA + WS hello + full voice turn quickly.
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
        assert b_elapsed < 4.0, f"Session B was blocked by hung Session A ASR ({b_elapsed:.2f}s)"
        assert "合约测试" in "".join(turn_b["stt"])
        assert turn_b["decoded_pcm_bytes"] > 0 and "stop" in turn_b["tts_states"]

        # Wait for Session A's hung ASR to hit its configured ~2.5s/3.0s timeout (well under 10s).
        t_timeout_wait = time.monotonic()
        while time.monotonic() - t_timeout_wait < 6.0:
            stats = _get_json(f"{fake_url}/_stats")
            if stats["asr_in_flight"] == 0:
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("Session A hung ASR did not time out within 6s")
        timeout_elapsed = time.monotonic() - t_wait_inflight
        assert timeout_elapsed < 6.0, f"ASR timeout took too long: {timeout_elapsed:.2f}s"

        # Session A recovers cleanly on next fast turn
        turn_a_after_timeout = await run_turn(ws_a, sid_a)
        assert "合约测试" in "".join(turn_a_after_timeout["stt"])
        assert "stop" in turn_a_after_timeout["tts_states"]

        # 3b. Abort cancels an in-flight slow ASR request quickly
        post_json(f"{fake_url}/_control", {}, {"asr_delays": [12.0]})
        await ws_a.send(
            json.dumps({"session_id": sid_a, "type": "listen", "state": "start", "mode": "manual"})
        )
        for frame in opus_frames(8):
            await ws_a.send(frame)
        await asyncio.sleep(0.1)
        await ws_a.send(json.dumps({"session_id": sid_a, "type": "listen", "state": "stop"}))

        t_inflight2 = time.monotonic()
        while time.monotonic() - t_inflight2 < 5.0:
            if _get_json(f"{fake_url}/_stats")["asr_in_flight"] >= 1:
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Second slow ASR request never started")

        await ws_a.send(
            json.dumps({"session_id": sid_a, "type": "abort", "reason": "wake_word_detected"})
        )
        msg = json.loads(await asyncio.wait_for(ws_a.recv(), 2.0))
        assert msg.get("type") == "tts" and msg.get("state") == "stop"

        t_cancel = time.monotonic()
        while time.monotonic() - t_cancel < 2.5:
            if _get_json(f"{fake_url}/_stats")["asr_in_flight"] == 0:
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Aborted ASR request remained in flight")

        # Recover again after cancelling slow ASR
        turn_a_after_cancel = await run_turn(ws_a, sid_a)
        assert "合约测试" in "".join(turn_a_after_cancel["stt"])

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
        f"[PASS] blockers #1 & #3: OTA/WS device auth, allowlist bypass closed, "
        f"concurrent Session B ({b_elapsed:.2f}s) unaffected by hung Session A ASR, "
        f"timeout & abort cancel verified"
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
        srv_home = tmp / "srv_home"
        (srv_home / "data").mkdir(parents=True)
        for item in ("app.py", "config", "core", "models", "plugins_func", "config.yaml"):
            src = server_home / item
            if src.exists():
                (srv_home / item).symlink_to(src)

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

        env = {
            **os.environ,
            "XIAOZHI_HOME": str(srv_home),
            "PASSPORT_MODE": "demo",
            "PASSPORT_AUTH_FILE": str(auth_file),
            "PASSPORT_DEVICES_FILE": str(devices_file),
            "PASSPORT_BIND": "127.0.0.1",
            "PASSPORT_WS_BIND_PORT": str(ws_port),
            "PASSPORT_HTTP_BIND_PORT": str(http_port),
            "PASSPORT_PUBLIC_WS": f"ws://127.0.0.1:{ws_port}/xiaozhi/v1/",
            "PASSPORT_PUBLIC_HTTP": f"http://127.0.0.1:{http_port}/mcp/vision/explain",
            "PASSPORT_FAKE_BASE": f"http://127.0.0.1:{fake_port}",
            "PASSPORT_AUTH_EXPIRE_SECONDS": "2",
        }
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
        print("[PASS] blocker #1 natural TTL token expiration rejected")
        return {dev["ota_secret"], token}


def assert_logs_redacted(logs: list[Path], forbidden_literals: set[str]) -> None:
    """Blocker #2: verify neither stdout nor file logs contain raw secrets or unredacted Bearer tokens."""
    combined_parts = []
    for path in logs:
        if path.is_file():
            combined_parts.append(path.read_text(encoding="utf-8", errors="replace"))
    combined = "\n".join(combined_parts)
    assert len(combined) > 100, "Logs unexpectedly empty; cannot verify redaction"
    assert "conn - Headers:" in combined, "Expected INFO connection log line to be present"

    for secret in forbidden_literals:
        if secret and len(secret) >= 6:
            assert secret not in combined, "Secret value leaked into logs!"

    unredacted_bearer = re.findall(r"Bearer\s+(?!\[REDACTED\])([A-Za-z0-9._~+/=-]{6,})", combined)
    assert not unredacted_bearer, f"Found {len(unredacted_bearer)} unredacted Bearer token(s) in logs"

    for match in re.finditer(r"conn - Headers:\s*(\{[^\n]+\})", combined):
        line = match.group(1).lower()
        assert "'authorization':" not in line and '"authorization":' not in line, (
            f"Authorization header present in conn - Headers: {line}"
        )
    print("[PASS] blocker #2: stdout and file logs scrubbed of tokens, OTA secrets, and Authorization headers")


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
    test_real_vs_demo_config_persistence(server_home)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        fake_port = _free_port()
        ws_port = _free_port()
        http_port = _free_port()

        srv_home = tmp / "srv_home"
        (srv_home / "data").mkdir(parents=True)
        for item in ("app.py", "config", "core", "models", "plugins_func", "config.yaml"):
            src = server_home / item
            if src.exists():
                (srv_home / item).symlink_to(src)

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

        # Verify devices.yaml stores SHA-256 hash only and has mode 0600.
        reg_text = devices_file.read_text(encoding="utf-8")
        assert dev_a["ota_secret"] not in reg_text
        assert hash_ota_secret(dev_a["ota_secret"]) in reg_text
        assert stat.S_IMODE(devices_file.stat().st_mode) == 0o600

        env = {
            **os.environ,
            "XIAOZHI_HOME": str(srv_home),
            "PASSPORT_MODE": "demo",
            "PASSPORT_AUTH_FILE": str(auth_file),
            "PASSPORT_DEVICES_FILE": str(devices_file),
            "PASSPORT_BIND": "127.0.0.1",
            "PASSPORT_WS_BIND_PORT": str(ws_port),
            "PASSPORT_HTTP_BIND_PORT": str(http_port),
            "PASSPORT_PUBLIC_WS": f"ws://127.0.0.1:{ws_port}/xiaozhi/v1/",
            "PASSPORT_PUBLIC_HTTP": f"http://127.0.0.1:{http_port}/mcp/vision/explain",
            "PASSPORT_FAKE_BASE": f"http://127.0.0.1:{fake_port}",
            "PASSPORT_ASR_TIMEOUT": "2.5",
            "PASSPORT_AUTH_EXPIRE_SECONDS": "120",
            # Deliberately put device A in allowed_devices to prove bypass is dead!
            "PASSPORT_TEST_ALLOWED_DEVICES": dev_a["device_id"],
        }
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
                [server_stdout_log, srv_home / "tmp" / "server.log", fake_log],
                res["secrets_to_check"],
            )
        finally:
            if server_proc is not None:
                _stop_process_gracefully(server_proc, "xiaozhi-server")
            fake_proc.terminate()
            fake_proc.wait(timeout=5)

    print("PASSED ALL PASSPORT REGRESSION CHECKS")


if __name__ == "__main__":
    main()
