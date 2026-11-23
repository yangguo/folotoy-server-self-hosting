#!/usr/bin/env python3
"""Comprehensive regression tests for all 4 blockers and related non-blockers.

Runs against the real xiaozhi-server Python process (via passport_server/runner.py)
and local passport/fake_provider.py. Does not require Docker or real API keys, and
never logs or prints raw experimental tokens/secrets.
"""

import asyncio
import base64
import errno
import hashlib
import http.client
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import signal
import site
import socket
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.error
import urllib.request
import wave
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

import opuslib_next
from opuslib_next import constants
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
    SENSITIVE_QUERY_KEYS,
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


def _reserve_distinct_ports(count: int) -> list[int]:
    """Reserve `count` pairwise-distinct loopback TCP ports simultaneously before closing."""
    sockets: list[socket.socket] = []
    ports: list[int] = []
    seen: set[int] = set()
    try:
        while len(ports) < count:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
            if port in seen:
                sock.close()
                continue
            seen.add(port)
            sockets.append(sock)
            ports.append(port)
        return ports
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


class _ReservedPortPool:
    """Hold loopback ports simultaneously so dead upstreams and listen ports cannot collide."""

    def __init__(self) -> None:
        self._ports: dict[str, int] = {}
        self._by_port: dict[int, str] = {}
        self._dead_sockets: dict[str, socket.socket] = {}
        self._listen_sockets: dict[str, socket.socket] = {}

    def __enter__(self) -> "_ReservedPortPool":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _record_unique(self, label: str, port: int) -> None:
        assert label not in self._ports, f"Duplicate port label: {label}"
        assert port not in self._by_port, (
            f"Port collision between {label} and {self._by_port[port]} on 127.0.0.1:{port}"
        )
        self._ports[label] = port
        self._by_port[port] = label

    def register_external(self, label: str, port: int) -> int:
        self._record_unique(label, int(port))
        return int(port)

    def _bind_new(self, label: str) -> tuple[socket.socket, int]:
        for _ in range(32):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
            if port not in self._by_port:
                self._record_unique(label, port)
                return sock, port
            sock.close()
        raise RuntimeError(f"Failed to allocate unique loopback port for {label}")

    def reserve_dead(self, label: str) -> int:
        """Bind (without listen) and hold a port for the entire fixture so nothing can bind/listen on it."""
        sock, port = self._bind_new(label)
        self._dead_sockets[label] = sock
        return port

    def reserve_listen(self, label: str) -> int:
        """Bind and hold a listen port until release_listen_ports() immediately before proxy start."""
        sock, port = self._bind_new(label)
        self._listen_sockets[label] = sock
        return port

    def release_listen_ports(self) -> None:
        """Release held listen-port placeholders right before starting the proxy; dead ports stay held."""
        for label in list(self._listen_sockets.keys()):
            sock = self._listen_sockets.pop(label)
            try:
                sock.close()
            except OSError:
                pass

    def assert_dead_ports_unreachable(self, context: str = "") -> None:
        prefix = f"{context}: " if context else ""
        for label, sock in self._dead_sockets.items():
            port = self._ports[label]
            assert sock.fileno() != -1, f"{prefix}dead socket {label} (port {port}) was closed early"
            assert sock.getsockname() == ("127.0.0.1", port), (
                f"{prefix}dead socket {label} moved from {port} to {sock.getsockname()}"
            )
            probe_bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe_bind.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                try:
                    probe_bind.bind(("127.0.0.1", port))
                except OSError as exc:
                    assert exc.errno == errno.EADDRINUSE, (
                        f"{prefix}unexpected errno on probe bind for dead port {label}={port}: {exc}"
                    )
                else:
                    raise AssertionError(
                        f"{prefix}dead port {label}={port} was rebindable during fixture"
                    )
            finally:
                probe_bind.close()

            try:
                conn = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            except OSError as exc:
                assert exc.errno == errno.ECONNREFUSED, (
                    f"{prefix}dead port {label}={port} failed with {exc.errno} instead of ECONNREFUSED"
                )
            else:
                conn.close()
                raise AssertionError(f"{prefix}dead port {label}={port} unexpectedly accepted TCP connection")

    def assert_all_disjoint(self, context: str = "") -> None:
        prefix = f"{context}: " if context else ""
        assert len(self._ports) == len(set(self._ports.values())), (
            f"{prefix}port collision detected in {self._ports}"
        )
        self.assert_dead_ports_unreachable(context)

    def port_map(self) -> dict[str, int]:
        return dict(self._ports)

    def dead_hold_state(self) -> dict[str, bool]:
        return {label: (sock.fileno() != -1) for label, sock in self._dead_sockets.items()}

    def close(self) -> None:
        self.release_listen_ports()
        for label in list(self._dead_sockets.keys()):
            sock = self._dead_sockets.pop(label)
            try:
                sock.close()
            except OSError:
                pass


def _redact_proxy_diag(text: str, forbidden_secrets: set[str]) -> str:
    """Scrub synthetic/live OTA secrets, tokens, and URLs before saving failure diagnostics."""
    out = str(text or "")
    for secret_val in sorted((s for s in forbidden_secrets if s and len(s) >= 6), key=len, reverse=True):
        out = out.replace(secret_val, "[REDACTED]")
    out = re.sub(r"/xiaozhi/ota/d/[^/\s\"'?]+", "/xiaozhi/ota/d/[REDACTED]", out)
    return redact_text(out)


def _save_proxy_failure_diag(
    fixture: str,
    *,
    port_map: dict[str, int],
    dead_hold_state: dict[str, bool],
    last_response: Optional[dict],
    log_files: dict[str, Path],
    extra_logs: Optional[dict[str, str]],
    forbidden_secrets: set[str],
    error: BaseException,
    diag_dir: Optional[Path] = None,
) -> Path:
    """Persist redacted port mappings, last HTTP response, and error logs on proxy fixture failure."""
    safe_last: Optional[dict] = None
    if last_response:
        safe_last = {
            "label": str(last_response.get("label", "")),
            "port": last_response.get("port"),
            "method": str(last_response.get("method", "")),
            "path": _redact_proxy_diag(str(last_response.get("path", "")), forbidden_secrets),
            "status": last_response.get("status"),
            "body_preview": _redact_proxy_diag(
                str(last_response.get("body_preview", ""))[:512], forbidden_secrets
            ),
        }

    redacted_logs: dict[str, str] = {}
    for name, log_path in log_files.items():
        if log_path.is_file():
            raw = log_path.read_text(encoding="utf-8", errors="replace")
            if raw:
                redacted_logs[name] = _redact_proxy_diag(raw[-4000:], forbidden_secrets)
    for name, raw_text in (extra_logs or {}).items():
        if raw_text:
            redacted_logs[name] = _redact_proxy_diag(raw_text[-4000:], forbidden_secrets)

    payload = {
        "fixture": fixture,
        "error_type": type(error).__name__,
        "error": _redact_proxy_diag(str(error), forbidden_secrets),
        "ports": port_map,
        "dead_ports_held": dead_hold_state,
        "last_response": safe_last,
        "error_logs": redacted_logs,
    }
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)
    for secret_val in forbidden_secrets:
        if secret_val and len(secret_val) >= 6:
            assert secret_val not in serialized, "Proxy diagnostic redaction failed on secret literal"
    assert "/xiaozhi/ota/d/" not in serialized.replace("/xiaozhi/ota/d/[REDACTED]", ""), (
        "Proxy diagnostic redaction left raw /xiaozhi/ota/d/ path"
    )
    target_dir = diag_dir or Path(tempfile.gettempdir())
    out_path = target_dir / f"passport-{fixture}-failure-{os.getpid()}-{int(time.time())}.json"
    atomic_write_private(out_path, serialized, mode=0o600)
    return out_path


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


def _snapshot_file_meta(paths: list[Path]) -> dict[Path, Optional[tuple[bytes, int, int, int]]]:
    """Snapshot file bytes, inode, link count, and mode for sentinel verification."""
    snap: dict[Path, Optional[tuple[bytes, int, int, int]]] = {}
    for p in paths:
        if p.exists() or p.is_symlink():
            st = p.lstat()
            data = p.read_bytes() if stat.S_ISREG(st.st_mode) else b""
            snap[p] = (data, st.st_ino, st.st_nlink, stat.S_IMODE(st.st_mode))
        else:
            snap[p] = None
    return snap


def _assert_file_meta_unchanged(
    before: dict[Path, Optional[tuple[bytes, int, int, int]]],
    context: str,
    *,
    expected_nlink: Optional[dict[Path, int]] = None,
) -> None:
    for path, prev in before.items():
        if prev is None:
            assert not path.exists() and not path.is_symlink(), f"{context}: {path} unexpectedly created"
            continue
        assert path.exists() or path.is_symlink(), f"{context}: sentinel {path} disappeared"
        st = path.lstat()
        cur_bytes = path.read_bytes() if stat.S_ISREG(st.st_mode) else b""
        prev_bytes, prev_ino, _prev_nlink, prev_mode = prev
        assert cur_bytes == prev_bytes, f"{context}: {path} bytes changed"
        assert st.st_ino == prev_ino, f"{context}: {path} inode changed ({prev_ino} -> {st.st_ino})"
        assert stat.S_IMODE(st.st_mode) == prev_mode, (
            f"{context}: {path} mode changed ({oct(prev_mode)} -> {oct(stat.S_IMODE(st.st_mode))})"
        )
        if expected_nlink and path in expected_nlink:
            assert st.st_nlink == expected_nlink[path], (
                f"{context}: {path} nlink={st.st_nlink}, expected {expected_nlink[path]}"
            )


def _start_counting_upstream():
    """Start a loopback HTTP upstream recording every forwarded request hit and returning 200."""
    hits: list[dict] = []
    hit_lock = threading.Lock()

    class _CountingHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b""
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            with hit_lock:
                hits.append(
                    {
                        "method": method,
                        "path": self.path,
                        "headers": hdrs,
                        "body": body,
                    }
                )
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, int(srv.server_address[1]), hits, hit_lock


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


def test_port_fixture_mutual_exclusion_and_diag_redaction() -> None:
    """Verify _ReservedPortPool enforces non-overlapping ports, holds dead ports, and redacts failure diagnostics."""
    live_srv, live_port, _, _ = _start_counting_upstream()
    try:
        with _ReservedPortPool() as pool:
            pool.register_external("counting_live", live_port)
            dead_port = pool.reserve_dead("dead_upstream")
            listen_ports = [pool.reserve_listen(f"listen_{idx}") for idx in range(40)]
            all_ports = [live_port, dead_port, *listen_ports]
            assert len(all_ports) == len(set(all_ports)) == 42
            pool.assert_all_disjoint("unit_pool_all_held")

            pool.release_listen_ports()
            pool.assert_dead_ports_unreachable("unit_pool_after_release_listen")

            syn_secret = "diag_ota_" + secrets.token_hex(12)
            syn_q = "diag_q_" + secrets.token_hex(10)
            syn_tok = "diag_bearer_" + secrets.token_hex(10)
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                err_file = tmp / "dead_err.log"
                err_file.write_text(
                    f'connect() failed upstream: "http://127.0.0.1:{dead_port}/xiaozhi/ota/d/{syn_secret}/", '
                    f'referrer: "https://passport.example/?token={syn_q}"\n',
                    encoding="utf-8",
                )
                diag_path = _save_proxy_failure_diag(
                    "unit-test",
                    port_map=pool.port_map(),
                    dead_hold_state=pool.dead_hold_state(),
                    last_response={
                        "label": "p_dead",
                        "port": dead_port,
                        "method": "POST",
                        "path": f"/xiaozhi/ota/d/{syn_secret}/?token={syn_q}",
                        "status": 502,
                        "body_preview": f"Authorization: Bearer {syn_tok}",
                    },
                    log_files={"dead_error": err_file},
                    extra_logs={"stderr": f"Bearer {syn_tok}"},
                    forbidden_secrets={syn_secret, syn_q, syn_tok},
                    error=RuntimeError(f"failed hitting /xiaozhi/ota/d/{syn_secret}/"),
                    diag_dir=tmp,
                )
                assert stat.S_IMODE(diag_path.stat().st_mode) == 0o600
                diag_raw = diag_path.read_text(encoding="utf-8")
                diag_obj = json.loads(diag_raw)
                assert diag_obj["dead_ports_held"] == {"dead_upstream": True}
                assert diag_obj["ports"]["dead_upstream"] == dead_port
                assert diag_obj["last_response"]["status"] == 502
                assert "dead_error" in diag_obj["error_logs"]
                for secret_val in (syn_secret, syn_q, syn_tok):
                    assert secret_val not in diag_raw
                assert f"/xiaozhi/ota/d/{syn_secret}" not in diag_raw
                assert "/xiaozhi/ota/d/[REDACTED]" in diag_raw
    finally:
        live_srv.shutdown()
        live_srv.server_close()

    print("[PASS] unit tests: port fixture mutual exclusion, held dead port, and redacted failure diagnostics")


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

        # 4. Sidecar lock safety: preserve single regular inode for concurrent flock,
        #    and refuse hard-linked or symlinked lock files without altering target permissions/bytes/inode.
        dev_lock = devices_file.parent / f".{devices_file.name}.lock"
        dev_lock_stat = dev_lock.lstat()
        assert stat.S_ISREG(dev_lock_stat.st_mode) and not stat.S_ISLNK(dev_lock_stat.st_mode)
        assert dev_lock_stat.st_nlink == 1
        assert stat.S_IMODE(dev_lock_stat.st_mode) == 0o600
        with locked_file(devices_file):
            assert dev_lock.lstat().st_ino == dev_lock_stat.st_ino, (
                "locked_file must preserve the sidecar lock inode for cross-process flock"
            )

        # 4a. Hard-linked .devices.yaml.lock -> external 0640 sentinel must be refused without fchmod(0600).
        sentinel_hl = tmp / "external-sentinel-hl.txt"
        sentinel_hl.write_text("LOCK_SENTINEL\n", encoding="utf-8")
        os.chmod(sentinel_hl, 0o640)
        dev_lock.unlink()
        os.link(sentinel_hl, dev_lock)
        assert dev_lock.lstat().st_nlink == 2
        snap_hl = _snapshot_file_meta([sentinel_hl])
        try:
            with locked_file(devices_file):
                raise AssertionError("locked_file must refuse multi-hard-link sidecar lock")
        except PermissionError:
            pass
        bad_cli = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "provision_device.py"),
                "add",
                "--devices-file",
                str(devices_file),
                "--device-id",
                "aa:bb:cc:dd:ee:77",
                "--client-id",
                "bad-lock-client",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        assert bad_cli.returncode != 0, "provision_device.py must fail when sidecar lock has nlink > 1"
        _assert_file_meta_unchanged(
            snap_hl, "hard-linked .devices.yaml.lock refusal", expected_nlink={sentinel_hl: 2}
        )

        # 4b. Hard-linked .auth_key.lock -> external 0640 sentinel must be refused by write_config.py.
        guarded_auth = tmp / "guarded_auth_key"
        guarded_auth_lock = tmp / ".guarded_auth_key.lock"
        sentinel_auth_hl = tmp / "external-auth-sentinel.txt"
        sentinel_auth_hl.write_text("AUTH_LOCK_SENTINEL\n", encoding="utf-8")
        os.chmod(sentinel_auth_hl, 0o640)
        os.link(sentinel_auth_hl, guarded_auth_lock)
        snap_auth_hl = _snapshot_file_meta([sentinel_auth_hl])
        guarded_home = tmp / "guarded_home"
        (guarded_home / "data").mkdir(parents=True)
        bad_wc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write_config.py")],
            env=_base_env(
                XIAOZHI_HOME=str(guarded_home),
                PASSPORT_MODE="demo",
                PASSPORT_AUTH_FILE=str(guarded_auth),
                PASSPORT_DEVICES_FILE=str(tmp / "guarded_devices.yaml"),
            ),
            capture_output=True,
            text=True,
        )
        assert bad_wc.returncode != 0, "write_config.py must fail when .auth_key.lock has nlink > 1"
        assert not guarded_auth.exists(), "write_config.py created auth_key despite rejected lock"
        _assert_file_meta_unchanged(
            snap_auth_hl, "hard-linked .auth_key.lock refusal", expected_nlink={sentinel_auth_hl: 2}
        )

        # 4c. Symlinked .devices.yaml.lock -> external 0640 sentinel must be refused via O_NOFOLLOW.
        sym_dir = tmp / "sym_lock_dir"
        sym_dir.mkdir(parents=True)
        sym_dev = sym_dir / "devices.yaml"
        sym_sentinel = tmp / "external-sentinel-sym.txt"
        sym_sentinel.write_text("SYM_LOCK_SENTINEL\n", encoding="utf-8")
        os.chmod(sym_sentinel, 0o640)
        (sym_dir / ".devices.yaml.lock").symlink_to(sym_sentinel)
        snap_sym = _snapshot_file_meta([sym_sentinel])
        try:
            with locked_file(sym_dev):
                raise AssertionError("locked_file must refuse symlinked sidecar lock")
        except OSError:
            pass
        _assert_file_meta_unchanged(
            snap_sym, "symlinked .devices.yaml.lock refusal", expected_nlink={sym_sentinel: 1}
        )

        # 4d. Dangling symlink .devices.yaml.lock must be refused without creating its target.
        dangling_dir = tmp / "dangling_lock_dir"
        dangling_dir.mkdir(parents=True)
        dangling_target = tmp / "dangling-must-not-exist.txt"
        (dangling_dir / ".devices.yaml.lock").symlink_to(dangling_target)
        try:
            with locked_file(dangling_dir / "devices.yaml"):
                raise AssertionError("locked_file must refuse dangling symlinked sidecar lock")
        except OSError:
            pass
        assert not dangling_target.exists(), "locked_file created target of dangling symlink"
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
            ws_p, http_p = _reserve_distinct_ports(2)
            server_block = {
                "ip": "127.0.0.1",
                "port": ws_p,
                "http_port": http_p,
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
        e2e_provider_port, e2e_ws_port, e2e_http_port = _reserve_distinct_ports(3)
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


def _upstream_checkout_root(server_home: Path) -> Path:
    """Resolve the pinned xiaozhi-esp32-server checkout root from server_home."""
    resolved = server_home.resolve()
    if len(resolved.parents) >= 2:
        cand = resolved.parents[1]
        if (cand / ".git").exists() and (cand / "main" / "xiaozhi-server").resolve() == resolved:
            return cand
    fallback = ROOT / "runtime" / "xiaozhi-esp32-server"
    if (fallback / ".git").exists():
        return fallback
    raise AssertionError(f"Cannot locate upstream git checkout root from server_home={server_home}")


def _current_interpreter_site_dirs() -> list[Path]:
    """Return deduplicated site-packages directories of the currently running Python interpreter."""
    candidates: list[str] = list(sys.path)
    if hasattr(site, "getsitepackages"):
        try:
            candidates.extend(site.getsitepackages())
        except Exception:
            pass
    sys_paths = sysconfig.get_paths()
    for key in ("purelib", "platlib"):
        if sys_paths.get(key):
            candidates.append(sys_paths[key])
    for mod in (yaml, websockets):
        mod_file = getattr(mod, "__file__", None)
        if mod_file:
            candidates.append(str(Path(mod_file).resolve().parent.parent))
    dirs: list[Path] = []
    seen: set[Path] = set()
    for raw in candidates:
        if not raw:
            continue
        p = Path(raw).resolve()
        if not p.is_dir() or p in seen:
            continue
        if p.name in ("site-packages", "dist-packages") or (p / "yaml").exists() or (p / "websockets").exists():
            seen.add(p)
            dirs.append(p)
    assert dirs, f"Failed to locate any site-packages directory for {sys.executable}"
    return dirs


def _create_simulated_shared_venv(venv_dir: Path, dep_site_dirs: list[Path]) -> Path:
    """Create a writable venv in tmpdir exposing current test dependencies read-only via .pth."""
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
        check=True,
        capture_output=True,
    )
    purelib = Path(
        subprocess.check_output(
            [str(venv_dir / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
            text=True,
        ).strip()
    ).resolve()
    pth_lines = "".join(f"import site; site.addsitedir({str(d)!r})\n" for d in dep_site_dirs)
    (purelib / "zz_test_deps_readonly.pth").write_text(pth_lines, encoding="utf-8")
    return purelib


def test_demo_isolation_preserves_real_state(server_home: Path) -> None:
    """Blocker #1: run_isolated.sh & demo Compose MUST NOT delete or alter real devices.yaml / auth_key / config."""
    real_files = [
        ROOT / "runtime" / "devices.yaml",
        ROOT / "runtime" / "auth_key",
        server_home / "data" / ".config.yaml",
        ROOT / "config" / "server.config.yaml",
    ]
    real_before = _snapshot_files(real_files)
    upstream_checkout = _upstream_checkout_root(server_home)
    dep_site_dirs = _current_interpreter_site_dirs()

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
        sim_shared_venv = copy_runtime / "venv"
        _create_simulated_shared_venv(sim_shared_venv, dep_site_dirs)
        sim_shared_before = _tree_signature(sim_shared_venv)
        (copy_runtime / "xiaozhi-esp32-server").symlink_to(upstream_checkout)

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
        real_pth_sentinel = copy_runtime / "real-pth-sentinel.txt"
        real_dev_lock_sentinel = copy_runtime / "real-dev-lock-sentinel.txt"
        real_auth_lock_sentinel = copy_runtime / "real-auth-lock-sentinel.txt"
        for real_path in (
            real_srv_log,
            real_cfg_yaml,
            real_fake_log,
            real_pth_sentinel,
            real_dev_lock_sentinel,
            real_auth_lock_sentinel,
        ):
            real_path.write_text(f"real-state-{real_path.name}\n", encoding="utf-8")
        os.chmod(real_dev_lock_sentinel, 0o640)
        os.chmod(real_auth_lock_sentinel, 0o640)
        real_pth_ino = os.stat(real_pth_sentinel).st_ino
        symlinked_outputs = {
            demo_root / "xiaozhi-server.log": copy_devices,
            demo_root / "auth_key": copy_auth,
            demo_root / "devices.yaml": copy_devices,
            demo_root / "xiaozhi-home" / "tmp" / "server.log": real_srv_log,
            demo_root / "xiaozhi-home" / "data" / ".config.yaml": real_cfg_yaml,
            demo_root / ".auth_key.lock": real_auth_lock_sentinel,
        }
        for link_path, target in symlinked_outputs.items():
            link_path.symlink_to(target)
        hardlinked_output = demo_root / "fake-provider.log"
        os.link(real_fake_log, hardlinked_output)
        hardlinked_dev_lock = demo_root / ".devices.yaml.lock"
        os.link(real_dev_lock_sentinel, hardlinked_dev_lock)
        assert os.lstat(real_dev_lock_sentinel).st_nlink == 2
        linked_before = _snapshot_files([real_srv_log, real_cfg_yaml, real_fake_log, real_pth_sentinel])
        lock_sentinels_before = _snapshot_file_meta([real_dev_lock_sentinel, real_auth_lock_sentinel])
        copy_entries_before = sorted(p.name for p in copy_runtime.iterdir())
        real_entries_before = sorted(p.name for p in (ROOT / "runtime").iterdir()) if (ROOT / "runtime").is_dir() else None
        shared_venv_before = _tree_signature(ROOT / "runtime" / "venv") if (ROOT / "runtime" / "venv").exists() else None
        # Synthetic stand-in for an operator's real signing key left in the env.
        synthetic_real_key = secrets.token_hex(32)

        # Exercise default $ROOT/runtime-demo by leaving PASSPORT_DEMO_RUNTIME unset.
        # pip runs (offline "already satisfied" via the read-only shared venv) so
        # the test proves dependency installation never writes the shared venv.
        demo_ws_p, demo_http_p, demo_fake_p = _reserve_distinct_ports(3)
        demo_res = subprocess.run(
            ["sh", str(passport_copy / "scripts" / "run_isolated.sh")],
            env=_base_env(
                PASSPORT_SKIP_REGRESSION="1",
                PASSPORT_PYTHON=sys.executable,
                PASSPORT_AUTH_KEY=synthetic_real_key,
                PASSPORT_WS_BIND_PORT=str(demo_ws_p),
                PASSPORT_HTTP_BIND_PORT=str(demo_http_p),
                PASSPORT_FAKE_PORT=str(demo_fake_p),
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
        _assert_file_meta_unchanged(
            lock_sentinels_before,
            "first run_isolated.sh sidecar lock sentinels",
            expected_nlink={real_dev_lock_sentinel: 1, real_auth_lock_sentinel: 1},
        )
        for link_path in list(symlinked_outputs) + [hardlinked_output, hardlinked_dev_lock]:
            assert link_path.is_file() and not link_path.is_symlink(), (
                f"demo output {link_path} still a link after run_isolated.sh"
            )
        assert os.stat(hardlinked_output).st_ino != os.stat(real_fake_log).st_ino, (
            "demo fake-provider.log still hard-linked to a real file"
        )
        for lock_p, sent_p in (
            (demo_root / ".devices.yaml.lock", real_dev_lock_sentinel),
            (demo_root / ".auth_key.lock", real_auth_lock_sentinel),
        ):
            lst = lock_p.lstat()
            assert stat.S_ISREG(lst.st_mode) and not stat.S_ISLNK(lst.st_mode)
            assert lst.st_nlink == 1 and stat.S_IMODE(lst.st_mode) == 0o600
            assert lst.st_ino != sent_p.lstat().st_ino
        assert sorted(p.name for p in copy_runtime.iterdir()) == copy_entries_before, (
            "run_isolated.sh created/removed entries in the copy's real runtime/"
        )
        assert _tree_signature(sim_shared_venv) == sim_shared_before, (
            "run_isolated.sh dependency install modified the simulated shared runtime/venv"
        )
        if real_entries_before is not None:
            assert sorted(p.name for p in (ROOT / "runtime").iterdir()) == real_entries_before, (
                "run_isolated.sh created/removed entries in real passport/runtime/"
            )
        else:
            assert not (ROOT / "runtime").exists(), "run_isolated.sh created real passport/runtime/"
        if shared_venv_before is not None:
            assert _tree_signature(ROOT / "runtime" / "venv") == shared_venv_before, (
                "run_isolated.sh dependency install modified the shared runtime/venv"
            )
        else:
            assert not (ROOT / "runtime" / "venv").exists(), (
                "run_isolated.sh created real passport/runtime/venv"
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

        # Reused demo venv + same-version shared runtime/venv branch:
        # if zz_passport_shared_readonly.pth is hard-linked to a real sentinel file,
        # refreshing it must atomically replace the entry without altering sentinel bytes or inode.
        # Also swap sidecar lock links (.auth_key.lock hard-linked, .devices.yaml.lock symlinked).
        demo_purelib = Path(
            subprocess.check_output(
                [str(demo_venv / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
                text=True,
            ).strip()
        ).resolve()
        demo_pth = demo_purelib / "zz_passport_shared_readonly.pth"
        assert demo_pth.is_file() and not demo_pth.is_symlink(), (
            f"expected {demo_pth} after initial shared-venv demo run"
        )
        demo_pth.unlink()
        os.link(real_pth_sentinel, demo_pth)
        assert os.stat(demo_pth).st_ino == real_pth_ino
        assert os.stat(real_pth_sentinel).st_nlink == 2
        (demo_root / ".auth_key.lock").unlink()
        os.link(real_auth_lock_sentinel, demo_root / ".auth_key.lock")
        assert os.lstat(real_auth_lock_sentinel).st_nlink == 2
        (demo_root / ".devices.yaml.lock").unlink()
        (demo_root / ".devices.yaml.lock").symlink_to(real_dev_lock_sentinel)

        reuse_ws_p, reuse_http_p, reuse_fake_p = _reserve_distinct_ports(3)
        reuse_res = subprocess.run(
            ["sh", str(passport_copy / "scripts" / "run_isolated.sh")],
            env=_base_env(
                PASSPORT_SKIP_REGRESSION="1",
                PASSPORT_PYTHON=sys.executable,
                PASSPORT_AUTH_KEY=synthetic_real_key,
                PASSPORT_WS_BIND_PORT=str(reuse_ws_p),
                PASSPORT_HTTP_BIND_PORT=str(reuse_http_p),
                PASSPORT_FAKE_PORT=str(reuse_fake_p),
            ),
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert reuse_res.returncode == 0, (
            f"reused-venv run_isolated.sh failed ({reuse_res.returncode}):\n"
            f"{redact_text(reuse_res.stdout)}\n{redact_text(reuse_res.stderr)}"
        )
        assert "PASSED tightened upstream websocket contract with local fake providers" in reuse_res.stdout
        assert synthetic_real_key not in reuse_res.stdout + reuse_res.stderr
        _assert_files_unchanged(linked_before, "reused-venv hard-linked pth sentinel")
        _assert_file_meta_unchanged(
            lock_sentinels_before,
            "reused-venv sidecar lock sentinels",
            expected_nlink={real_dev_lock_sentinel: 1, real_auth_lock_sentinel: 1},
        )
        for lock_p, sent_p in (
            (demo_root / ".devices.yaml.lock", real_dev_lock_sentinel),
            (demo_root / ".auth_key.lock", real_auth_lock_sentinel),
        ):
            lst = lock_p.lstat()
            assert stat.S_ISREG(lst.st_mode) and not stat.S_ISLNK(lst.st_mode)
            assert lst.st_nlink == 1 and stat.S_IMODE(lst.st_mode) == 0o600
            assert lst.st_ino != sent_p.lstat().st_ino
        _assert_files_unchanged(copy_before, "reused-venv isolated copy runtime/")
        _assert_files_unchanged(real_before, "reused-venv real passport/runtime/")
        pth_sentinel_stat = os.stat(real_pth_sentinel)
        assert pth_sentinel_stat.st_ino == real_pth_ino, (
            "reused-venv run_isolated.sh altered real-pth-sentinel inode"
        )
        assert pth_sentinel_stat.st_nlink == 1, (
            f"zz_passport_shared_readonly.pth still shares a hard link with sentinel (nlink={pth_sentinel_stat.st_nlink})"
        )
        assert demo_pth.is_file() and not demo_pth.is_symlink(), (
            "zz_passport_shared_readonly.pth missing or symlink after reused-venv run"
        )
        assert os.stat(demo_pth).st_ino != real_pth_ino, (
            "zz_passport_shared_readonly.pth still shares inode with real-pth-sentinel"
        )
        assert "site.addsitedir(" in demo_pth.read_text(encoding="utf-8")
        assert _tree_signature(sim_shared_venv) == sim_shared_before, (
            "reused-venv run_isolated.sh modified simulated shared runtime/venv"
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
    real_venv_dir = ROOT / "runtime" / "venv"
    real_venv_before = _tree_signature(real_venv_dir) if real_venv_dir.exists() else None
    upstream_checkout = _upstream_checkout_root(server_home)
    dep_site_dirs = _current_interpreter_site_dirs()

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
        (copy_runtime / "xiaozhi-esp32-server").symlink_to(upstream_checkout)

        sim_shared_venv = copy_runtime / "venv"
        sim_shared_site = _create_simulated_shared_venv(sim_shared_venv, dep_site_dirs)
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
        demo_site_pre = Path(
            subprocess.check_output(
                [str(demo_venv / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
                text=True,
            ).strip()
        ).resolve()
        pip_pth_sentinel = copy_runtime / "real-pip-pth-sentinel.txt"
        pip_pth_sentinel_bytes = f"pip-pth-sentinel-{secrets.token_hex(8)}\n".encode("utf-8")
        pip_pth_sentinel.write_bytes(pip_pth_sentinel_bytes)
        pip_pth_sentinel_ino = os.stat(pip_pth_sentinel).st_ino
        demo_pth_pre = demo_site_pre / "zz_passport_shared_readonly.pth"
        if demo_pth_pre.exists() or demo_pth_pre.is_symlink():
            demo_pth_pre.unlink()
        os.link(pip_pth_sentinel, demo_pth_pre)
        assert os.stat(demo_pth_pre).st_ino == pip_pth_sentinel_ino
        assert os.stat(pip_pth_sentinel).st_nlink == 2
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
                PASSPORT_WS_BIND_PORT=str((pip_ports := _reserve_distinct_ports(3))[0]),
                PASSPORT_HTTP_BIND_PORT=str(pip_ports[1]),
                PASSPORT_FAKE_PORT=str(pip_ports[2]),
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
        assert pip_pth_sentinel.read_bytes() == pip_pth_sentinel_bytes, (
            "run_isolated.sh altered hard-linked .pth sentinel bytes before pip preflight"
        )
        pip_sentinel_stat = os.stat(pip_pth_sentinel)
        assert pip_sentinel_stat.st_ino == pip_pth_sentinel_ino
        assert pip_sentinel_stat.st_nlink == 1
        assert os.stat(demo_site / "zz_passport_shared_readonly.pth").st_ino != pip_pth_sentinel_ino
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
        if real_venv_before is not None:
            assert _tree_signature(real_venv_dir) == real_venv_before, (
                "demo pip install modified real passport/runtime/venv"
            )
        else:
            assert not real_venv_dir.exists(), "demo pip install created real passport/runtime/venv"

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

        # Fresh entry without shared runtime/venv: run_isolated.sh creates runtime-demo/venv via $PY_BIN,
        # omits zz_passport_shared_readonly.pth, and installs into runtime-demo/venv only.
        fresh_marker = "fresh_probe_" + secrets.token_hex(8)
        fresh_wheel_path = _build_local_test_wheel(tmp, "passport_demo_probe_fresh", "0.1.0", fresh_marker)
        passport_copy_fresh = tmp / "passport_copy_fresh"
        passport_copy_fresh.mkdir(parents=True)
        for subdir in ("config", "passport_server", "scripts"):
            shutil.copytree(ROOT / subdir, passport_copy_fresh / subdir, ignore=ignore)
        shutil.copy2(ROOT / "fake_provider.py", passport_copy_fresh / "fake_provider.py")
        (passport_copy_fresh / "requirements-runtime.txt").write_text(
            req_text + f"\n{fresh_wheel_path}\n", encoding="utf-8"
        )
        fresh_runtime = passport_copy_fresh / "runtime"
        fresh_runtime.mkdir(parents=True)
        (fresh_runtime / "xiaozhi-esp32-server").symlink_to(upstream_checkout)
        assert not (fresh_runtime / "venv").exists()
        assert not (passport_copy_fresh / "runtime-demo").exists()

        fresh_decoy_target = tmp / "fresh_decoy_target"
        fresh_decoy_target.mkdir(parents=True)
        fresh_cfg_body = f"[install]\ntarget = {fresh_decoy_target}\n"
        fresh_home = tmp / "fresh_home"
        fresh_xdg = tmp / "fresh_xdg"
        for cfg_path in (
            fresh_home / ".config" / "pip" / "pip.conf",
            fresh_home / ".pip" / "pip.conf",
            fresh_xdg / "pip" / "pip.conf",
            tmp / "fresh_hostile_pip.conf",
        ):
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            cfg_path.write_text(fresh_cfg_body, encoding="utf-8")

        fresh_res = subprocess.run(
            ["sh", str(passport_copy_fresh / "scripts" / "run_isolated.sh")],
            env=_base_env(
                PASSPORT_SKIP_PIP="0",
                PASSPORT_SKIP_REGRESSION="1",
                PASSPORT_PYTHON=sys.executable,
                PYTHONPATH=os.pathsep.join(str(p) for p in dep_site_dirs),
                HOME=str(fresh_home),
                XDG_CONFIG_HOME=str(fresh_xdg),
                PIP_CONFIG_FILE=str(tmp / "fresh_hostile_pip.conf"),
                PIP_TARGET=str(fresh_decoy_target),
                PIP_PREFIX=str(fresh_decoy_target),
                PIP_ROOT=str(fresh_decoy_target),
                PIP_USER="1",
                PIP_PYTHON=sys.executable,
                PASSPORT_WS_BIND_PORT=str((fresh_ports := _reserve_distinct_ports(3))[0]),
                PASSPORT_HTTP_BIND_PORT=str(fresh_ports[1]),
                PASSPORT_FAKE_PORT=str(fresh_ports[2]),
            ),
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert fresh_res.returncode == 0, (
            f"fresh missing-shared-venv run_isolated.sh failed ({fresh_res.returncode}):\n"
            f"{redact_text(fresh_res.stdout)}\n{redact_text(fresh_res.stderr)}"
        )
        assert "PASSED tightened upstream websocket contract with local fake providers" in fresh_res.stdout
        assert not (fresh_runtime / "venv").exists(), (
            "fresh missing-shared-venv run_isolated.sh unexpectedly created runtime/venv"
        )

        fresh_demo_venv = (passport_copy_fresh / "runtime-demo" / "venv").resolve()
        assert (fresh_demo_venv / "bin" / "python").is_file()
        fresh_demo_site = Path(
            subprocess.check_output(
                [str(fresh_demo_venv / "bin" / "python"), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
                text=True,
            ).strip()
        ).resolve()
        assert fresh_demo_venv in fresh_demo_site.parents
        assert not (fresh_demo_site / "zz_passport_shared_readonly.pth").exists(), (
            "fresh demo venv without shared runtime/venv should not write zz_passport_shared_readonly.pth"
        )
        fresh_init = fresh_demo_site / "passport_demo_probe_fresh" / "__init__.py"
        fresh_meta = fresh_demo_site / "passport_demo_probe_fresh-0.1.0.dist-info" / "METADATA"
        assert fresh_init.is_file() and fresh_meta.is_file(), (
            f"expected fresh demo probe package inside {fresh_demo_site}"
        )
        assert fresh_marker in fresh_init.read_text(encoding="utf-8")

        clean_imp_env = _base_env()
        clean_imp_env.pop("PYTHONPATH", None)
        fresh_imp = subprocess.run(
            [
                str(fresh_demo_venv / "bin" / "python"),
                "-c",
                (
                    "import pathlib, passport_demo_probe_fresh; "
                    f"p = pathlib.Path(passport_demo_probe_fresh.__file__).resolve(); "
                    f"assert pathlib.Path({str(fresh_demo_venv)!r}) in p.parents, p; "
                    f"assert passport_demo_probe_fresh.MARKER == {fresh_marker!r}"
                ),
            ],
            env=clean_imp_env,
            capture_output=True,
            text=True,
        )
        assert fresh_imp.returncode == 0, f"fresh demo package import check failed: {fresh_imp.stderr}"
        assert list(fresh_decoy_target.iterdir()) == [], (
            f"fresh demo pip diverted writes into decoy target: {list(fresh_decoy_target.iterdir())}"
        )
        for dep_dir in dep_site_dirs:
            assert not (dep_dir / "passport_demo_probe_fresh").exists(), (
                f"fresh demo pip wrote package into interpreter site dir: {dep_dir}"
            )
        if real_venv_before is not None:
            assert _tree_signature(real_venv_dir) == real_venv_before, (
                "fresh demo pip modified real passport/runtime/venv"
            )
        else:
            assert not real_venv_dir.exists()

        _assert_files_unchanged(real_before, "post-controlled-pip real passport/runtime/")
    print("[PASS] round-3 blocker #2: controlled demo pip (with & without shared runtime/venv) wrote test packages into demo venv only; shared venv untouched")


def _host_caddy_state_paths() -> list[Path]:
    """Return host Caddy config/data/cache paths that isolated Caddy tests must never create or modify."""
    candidates: list[Path] = [
        Path.home() / ".config" / "caddy",
        Path.home() / ".local" / "share" / "caddy",
        Path.home() / ".cache" / "caddy",
    ]
    for env_key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            candidates.append(Path(raw) / "caddy")
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve(strict=False)
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(path)
    return deduped


def _snapshot_host_caddy_state() -> dict[Path, tuple[bool, Optional[dict[str, tuple[int, int]]]]]:
    snap: dict[Path, tuple[bool, Optional[dict[str, tuple[int, int]]]]] = {}
    for p in _host_caddy_state_paths():
        snap[p] = (p.exists(), _tree_signature(p) if p.is_dir() else None)
    return snap


def _assert_host_caddy_state_unchanged(
    before: dict[Path, tuple[bool, Optional[dict[str, tuple[int, int]]]]],
    context: str,
) -> None:
    for path, (existed_before, sig_before) in before.items():
        if not existed_before:
            assert not path.exists(), f"{context}: host Caddy path unexpectedly created: {path}"
        else:
            assert path.exists(), f"{context}: host Caddy path disappeared: {path}"
            if sig_before is not None:
                assert _tree_signature(path) == sig_before, (
                    f"{context}: host Caddy persistent state modified: {path}"
                )


def _prepare_real_caddy_fixture(
    caddy_text: str,
    work_dir: Path,
    *,
    live_port: int,
    counting_http_port: int,
    counting_ws_port: int,
    dead_proxy_port: int,
    dead_port: int,
    live_acc_log: Path,
    dead_acc_log: Path,
    err_log: Path,
) -> tuple[Path, dict[str, str], dict[str, Path]]:
    """Render an isolated loopback Caddyfile + child env with persistence disabled."""
    site_marker = "your-passport-host.example.com {"
    idx = caddy_text.find(site_marker)
    assert idx != -1, "Missing site block in Caddyfile.example"
    global_block = caddy_text[:idx]
    site_tpl = caddy_text[idx:]

    global_block = global_block.replace(
        "{\n    log default {",
        "{\n    auto_https off\n    admin off\n    persist_config off\n    log default {",
        1,
    )
    global_block = global_block.replace("/var/log/caddy/passport_error.log", str(err_log))

    def _render_site(listen_port: int, acc_log: Path, http_port: int, ws_port: int) -> str:
        s = site_tpl.replace(site_marker, f"http://127.0.0.1:{listen_port} {{", 1)
        s = s.replace("/var/log/caddy/passport_access.log", str(acc_log))
        s = s.replace("127.0.0.1:18013", f"127.0.0.1:{http_port}")
        s = s.replace("127.0.0.1:18010", f"127.0.0.1:{ws_port}")
        return s

    cf_path = work_dir / "Caddyfile"
    cf_path.write_text(
        global_block
        + _render_site(live_port, live_acc_log, counting_http_port, counting_ws_port)
        + "\n\n"
        + _render_site(dead_proxy_port, dead_acc_log, dead_port, dead_port),
        encoding="utf-8",
    )

    caddy_home = work_dir / "caddy_home"
    caddy_cfg = work_dir / "caddy_xdg_config"
    caddy_data = work_dir / "caddy_xdg_data"
    caddy_cache = work_dir / "caddy_xdg_cache"
    for d in (caddy_home, caddy_cfg, caddy_data, caddy_cache):
        d.mkdir(parents=True, exist_ok=True)
    caddy_env = _base_env(
        HOME=str(caddy_home),
        XDG_CONFIG_HOME=str(caddy_cfg),
        XDG_DATA_HOME=str(caddy_data),
        XDG_CACHE_HOME=str(caddy_cache),
    )
    return cf_path, caddy_env, {
        "home": caddy_home,
        "xdg_config": caddy_cfg,
        "xdg_data": caddy_data,
        "xdg_cache": caddy_cache,
    }


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
    assert "access_log /var/log/nginx/passport_access.log passport_safe if=$passport_log_access;" in nginx_text
    acc_directives = [
        line.strip()
        for line in active_nginx_lines.splitlines()
        if "access_log" in line and "passport_access.log" in line
    ]
    assert len(acc_directives) >= 5, f"Expected server+location passport_access.log directives, got {acc_directives}"
    for acc_line in acc_directives:
        assert acc_line == "access_log /var/log/nginx/passport_access.log passport_safe if=$passport_log_access;", (
            f"passport_access.log directive missing conditional if=$passport_log_access: {acc_line}"
        )

    _, uri_rules = _nginx_map_rules(nginx_text, "passport_safe_uri")
    _, query_rules = _nginx_map_rules(nginx_text, "passport_safe_query")
    ref_src, unsafe_ref_rules = _nginx_map_rules(nginx_text, "passport_unsafe_referer")
    assert ref_src == "http_referer"
    unsafe_q_src, unsafe_q_rules = _nginx_map_rules(nginx_text, "passport_unsafe_query")
    assert unsafe_q_src == "$is_args$args|$uri"
    sec_uri_src, _ = _nginx_map_rules(nginx_text, "passport_secret_ota_uri")
    assert sec_uri_src == "uri"
    unsafe_p_src, _ = _nginx_map_rules(nginx_text, "passport_unsafe_path")
    assert unsafe_p_src == "$passport_secret_ota_uri:$request_uri"
    nginx_guards = _nginx_server_guards(nginx_text)
    assert ("$passport_unsafe_query", 400) in nginx_guards, (
        "Missing shared server-level $passport_unsafe_query guard"
    )
    assert ("$passport_unsafe_path", 400) in nginx_guards, (
        "Missing shared server-level $passport_unsafe_path guard"
    )
    log_src, _ = _nginx_map_rules(nginx_text, "passport_log_access")
    assert (
        "$passport_unsafe_referer" in log_src
        and "$passport_unsafe_query" in log_src
        and "$passport_unsafe_path" in log_src
        and "$passport_secret_ota_uri" in log_src
    ), f"Unexpected $passport_log_access source expression: {log_src}"

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
        if "ota" in test_uri:
            assert rendered_uri.startswith("/xiaozhi/ota/d/[REDACTED]/"), rendered_uri
        for forbidden in (syn_secret, syn_qtok, syn_user, syn_pass):
            assert forbidden not in rendered_uri, f"Nginx URI map leaked secret: {rendered_uri}"

    # Verify $passport_unsafe_query rejects literal, percent-encoded, and non-allowlisted
    # queries while permitting empty queries and exact /xiaozhi/v1/?from=mqtt_gateway,
    # sharing the exact decision with $passport_log_access.
    for qk in sorted(SENSITIVE_QUERY_KEYS):
        enc_lower = f"%{ord(qk[0].lower()):02x}{qk[1:]}"
        enc_upper = f"%{ord(qk[0].upper()):02X}{qk[1:]}"
        for q_sample in (
            f"{qk}={syn_qtok}",
            f"{qk.upper()}={syn_qtok}",
            f"{enc_lower}={syn_qtok}",
            f"{enc_upper}={syn_qtok}",
            f"%20{qk}={syn_qtok}",
            f"+{qk}={syn_qtok}",
            f"probe=1&{qk}={syn_qtok}",
            f"from=mqtt_gateway&{enc_lower}={syn_qtok}",
        ):
            for route_uri in ("/xiaozhi/ota/", "/xiaozhi/v1/", "/mcp/vision/explain"):
                assert (
                    _eval_nginx_var(
                        nginx_text,
                        "passport_unsafe_query",
                        norm_path=route_uri,
                        query=q_sample,
                        headers={"Referer": "https://proxy.example/"},
                    )
                    == "1"
                ), f"$passport_unsafe_query missed {route_uri}?{q_sample}"
                assert (
                    _eval_nginx_var(
                        nginx_text,
                        "passport_log_access",
                        norm_path=route_uri,
                        query=q_sample,
                        headers={"Referer": "https://proxy.example/"},
                    )
                    == "0"
                ), f"$passport_log_access did not skip rejected query on {route_uri}?{q_sample}"

    for bad_route, bad_q in (
        ("/xiaozhi/ota/", f"|token={syn_qtok}"),
        ("/xiaozhi/ota/", f"probe={syn_qtok}"),
        ("/xiaozhi/ota/", "from=mqtt_gateway"),
        ("/xiaozhi/v1/", "%66rom=mqtt_gateway"),
        ("/xiaozhi/v1/", "FROM=MQTT_GATEWAY"),
        ("/xiaozhi/v1/", "from=mqtt_gateway&extra=1"),
        ("/xiaozhi/v1/extra", "from=mqtt_gateway"),
    ):
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_unsafe_query",
                norm_path=bad_route,
                query=bad_q,
                headers={"Referer": "https://proxy.example/"},
            )
            == "1"
        ), f"$passport_unsafe_query unexpectedly allowed {bad_route}?{bad_q}"
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_log_access",
                norm_path=bad_route,
                query=bad_q,
                headers={"Referer": "https://proxy.example/"},
            )
            == "0"
        )

    assert _eval_nginx_map(unsafe_q_rules, "|/xiaozhi/ota/") == "0"
    assert _eval_nginx_map(unsafe_q_rules, "?from=mqtt_gateway|/xiaozhi/v1/") == "0"

    # Verify $passport_unsafe_path catches >=2 dot-segment & encoded OTA path traversals
    # while keeping single-dot paths inside /xiaozhi/ota/d/ as negative controls (log_access=0).
    for trav_raw in (
        f"/xiaozhi/ota/d/{syn_secret}/../../",
        f"/xiaozhi/ota/d/{syn_secret}/../..",
        f"/xiaozhi/ota/d/{syn_secret}/%2e%2e/%2e%2e/",
        f"/xiaozhi/ota/d/{syn_secret}/%2e%2e/%2e%2e",
        f"/%78iaozhi/ota/d/{syn_secret}/../../",
        f"/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn_secret}/../../",
        f"/xiaozhi/ota/d/{syn_secret}/..%2f../",
        f"/%58iaozhi/%4fta/%44/{syn_secret}/../../",
        f"/xiaozhi/ota/d/{syn_secret}/../../../",
        f"/xiaozhi/ota/d/{syn_secret}/../../../../xiaozhi/v1/",
        f"/xiaozhi/ota/d/{syn_secret}/../../../../mcp/vision/explain",
        f"/xiaozhi/ota/d/{syn_secret}/../../download/fw_1.0.bin",
    ):
        trav_norm = _nginx_normalize_uri(trav_raw)
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_unsafe_path",
                norm_path=trav_norm,
                query="",
                headers={},
                raw_target=trav_raw,
            )
            == "1"
        ), f"$passport_unsafe_path missed traversal {trav_raw} (norm={trav_norm})"
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_log_access",
                norm_path=trav_norm,
                query="",
                headers={},
                raw_target=trav_raw,
            )
            == "0"
        )

    for onedot_raw in (
        f"/xiaozhi/ota/d/{syn_secret}/../",
        f"/xiaozhi/ota/d/{syn_secret}/..",
        f"/xiaozhi/ota/d/{syn_secret}/%2e%2e/",
        f"/%78iaozhi/ota/d/{syn_secret}/../",
    ):
        onedot_norm = _nginx_normalize_uri(onedot_raw)
        assert onedot_norm == "/xiaozhi/ota/d/", onedot_raw
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_secret_ota_uri",
                norm_path=onedot_norm,
                query="",
                headers={},
                raw_target=onedot_raw,
            )
            == "1"
        )
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_unsafe_path",
                norm_path=onedot_norm,
                query="",
                headers={},
                raw_target=onedot_raw,
            )
            == "0"
        )
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_log_access",
                norm_path=onedot_norm,
                query="",
                headers={},
                raw_target=onedot_raw,
            )
            == "0"
        )
    assert (
        _eval_nginx_var(
            nginx_text,
            "passport_unsafe_query",
            norm_path="/xiaozhi/v1/",
            query="from=mqtt_gateway",
            headers={"Referer": "https://proxy.example/"},
        )
        == "0"
    )
    assert (
        _eval_nginx_var(
            nginx_text,
            "passport_log_access",
            norm_path="/xiaozhi/v1/",
            query="from=mqtt_gateway",
            headers={"Referer": "https://proxy.example/"},
        )
        == "1"
    )

    # Verify $passport_unsafe_referer strict allowlist & $passport_log_access conditional suppression.
    for safe_ref in ("", "https://proxy.example", "https://proxy.example/", "http://127.0.0.1:8443/", "https://[::1]:8443/"):
        assert _eval_nginx_map(unsafe_ref_rules, safe_ref) == "0", f"Safe Referer rejected: {safe_ref!r}"
        assert (
            _eval_nginx_var(
                nginx_text, "passport_log_access", norm_path="/xiaozhi/ota/", query="", headers={"Referer": safe_ref}
            )
            == "1"
        )
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_log_access",
                norm_path=f"/xiaozhi/ota/d/{syn_secret}/",
                query="",
                headers={"Referer": safe_ref},
            )
            == "0"
        )
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
        assert (
            _eval_nginx_var(
                nginx_text, "passport_log_access", norm_path="/xiaozhi/ota/", query="", headers={"Referer": bad_ref}
            )
            == "0"
        )
        assert (
            _eval_nginx_var(
                nginx_text,
                "passport_log_access",
                norm_path=f"/xiaozhi/ota/d/{syn_secret}/",
                query="",
                headers={"Referer": bad_ref},
            )
            == "0"
        )

    # Verify /xiaozhi/ota/d/ location block order & directives.
    ota_prefix_match = re.search(r"location\s+\^~\s+/xiaozhi/ota/d/\s*\{(.*?)\n    \}", nginx_text, re.DOTALL)
    assert ota_prefix_match, "Missing location ^~ /xiaozhi/ota/d/ block"
    ota_block = ota_prefix_match.group(1)
    assert "access_log off;" in ota_block
    assert "error_log /dev/null emerg;" in ota_block
    assert "log_not_found off;" in ota_block
    assert "log_subrequest off;" in ota_block
    assert "if ($passport_unsafe_query)" in ota_block

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
    idx_if = nested_block.find("if ($passport_unsafe_query)")
    idx_rw = nested_block.find("rewrite ^ /xiaozhi/ota/? break;")
    assert 0 <= idx_set < idx_if < idx_rw, (
        "Nginx nested OTA block must capture $passport_ota_secret before `if ($passport_unsafe_query)` and `rewrite`"
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

    # Caddy template structural & expression assertions.
    assert "@ota_secret_prefix path /xiaozhi/ota/d/*" in caddy_text
    assert "log_skip @ota_secret_prefix" in caddy_text
    assert "log_skip @unsafe_query" in caddy_text
    assert "log_skip @unsafe_path" in caddy_text
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
    assert "respond @unsafe_query 400" in caddy_text
    assert "respond @unsafe_path 400" in caddy_text
    caddy_adapted = _caddy_adapt_site(caddy_text)
    cred_matcher = caddy_adapted["matchers"].get("@unsafe_query", [])
    assert cred_matcher and all(sub["kind"] == "expression" for sub in cred_matcher), (
        f"@unsafe_query must use route-scoped CEL expression allowlist: {cred_matcher}"
    )
    path_matcher = caddy_adapted["matchers"].get("@unsafe_path", [])
    assert path_matcher and all(sub["kind"] == "expression" for sub in path_matcher), (
        f"@unsafe_path must use route-scoped CEL expression allowlist: {path_matcher}"
    )
    assert len(caddy_adapted["routes"]) == 1 and caddy_adapted["routes"][0]["tokens"] == ["route"], (
        "Caddy site handlers must be wrapped inside an ordered `route { ... }` block"
    )
    route_children = [c["tokens"] for c in caddy_adapted["routes"][0]["children"] or []]
    idx_log_skip = route_children.index(["log_skip", "@ota_secret_prefix"])
    idx_q_skip = route_children.index(["log_skip", "@unsafe_query"])
    idx_p_skip = route_children.index(["log_skip", "@unsafe_path"])
    idx_resp_cred = route_children.index(["respond", "@unsafe_query", "400"])
    idx_resp_path = route_children.index(["respond", "@unsafe_path", "400"])
    first_proxy_idx = min(
        i for i, toks in enumerate(route_children) if toks[0] in ("handle", "reverse_proxy")
    )
    assert (
        0 <= idx_log_skip < idx_q_skip < idx_p_skip < idx_resp_cred < idx_resp_path < first_proxy_idx
    ), f"Unexpected ordered Caddy route sequence: {route_children}"
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

    # Verify real-Caddy test fixture construction injects persist_config off / admin off / auto_https off
    # and isolates HOME/XDG_* inside tempdir (fixture construction check only; NOT real Caddy acceptance).
    with tempfile.TemporaryDirectory() as fix_tmp:
        fix_dir = Path(fix_tmp)
        fix_cf, fix_env, fix_dirs = _prepare_real_caddy_fixture(
            caddy_text,
            fix_dir,
            live_port=18101,
            counting_http_port=18102,
            counting_ws_port=18103,
            dead_proxy_port=18104,
            dead_port=18105,
            live_acc_log=fix_dir / "live_acc.log",
            dead_acc_log=fix_dir / "dead_acc.log",
            err_log=fix_dir / "err.log",
        )
        fix_txt = fix_cf.read_text(encoding="utf-8")
        assert "persist_config off" in fix_txt and "admin off" in fix_txt and "auto_https off" in fix_txt
        for env_k, dir_key in (
            ("HOME", "home"),
            ("XDG_CONFIG_HOME", "xdg_config"),
            ("XDG_DATA_HOME", "xdg_data"),
            ("XDG_CACHE_HOME", "xdg_cache"),
        ):
            assert fix_env[env_k] == str(fix_dirs[dir_key]) and fix_dir.resolve() in Path(fix_env[env_k]).resolve().parents

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

        def _should_access_log(self, raw_target: str, norm_path: str, query: str) -> bool:
            if norm_path.startswith("/xiaozhi/ota/d/"):
                return False
            acc_m = re.search(r"^    access_log\s+(\S+)\s+(\w+)(?:\s+if=\$(\w+))?;", nginx_text, re.MULTILINE)
            if not acc_m or acc_m.group(1) == "off":
                return False
            cond_var = acc_m.group(3)
            if cond_var:
                return (
                    _eval_nginx_var(
                        nginx_text,
                        cond_var,
                        norm_path=norm_path,
                        query=query,
                        headers=self.headers,
                        raw_target=raw_target,
                    )
                    not in ("", "0")
                )
            return True

        def _handle(self, method: str) -> None:
            parsed = urlsplit(self.path)
            norm_path = _nginx_normalize_uri(parsed.path)
            query = parsed.query
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length > 0 else b""
            referer = self.headers.get("Referer", "")
            is_secret_prefix = norm_path.startswith("/xiaozhi/ota/d/")

            # Server-level guards run before location matching.
            for guard_cond, guard_code in nginx_guards:
                g_m = re.fullmatch(r"\$(\w+)", guard_cond)
                assert g_m, f"Unsupported nginx guard: {guard_cond}"
                if (
                    _eval_nginx_var(
                        nginx_text,
                        g_m.group(1),
                        norm_path=norm_path,
                        query=query,
                        headers=self.headers,
                        raw_target=self.path,
                    )
                    not in ("", "0")
                ):
                    resp_body = json.dumps({"success": False, "guard": g_m.group(1)}).encode("utf-8")
                    if self._should_access_log(self.path, norm_path, query):
                        with proxy_lock:
                            proxy_access_logs.append(self._safe_log_line(method, norm_path, query, guard_code, len(resp_body)))
                    self.send_response(guard_code)
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

            full_target = ota_base.rstrip("/") + target_path + (f"?{query}" if query else "")
            req = urllib.request.Request(
                full_target,
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
            if self._should_access_log(self.path, norm_path, query):
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

    proxy_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TemplateProxyHandler)
    proxy_port = int(proxy_srv.server_address[1])
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

        # 2. Query credential (literal & percent-encoded) rejected with 400.
        for bad_q_url in (
            f"{proxy_base}/xiaozhi/ota/d/{dev_a['ota_secret']}/?token={q_sentinel}",
            f"{proxy_base}/xiaozhi/ota/d/{dev_a['ota_secret']}/?%74oken={q_sentinel}",
        ):
            st_q, _ = post_json(
                bad_q_url,
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

        # 4. Safe GET /xiaozhi/ota/ & exact GET /xiaozhi/v1/?from=mqtt_gateway logged safely,
        # while literal/percent-encoded/unexpected queries return 400 and skip access_log.
        benign_q = "q_benign_" + secrets.token_hex(8)
        with urllib.request.urlopen(f"{proxy_base}/xiaozhi/ota/", timeout=5) as r_get:
            assert r_get.status == 200
        try:
            with urllib.request.urlopen(f"{proxy_base}/xiaozhi/v1/?from=mqtt_gateway", timeout=5):
                pass
        except urllib.error.HTTPError as exc:
            assert exc.code == 404  # forwarded to HTTP OTA server (WS port not bound here) and access-logged
        for bad_q_path in (
            f"/xiaozhi/ota/?token={q_sentinel}",
            f"/xiaozhi/ota/?%74oken={q_sentinel}",
            f"/xiaozhi/ota/?%54oken={q_sentinel}",
            f"/xiaozhi/ota/?probe={benign_q}",
            "/xiaozhi/ota/?from=mqtt_gateway",
            "/xiaozhi/v1/?%66rom=mqtt_gateway",
            "/xiaozhi/v1/?FROM=MQTT_GATEWAY",
            f"/xiaozhi/v1/?from=mqtt_gateway&%74oken={q_sentinel}",
        ):
            st_get_q, _ = post_json(
                f"{proxy_base}{bad_q_path}",
                {
                    "Device-Id": dev_a["device_id"],
                    "Client-Id": dev_a["client_id"],
                    "Referer": "https://proxy.example/",
                },
            )
            assert st_get_q == 400, f"Expected 400 on {bad_q_path}, got {st_get_q}"

        # Raw two-dot traversals return 400 and single-dot returns 404 (both skip access log).
        def _raw_proxy_status(target_url: str, raw_path: str) -> int:
            u = urlsplit(target_url)
            conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
            try:
                conn.request("GET", raw_path, headers={"Connection": "close"})
                r = conn.getresponse()
                r.read()
                return r.status
            finally:
                conn.close()

        for trav_p in (
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../..",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/%2e%2e/%2e%2e/",
            f"/%78iaozhi/ota/d/{dev_a['ota_secret']}/../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../../../xiaozhi/v1/",
        ):
            assert _raw_proxy_status(proxy_base, trav_p) == 400, trav_p
        assert _raw_proxy_status(proxy_base, f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../") == 404

        joined_proxy_logs = "\n".join(proxy_access_logs + proxy_error_logs)
        assert len(proxy_access_logs) == 2, f"Expected only 2 safe access log entries, got: {proxy_access_logs}"
        assert "/xiaozhi/ota/" in joined_proxy_logs
        assert "/xiaozhi/v1/?[REDACTED]" in joined_proxy_logs
        assert not any("/xiaozhi/ota/d/" in line for line in proxy_access_logs), (
            f"Secret route or unsafe-Referer rejection entered access log: {proxy_access_logs}"
        )
        for forbidden in (dev_a["ota_secret"], wrong_secret, q_sentinel, benign_q, issued_ws_token, issued_ws_token_enc):
            assert forbidden not in joined_proxy_logs, "Proxy log leaked credential!"
    finally:
        proxy_srv.shutdown()
        proxy_srv.server_close()

    # Behavioral Caddyfile adapter/router semantic test (in-process model, NOT real Caddy).
    def _drive_caddy_model(tpl_text: str):
        adapted = _caddy_adapt_site(tpl_text)
        global_sinks = _caddy_log_sinks(tpl_text)
        access_sink = _caddy_site_access_sink(tpl_text)
        upstream_hits: list[tuple[str, str, str, dict[str, str]]] = []
        hit_lock = threading.Lock()

        def _caddy_upstream(
            method: str,
            target_upstream: str,
            target_path: str,
            raw_query: str,
            fwd_headers: dict[str, str],
            raw_body: bytes,
        ):
            with hit_lock:
                upstream_hits.append((target_upstream, target_path, raw_query, dict(fwd_headers)))
            if target_upstream == "127.0.0.1:18010":
                return 200, b"{}", "application/json"
            full_target = ota_base.rstrip("/") + target_path + (f"?{raw_query}" if raw_query else "")
            req = urllib.request.Request(
                full_target,
                data=raw_body if method == "POST" else None,
                headers=fwd_headers,
                method=method,
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read(), exc.headers.get("Content-Type", "application/json")

        class _TemplateCaddyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b""
                hdrs = {k: v for k, v in self.headers.items()}
                status, resp_body, ctype = _caddy_execute_routes(
                    adapted,
                    method=method,
                    raw_target=self.path,
                    headers=hdrs,
                    body=raw_body,
                    upstream_fn=_caddy_upstream,
                    sinks=global_sinks,
                    access_sink=access_sink,
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

        c_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TemplateCaddyHandler)
        c_srv.daemon_threads = True
        threading.Thread(target=c_srv.serve_forever, daemon=True).start()
        return c_srv, f"http://127.0.0.1:{c_srv.server_address[1]}", upstream_hits, access_sink, global_sinks

    caddy_srv, caddy_base, caddy_hits, caddy_acc_sink, caddy_global_sinks = _drive_caddy_model(caddy_text)
    caddy_q_sentinel = "q_caddy_" + secrets.token_hex(8)
    caddy_benign_q = "q_caddy_ok_" + secrets.token_hex(6)
    caddy_ws_token = ""
    try:
        # 1. Every credential key (literal, uppercase, percent-encoded, non-first param)
        #    and unexpected query returns 400 ahead of all proxy handles with ZERO upstream hits
        #    and skips access logging via `log_skip @unsafe_query`.
        for qk in sorted(SENSITIVE_QUERY_KEYS):
            enc_l = f"%{ord(qk[0].lower()):02x}{qk[1:]}"
            enc_u = f"%{ord(qk[0].upper()):02X}{qk[1:]}"
            for q_pair in (
                f"{qk}={caddy_q_sentinel}",
                f"{qk.upper()}={caddy_q_sentinel}",
                f"{enc_l}={caddy_q_sentinel}",
                f"{enc_u}={caddy_q_sentinel}",
                f"%20{qk}={caddy_q_sentinel}",
                f"+{qk}={caddy_q_sentinel}",
                f"probe=1&{qk}={caddy_q_sentinel}",
                f"from=mqtt_gateway&{enc_l}={caddy_q_sentinel}",
            ):
                for route_path in (
                    "/xiaozhi/ota/",
                    f"/xiaozhi/ota/d/{dev_a['ota_secret']}/",
                    "/mcp/vision/explain",
                    "/xiaozhi/v1/",
                ):
                    st_cq, _ = post_json(
                        f"{caddy_base}{route_path}?{q_pair}",
                        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
                    )
                    assert st_cq == 400, (
                        f"Caddy model failed to reject {route_path}?{q_pair}: got {st_cq}"
                    )
        for bad_get_path in (
            f"/xiaozhi/ota/?token={caddy_q_sentinel}",
            f"/xiaozhi/ota/?%74oken={caddy_q_sentinel}",
            f"/xiaozhi/ota/?%54oken={caddy_q_sentinel}",
            f"/xiaozhi/ota/?probe={caddy_benign_q}",
            "/xiaozhi/ota/?from=mqtt_gateway",
            f"/xiaozhi/v1/?api_key={caddy_q_sentinel}",
            f"/xiaozhi/v1/?%61pi_key={caddy_q_sentinel}",
            "/xiaozhi/v1/?%66rom=mqtt_gateway",
            "/xiaozhi/v1/?FROM=MQTT_GATEWAY",
        ):
            try:
                with urllib.request.urlopen(f"{caddy_base}{bad_get_path}", timeout=5):
                    raise AssertionError(f"Expected 400 on GET {bad_get_path}")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400, f"Unexpected GET status on {bad_get_path}: {exc.code}"
        for raw_trav_path in (
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/..",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../..",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/%2e%2e/%2e%2e/",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/%2e%2e/%2e%2e",
            f"/%78iaozhi/ota/d/{dev_a['ota_secret']}/../../",
            f"/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{dev_a['ota_secret']}/../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/..%2f../",
            f"/%58iaozhi/%4fta/%44/{dev_a['ota_secret']}/../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../../../xiaozhi/v1/",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../../../mcp/vision/explain",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../download/fw_1.0.bin",
        ):
            st_raw_trav = _raw_proxy_status(caddy_base, raw_trav_path)
            assert st_raw_trav == 400, f"Caddy model failed to reject {raw_trav_path}: {st_raw_trav}"
        for raw_onedot_path in (
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/%2e%2e/",
            f"/%78iaozhi/ota/d/{dev_a['ota_secret']}/../",
        ):
            st_onedot = _raw_proxy_status(caddy_base, raw_onedot_path)
            assert st_onedot == 404, f"Caddy model unexpected status on {raw_onedot_path}: {st_onedot}"
        assert caddy_hits == [], f"Disallowed queries/paths reached Caddy upstream: {caddy_hits}"
        assert caddy_acc_sink["lines"] == [], f"@unsafe_query/@unsafe_path/@ota_secret_prefix leaked into Caddy access log: {caddy_acc_sink['lines']}"

        # 2. Valid per-device OTA secret route rewrites to /xiaozhi/ota/, injects X-OTA-Secret,
        #    strips tracing headers, skips access logs, and returns live WS token.
        st_c_ok, body_c_ok = post_ota(
            caddy_base,
            {
                "Device-Id": dev_a["device_id"],
                "Client-Id": dev_a["client_id"],
                "X-Original-URI": f"/xiaozhi/ota/d/{dev_a['ota_secret']}/",
                "Referer": f"https://proxy.example/xiaozhi/ota/d/{dev_a['ota_secret']}/",
            },
            secret=dev_a["ota_secret"],
        )
        assert st_c_ok == 200 and body_c_ok["websocket"]["token"], f"Caddy OTA forward failed: {st_c_ok} {body_c_ok}"
        caddy_ws_token = body_c_ok["websocket"]["token"]
        assert len(caddy_hits) == 1
        hit_up, hit_path, _hit_q, hit_hdrs = caddy_hits[0]
        assert hit_up == "127.0.0.1:18013" and hit_path == "/xiaozhi/ota/"
        assert hit_hdrs.get("X-OTA-Secret") == dev_a["ota_secret"]
        lower_hit_hdrs = {k.lower() for k in hit_hdrs}
        for scrubbed in ("authorization", "x-original-uri", "referer"):
            assert scrubbed not in lower_hit_hdrs, f"Caddy failed to scrub {scrubbed}"

        # 3. Unknown subpath under /xiaozhi/ota/d/* hits @ota_secret_prefix -> 404 (not upstream), log skipped.
        st_c_404, _ = post_json(f"{caddy_base}/xiaozhi/ota/d/{dev_a['ota_secret']}/extra", {})
        assert st_c_404 == 404 and len(caddy_hits) == 1

        # 4. Permitted GET /xiaozhi/ota/ & exact /xiaozhi/v1/?from=mqtt_gateway reach upstream (200) and log redacted URI.
        with urllib.request.urlopen(f"{caddy_base}/xiaozhi/ota/", timeout=5) as r_c_ota:
            assert r_c_ota.status == 200
        with urllib.request.urlopen(f"{caddy_base}/xiaozhi/v1/?from=mqtt_gateway", timeout=5) as r_c_ws:
            assert r_c_ws.status == 200
        assert len(caddy_hits) == 3

        # 5. Unknown path outside handles hits fallback `respond 404`.
        try:
            with urllib.request.urlopen(f"{caddy_base}/unknown", timeout=5):
                raise AssertionError("Expected 404 on /unknown")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        assert len(caddy_hits) == 3

        # Verify site access log skipped /xiaozhi/ota/d/* and redacted all URIs/headers.
        assert not any("/xiaozhi/ota/d/" in ln for ln in caddy_acc_sink["lines"]), (
            f"Caddy access log recorded /xiaozhi/ota/d/ despite log_skip: {caddy_acc_sink['lines']}"
        )
        all_caddy_lines = list(caddy_acc_sink["lines"]) + [ln for s in caddy_global_sinks for ln in s["lines"]]
        assert len(caddy_acc_sink["lines"]) == 3
        assert all('"uri": "[REDACTED]"' in ln for ln in caddy_acc_sink["lines"])
        joined_caddy_logs = "\n".join(all_caddy_lines)
        for forbidden in (dev_a["ota_secret"], caddy_q_sentinel, caddy_benign_q, caddy_ws_token):
            assert forbidden not in joined_caddy_logs, "Caddy model log leaked credential!"
    finally:
        caddy_srv.shutdown()
        caddy_srv.server_close()

    # Caddy negative control A: multi-key `query` matcher ANDs distinct keys, letting single ?token=... pass to upstream.
    caddy_legacy_query = _caddy_with_legacy_and_query(caddy_text)
    neg_a_srv, neg_a_base, neg_a_hits, _, _ = _drive_caddy_model(caddy_legacy_query)
    try:
        with urllib.request.urlopen(f"{neg_a_base}/xiaozhi/ota/?token={caddy_q_sentinel}", timeout=5) as r_neg_a:
            assert r_neg_a.status == 200
        assert len(neg_a_hits) == 1, "Caddy negative control A failed to show multi-key AND bypass"
    finally:
        neg_a_srv.shutdown()
        neg_a_srv.server_close()

    # Caddy negative control B: without `route { ... }`, Caddyfile directive sorting places `handle` before `respond`,
    # letting /xiaozhi/ota/?token=... reach upstream before `respond @unsafe_query 400`.
    caddy_no_route = _caddy_strip_route_wrapper(caddy_text)
    neg_b_srv, neg_b_base, neg_b_hits, _, _ = _drive_caddy_model(caddy_no_route)
    try:
        with urllib.request.urlopen(f"{neg_b_base}/xiaozhi/ota/?token={caddy_q_sentinel}", timeout=5) as r_neg_b:
            assert r_neg_b.status == 200
        assert len(neg_b_hits) == 1, "Caddy negative control B failed to show handle-before-respond ordering bypass"
    finally:
        neg_b_srv.shutdown()
        neg_b_srv.server_close()

    # Caddy negative control C: raw `{query}` regex (`vars_regexp`) is bypassed by percent-encoded `?%74oken=...`.
    caddy_raw_vars_re = _caddy_with_legacy_vars_regexp(caddy_text)
    neg_c_srv, neg_c_base, neg_c_hits, _, _ = _drive_caddy_model(caddy_raw_vars_re)
    try:
        with urllib.request.urlopen(f"{neg_c_base}/xiaozhi/ota/?%74oken={caddy_q_sentinel}", timeout=5) as r_neg_c:
            assert r_neg_c.status == 200
        assert len(neg_c_hits) == 1, "Caddy negative control C failed to show percent-encoded query key bypass"
    finally:
        neg_c_srv.shutdown()
        neg_c_srv.server_close()

    # Caddy negative control D: removing `@unsafe_path` lets dot-segment OTA traversal paths hit HTTP upstream.
    caddy_no_path = _caddy_strip_unsafe_path(caddy_text)
    neg_d_srv, neg_d_base, neg_d_hits, _, _ = _drive_caddy_model(caddy_no_path)
    try:
        for trav_bypass in (
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/../../",
            f"/xiaozhi/ota/d/{dev_a['ota_secret']}/..",
        ):
            u_d = urlsplit(neg_d_base)
            c_d = http.client.HTTPConnection(u_d.hostname, u_d.port, timeout=5)
            try:
                c_d.request("GET", trav_bypass, headers={"Connection": "close"})
                r_d = c_d.getresponse()
                r_d.read()
                assert r_d.status in (200, 404), (trav_bypass, r_d.status)
            finally:
                c_d.close()
        assert len(neg_d_hits) == 2 and all(dev_a["ota_secret"] in h[1] for h in neg_d_hits), (
            f"Caddy negative control D failed to show traversal upstream hit: {neg_d_hits}"
        )
    finally:
        neg_d_srv.shutdown()
        neg_d_srv.server_close()

    print("[PASS] blocker #2: Nginx/Caddy templates validated and proxy OTA forwarding logs zero secrets")


def _caddy_split_tokens(raw: str) -> list[str]:
    """Tokenize a single Caddyfile line while preserving backtick-quoted strings."""
    tokens: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        while i < n and raw[i].isspace():
            i += 1
        if i >= n or raw[i] == "#":
            break
        buf: list[str] = []
        while i < n and not raw[i].isspace():
            ch = raw[i]
            if ch == "`":
                i += 1
                start = i
                while i < n and raw[i] != "`":
                    i += 1
                assert i < n, f"Unterminated backtick string in Caddyfile line: {raw!r}"
                buf.append(raw[start:i])
                i += 1
            elif ch in ('"', "'"):
                quote_ch = ch
                i += 1
                while i < n and raw[i] != quote_ch:
                    if raw[i] == "\\" and quote_ch == '"' and i + 1 < n:
                        i += 1
                    buf.append(raw[i])
                    i += 1
                assert i < n, f"Unterminated quote in Caddyfile line: {raw!r}"
                i += 1
            else:
                buf.append(ch)
                i += 1
        tokens.append("".join(buf))
    return tokens


def _caddy_parse_blocks(text: str) -> list[dict]:
    """Minimal Caddyfile block parser: [{'tokens': [...], 'children': [...]|None}]."""
    root: dict = {"tokens": [], "children": []}
    stack = [root]
    for raw in text.splitlines():
        toks = _caddy_split_tokens(raw)
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


_CADDY_DIRECTIVE_ORDER = {
    "log_skip": 10,
    "request_body": 20,
    "rewrite": 30,
    "handle": 40,
    "route": 50,
    "respond": 60,
    "reverse_proxy": 70,
}


def _caddy_site_access_sink(caddy_text: str) -> dict:
    """Extract the site-level `log { format filter ... }` sink from a Caddyfile."""
    blocks = _caddy_parse_blocks(caddy_text)
    assert blocks, "Empty Caddyfile"
    site_block = blocks[1] if blocks[0]["tokens"] == [] else blocks[0]
    fields: list[list[str]] = []
    for child in site_block["children"] or []:
        if child["tokens"][:1] != ["log"]:
            continue
        for directive in child["children"] or []:
            if directive["tokens"][:2] == ["format", "filter"]:
                for sub in directive["children"] or []:
                    if sub["tokens"] == ["fields"]:
                        fields.extend(f["tokens"] for f in sub["children"] or [])
                    elif sub["tokens"][0] != "wrap":
                        fields.append(sub["tokens"])
    return {"name": "site_access", "include": ["http.log.access"], "exclude": [], "fields": fields, "lines": []}


def _caddy_adapt_site(caddy_text: str) -> dict:
    """In-process Caddyfile adapter model (NOT real `caddy adapt`): parses matchers and applies directive/sortRoutes order."""
    blocks = _caddy_parse_blocks(caddy_text)
    assert blocks, "Empty Caddyfile"
    site_block = blocks[1] if blocks[0]["tokens"] == [] else blocks[0]
    matchers: dict[str, list[dict]] = {}
    raw_directives: list[dict] = []

    def _compile_submatcher(m_name: str, sub_toks: list[str]) -> dict:
        kind = sub_toks[0]
        args = sub_toks[1:]
        if kind == "query":
            params: dict[str, list[str]] = {}
            for kv in args:
                assert "=" in kv, f"Malformed Caddy query matcher arg: {kv!r}"
                k, v = kv.split("=", 1)
                params.setdefault(k, []).append(v)
            return {"kind": "query", "params": params}
        if kind == "vars_regexp":
            if len(args) == 2:
                re_name, field, pattern = m_name[1:], args[0], args[1]
            elif len(args) == 3:
                re_name, field, pattern = args[0], args[1], args[2]
            else:
                raise AssertionError(f"Unsupported vars_regexp syntax: {sub_toks}")
            for bad_re2 in ("(?=", "(?!", "(?<=", "(?<!", "\\1"):
                assert bad_re2 not in pattern, f"Unsupported RE2 construct {bad_re2!r} in {pattern!r}"
            return {"kind": "vars_regexp", "name": re_name, "field": field, "regex": re.compile(pattern)}
        if kind == "path":
            return {"kind": "path", "patterns": list(args)}
        if kind == "path_regexp":
            if len(args) == 1:
                re_name, pattern = m_name[1:], args[0]
            elif len(args) == 2:
                re_name, pattern = args[0], args[1]
            else:
                raise AssertionError(f"Unsupported path_regexp syntax: {sub_toks}")
            return {"kind": "path_regexp", "name": re_name, "regex": re.compile(pattern)}
        if kind == "expression":
            expr = " ".join(args).strip()
            assert expr, f"Empty Caddy expression matcher: {sub_toks}"
            return {"kind": "expression", "expr": expr}
        raise AssertionError(f"Unsupported Caddy matcher type: {sub_toks}")

    for child in site_block["children"] or []:
        toks = child["tokens"]
        if toks[0].startswith("@"):
            m_name = toks[0]
            if child["children"] is not None:
                subs = [_compile_submatcher(m_name, sub["tokens"]) for sub in child["children"]]
            else:
                assert len(toks) > 1, f"Empty inline Caddy matcher: {toks}"
                subs = [_compile_submatcher(m_name, toks[1:])]
            matchers[m_name] = subs
        elif toks[0] != "log":
            raw_directives.append(child)

    def _matcher_sort_key(node: dict) -> tuple[int, int]:
        toks = node["tokens"]
        if toks[0] in ("handle", "respond", "log_skip", "rewrite") and len(toks) > 1:
            mref = toks[1]
            if mref.startswith("/"):
                return (0, -len(mref))
            if mref.startswith("@"):
                subs = matchers.get(mref, [])
                if len(subs) == 1 and subs[0]["kind"] == "path" and len(subs[0]["patterns"]) == 1:
                    return (0, -len(subs[0]["patterns"][0]))
                return (1, 0)
        return (2, 0)

    def _adapt_nodes(nodes: list[dict], *, inside_route: bool) -> list[dict]:
        adapted: list[dict] = []
        for node in nodes:
            cmd = node["tokens"][0]
            children = node["children"]
            if children is not None and cmd in ("route", "handle"):
                new_children = _adapt_nodes(children, inside_route=(cmd == "route"))
            else:
                new_children = children
            adapted.append({"tokens": list(node["tokens"]), "children": new_children})
        if inside_route:
            return adapted
        return sorted(
            adapted,
            key=lambda n: (_CADDY_DIRECTIVE_ORDER.get(n["tokens"][0], 999), _matcher_sort_key(n)),
        )

    return {"matchers": matchers, "routes": _adapt_nodes(raw_directives, inside_route=False)}


def _caddy_clean_path(raw_path: str) -> str:
    """Model Go/Caddy path cleaning: decode %, merge slashes, resolve dot-segments, preserve literal trailing '/'."""
    decoded = unquote(raw_path)
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    trailing_slash = decoded.endswith("/")
    parts: list[str] = []
    for seg in decoded.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
        else:
            parts.append(seg)
    cleaned = "/" + "/".join(parts)
    if trailing_slash and cleaned != "/":
        cleaned += "/"
    return cleaned


def _caddy_path_match(pattern: str, norm_path: str) -> bool:
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, norm_path, re.IGNORECASE) is not None


def _caddy_eval_matcher(matcher_ref: Optional[str], matchers: dict[str, list[dict]], req_state: dict) -> bool:
    if matcher_ref is None:
        return True
    if matcher_ref.startswith("/"):
        return _caddy_path_match(matcher_ref, req_state["norm_path"])
    assert matcher_ref in matchers, f"Unknown Caddy matcher reference: {matcher_ref}"
    for sub in matchers[matcher_ref]:
        kind = sub["kind"]
        if kind == "query":
            # Official Caddy `query` matcher: distinct keys are AND'd; values per key are OR'd.
            qs = parse_qs(req_state["raw_query"], keep_blank_values=True)
            for k, patterns in sub["params"].items():
                if k not in qs:
                    return False
                if not any(
                    re.fullmatch(re.escape(p).replace(r"\*", ".*"), val)
                    for val in qs[k]
                    for p in patterns
                ):
                    return False
        elif kind == "vars_regexp":
            field = sub["field"]
            if field in ("{query}", "{http.request.uri.query}"):
                val = req_state["raw_query"]
            elif field in ("{uri}", "{http.request.uri}"):
                val = req_state["raw_uri"]
            elif field in ("{path}", "{http.request.uri.path}"):
                val = req_state["decoded_path"]
            else:
                raise AssertionError(f"Unsupported vars_regexp field: {field}")
            m = sub["regex"].search(val)
            if not m:
                return False
            req_state["re_groups"][sub["name"]] = m
        elif kind == "path":
            if not any(_caddy_path_match(p, req_state["norm_path"]) for p in sub["patterns"]):
                return False
        elif kind == "path_regexp":
            m = sub["regex"].search(req_state["norm_path"])
            if not m:
                return False
            req_state["re_groups"][sub["name"]] = m
        elif kind == "expression":
            expr = sub["expr"]
            q_expected = '{query} != "" && !({path} == "/xiaozhi/v1/" && {query} == "from=mqtt_gateway")'
            p_expected = (
                '!({http.request.orig_uri}.matches("^(/xiaozhi/ota/|/xiaozhi/ota/download/'
                '[A-Za-z0-9_][A-Za-z0-9._-]*|/mcp/vision/explain|/xiaozhi/v1/)(\\\\?.*)?$") '
                '|| path("/xiaozhi/ota/d/*") || ({http.request.orig_uri} == {path} '
                '&& !path("/xiaozhi/*", "/mcp/*") && !{path}.matches("(^|/)\\\\.{1,2}(/|$)|//")))'
            )
            if expr == q_expected:
                matched = bool(req_state["raw_query"]) and not (
                    req_state["decoded_path"] == "/xiaozhi/v1/" and req_state["raw_query"] == "from=mqtt_gateway"
                )
            elif expr == p_expected:
                allowed_canon = bool(
                    re.match(
                        r"^(/xiaozhi/ota/|/xiaozhi/ota/download/[A-Za-z0-9_][A-Za-z0-9._-]*|/mcp/vision/explain|/xiaozhi/v1/)(\?.*)?$",
                        req_state["raw_uri"],
                    )
                )
                in_secret_prefix = _caddy_path_match("/xiaozhi/ota/d/*", req_state["norm_path"])
                clean_unknown = (
                    req_state["raw_uri"] == req_state["decoded_path"]
                    and not _caddy_path_match("/xiaozhi/*", req_state["norm_path"])
                    and not _caddy_path_match("/mcp/*", req_state["norm_path"])
                    and not re.search(r"(^|/)\.{1,2}(/|$)|//", req_state["decoded_path"])
                )
                matched = not (allowed_canon or in_secret_prefix or clean_unknown)
            else:
                raise AssertionError(f"Unsupported Caddy expression in test model: {expr!r}")
            if not matched:
                return False
        else:
            raise AssertionError(f"Unsupported Caddy submatcher kind: {kind}")
    return True


def _caddy_execute_routes(
    adapted: dict,
    *,
    method: str,
    raw_target: str,
    headers: dict[str, str],
    body: bytes,
    upstream_fn,
    sinks: list[dict],
    access_sink: Optional[dict] = None,
) -> tuple[int, bytes, str]:
    """Execute adapted Caddy routes (in-process router model; NOT real Caddy)."""
    parsed = urlsplit(raw_target)
    decoded_path = unquote(parsed.path)
    norm_path = _caddy_clean_path(parsed.path)
    raw_query = parsed.query

    def _canon_hdr(name: str) -> str:
        return "-".join(part.capitalize() for part in name.split("-"))

    original_request = {
        "remote_ip": "127.0.0.1",
        "method": method,
        "host": headers.get("Host", ""),
        "uri": raw_target,
        "headers": {_canon_hdr(k): [v] for k, v in headers.items()},
    }
    req_state = {
        "raw_uri": raw_target,
        "decoded_path": decoded_path,
        "norm_path": norm_path,
        "raw_query": raw_query,
        "headers": dict(headers),
        "re_groups": {},
        "rewritten": False,
        "log_skip": False,
        "original_request": original_request,
    }

    def _exec_nodes(nodes: list[dict]) -> Optional[tuple[int, bytes, str]]:
        handle_matched = False
        for node in nodes:
            toks = node["tokens"]
            cmd = toks[0]
            if cmd == "log_skip":
                mref = toks[1] if len(toks) > 1 else None
                if _caddy_eval_matcher(mref, adapted["matchers"], req_state):
                    req_state["log_skip"] = True
            elif cmd == "respond":
                if len(toks) >= 3 and (toks[1].startswith("@") or toks[1].startswith("/")):
                    mref, status = toks[1], int(toks[-1])
                else:
                    mref, status = None, int(toks[-1])
                if _caddy_eval_matcher(mref, adapted["matchers"], req_state):
                    return status, b"{}", "application/json"
            elif cmd == "rewrite":
                mref = toks[1]
                new_target = toks[2]
                if mref == "*" or _caddy_eval_matcher(mref, adapted["matchers"], req_state):
                    req_state["norm_path"] = new_target
                    req_state["rewritten"] = True
            elif cmd == "request_body":
                pass
            elif cmd == "route":
                res = _exec_nodes(node["children"] or [])
                if res is not None:
                    return res
            elif cmd == "handle":
                if handle_matched:
                    continue
                mref = toks[1] if len(toks) > 1 else None
                if _caddy_eval_matcher(mref, adapted["matchers"], req_state):
                    handle_matched = True
                    res = _exec_nodes(node["children"] or [])
                    if res is not None:
                        return res
            elif cmd == "reverse_proxy":
                target_upstream = toks[1]
                fwd_headers = {
                    k: v
                    for k, v in req_state["headers"].items()
                    if k.lower() not in ("host", "content-length", "connection")
                }
                for child in node["children"] or []:
                    ctoks = child["tokens"]
                    if ctoks[:1] == ["header_up"] and len(ctoks) >= 2:
                        h_arg = ctoks[1]
                        if h_arg.startswith("-"):
                            drop = h_arg[1:].lower()
                            for existing in [k for k in fwd_headers if k.lower() == drop]:
                                fwd_headers.pop(existing, None)
                        elif len(ctoks) >= 3:
                            def _sub_re(match_obj):
                                rm = req_state["re_groups"].get(match_obj.group(1))
                                if rm is None:
                                    return ""
                                grp = match_obj.group(2)
                                return rm.group(int(grp)) if grp.isdigit() else rm.group(grp)

                            val = re.sub(r"\{re\.([^.}]+)\.([^}]+)\}", _sub_re, ctoks[2])
                            for existing in [k for k in fwd_headers if k.lower() == h_arg.lower()]:
                                fwd_headers.pop(existing, None)
                            fwd_headers[h_arg] = val
                upstream_path = (
                    req_state["norm_path"]
                    if req_state["rewritten"]
                    else req_state["raw_uri"].split("?", 1)[0]
                )
                return upstream_fn(method, target_upstream, upstream_path, req_state["raw_query"], fwd_headers, body)
            else:
                raise AssertionError(f"Unsupported Caddy directive in model: {toks}")
        return None

    res = _exec_nodes(adapted["routes"])
    if res is None:
        res = (200, b"", "text/plain")
    status, resp_body, ctype = res
    if access_sink is not None and not req_state["log_skip"]:
        _caddy_emit([access_sink], "http.log.access.log0", {"request": original_request, "status": status})
    return status, resp_body, ctype


def _caddy_with_legacy_and_query(caddy_text: str) -> str:
    """Mutant for negative control A: restore old multi-key `query` matcher (AND across keys)."""
    legacy_matcher = (
        "    @unsafe_query {\n"
        "        query authorization=* token=* access_token=* refresh_token=* id_token=* "
        "secret=* ota_secret=* key=* api_key=* apikey=* password=* sig=* signature=* auth=*\n"
        "    }"
    )
    mutated = re.sub(
        r"    @unsafe_query \{.*?\n    \}",
        lambda _m: legacy_matcher,
        caddy_text,
        count=1,
        flags=re.DOTALL,
    )
    assert mutated != caddy_text, "Failed to inject legacy AND query matcher"
    return mutated


def _caddy_with_legacy_vars_regexp(caddy_text: str) -> str:
    """Mutant for negative control C: restore raw `{query}` vars_regexp bypassed by `%74oken`."""
    legacy_matcher = (
        "    @unsafe_query {\n"
        "        vars_regexp cred_query {query} "
        "(?i)(^|&)(authorization|token|access_token|refresh_token|id_token|secret|ota_secret|key|api_key|apikey|password|sig|signature|auth)=\n"
        "    }"
    )
    mutated = re.sub(
        r"    @unsafe_query \{.*?\n    \}",
        lambda _m: legacy_matcher,
        caddy_text,
        count=1,
        flags=re.DOTALL,
    )
    assert mutated != caddy_text, "Failed to inject legacy vars_regexp query matcher"
    return mutated


def _caddy_strip_route_wrapper(caddy_text: str) -> str:
    """Mutant for negative control B: unwrap `route { ... }` so Caddyfile sorts `handle` ahead of `respond`."""
    m = re.search(r"\n    route \{\n(.*?)\n    \}\n\}", caddy_text, re.DOTALL)
    assert m, "Failed to locate `route { ... }` block in Caddyfile.example"
    dedented = "\n".join(line[4:] if line.startswith("    ") else line for line in m.group(1).splitlines())
    mutated = caddy_text[: m.start()] + "\n" + dedented + "\n}" + caddy_text[m.end() :]
    assert mutated != caddy_text
    return mutated


def _caddy_strip_unsafe_path(caddy_text: str) -> str:
    """Mutant for negative control D: remove `@unsafe_path` guard so traversal paths reach HTTP upstream."""
    mutated = re.sub(r"\n    @unsafe_path \{.*?\n    \}\n", "\n", caddy_text, count=1, flags=re.DOTALL)
    mutated = mutated.replace("        log_skip @unsafe_path\n", "")
    mutated = mutated.replace("        respond @unsafe_path 400\n", "")
    assert mutated != caddy_text, "Failed to strip @unsafe_path from Caddyfile"
    return mutated


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
    m = re.search(rf"map\s+(\S+)\s+\${re.escape(var_name)}\s*\{{(.*?)\}}", nginx_text, re.DOTALL)
    assert m, f"Missing map ${var_name}"
    src_raw = m.group(1).strip()
    if src_raw.startswith('"') and src_raw.endswith('"'):
        src_expr = src_raw[1:-1]
    elif src_raw.startswith("$"):
        src_expr = src_raw[1:]
    else:
        src_expr = src_raw
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
            # Official Nginx `map` string keys are case-insensitive unless prefixed by `~`.
            exact_rules.append((re.compile("^" + re.escape(pat_raw.strip('"')) + "$", re.IGNORECASE), out_raw))
    return src_expr, exact_rules + regex_rules + default_rules


def _eval_nginx_var(
    template: str,
    var_name: str,
    *,
    norm_path: str,
    query: str,
    headers,
    raw_target: Optional[str] = None,
    _seen: Optional[set[str]] = None,
) -> str:
    """Evaluate a request-scoped Nginx variable or composite `map` expression."""
    seen = set(_seen or ())
    if var_name == "uri":
        return norm_path
    if var_name == "request_uri":
        if raw_target is not None:
            return raw_target
        return norm_path + (f"?{query}" if query else "")
    if var_name == "is_args":
        return "?" if query else ""
    if var_name == "args":
        return query
    if var_name == "http_referer":
        return headers.get("Referer", "")
    assert var_name not in seen, f"Cyclic nginx map reference: {var_name}"
    seen.add(var_name)
    src_expr, rules = _nginx_map_rules(template, var_name)
    if "$" in src_expr:
        src_val = re.sub(
            r"\$(\w+)",
            lambda m: _eval_nginx_var(
                template,
                m.group(1),
                norm_path=norm_path,
                query=query,
                headers=headers,
                raw_target=raw_target,
                _seen=seen,
            ),
            src_expr,
        )
    else:
        src_val = _eval_nginx_var(
            template,
            src_expr,
            norm_path=norm_path,
            query=query,
            headers=headers,
            raw_target=raw_target,
            _seen=seen,
        )
    return _eval_nginx_map(rules, src_val)


def test_proxy_runtime_error_logs_redacted() -> None:
    """Round-2/3/4 proxy log redaction: backend-failure (502) & access_log write-failure error/access logs never record OTA secrets.

    In-process HTTP stand-ins driven directly by the parsed templates model both
    upstream connection failure (502) and access_log write failure (`[alert]` to
    `error_log`, explicitly supplemented by real Nginx binary acceptance when
    available in `test_real_nginx_log_isolation`). Negative controls prove the
    Round-3 letter-percent-encoding bypass, server-guard removal leak, and
    `if=$passport_log_access` removal leak under access-log write failure.
    """
    with _ReservedPortPool() as port_pool:
        dead_port = port_pool.reserve_dead("standin_dead_upstream")
        port_pool.assert_dead_ports_unreachable("standin_proxy_init")
        _run_proxy_runtime_error_logs_redacted(dead_port, port_pool)


def _run_proxy_runtime_error_logs_redacted(dead_port: int, port_pool: _ReservedPortPool) -> None:
    caddy_text = (ROOT / "proxy" / "Caddyfile.example").read_text(encoding="utf-8")
    nginx_text = (ROOT / "proxy" / "nginx-passport.conf.example").read_text(encoding="utf-8")
    syn = "errlog_ota_" + secrets.token_hex(12)

    def _upstream_fails() -> bool:
        port_pool.assert_dead_ports_unreachable("standin_upstream_probe")
        return True

    caddy_re_m = re.search(r"path_regexp\s+ota\s+(\S+)", caddy_text)
    assert caddy_re_m
    caddy_secret_re = re.compile(caddy_re_m.group(1))

    def _make_handler(flavor: str, template: str, sinks, *, access_log_write_fail: bool = False):
        guards = _nginx_server_guards(template) if flavor == "nginx" else []
        caddy_adapted = _caddy_adapt_site(template) if flavor == "caddy" else None
        site_err_m = re.search(r"^    error_log\s+(\S+)\s+(\w+);", template, re.MULTILINE) if flavor == "nginx" else None
        site_acc_m = (
            re.search(r"^    access_log\s+(\S+)\s+(\w+)(?:\s+if=\$(\w+))?;", template, re.MULTILINE)
            if flavor == "nginx"
            else None
        )
        ota_d_block_m = re.search(r"location\s+\^~\s+/xiaozhi/ota/d/\s*\{(.*?)\n    \}", template, re.DOTALL)
        fmt_vars: set[str] = set()
        if flavor == "nginx":
            log_fmt_m = re.search(r"log_format\s+passport_safe\s+(.*?);", template, re.DOTALL)
            assert log_fmt_m, "Missing log_format passport_safe in nginx template"
            fmt_vars = set(re.findall(r"\$[A-Za-z0-9_]+", log_fmt_m.group(1)))

        def _guard_hit(cond: str, raw_target: str, norm_path: str, query: str, headers) -> bool:
            var_m = re.fullmatch(r"\$(\w+)", cond)
            if var_m:
                return (
                    _eval_nginx_var(
                        template,
                        var_m.group(1),
                        norm_path=norm_path,
                        query=query,
                        headers=headers,
                        raw_target=raw_target,
                    )
                    not in ("", "0")
                )
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

        def _nginx_access_enabled(raw_target: str, norm_path: str, query: str, headers, *, loc_acc_off: bool = False) -> bool:
            if loc_acc_off or not site_acc_m or site_acc_m.group(1) == "off":
                return False
            cond_var = site_acc_m.group(3)
            if cond_var:
                return (
                    _eval_nginx_var(
                        template,
                        cond_var,
                        norm_path=norm_path,
                        query=query,
                        headers=headers,
                        raw_target=raw_target,
                    )
                    not in ("", "0")
                )
            return True

        def _emit_nginx_access(
            requestline: str, raw_target: str, method: str, norm_path: str, query: str, status: int, headers, *, loc_acc_off: bool = False
        ) -> None:
            if not _nginx_access_enabled(raw_target, norm_path, query, headers, loc_acc_off=loc_acc_off):
                return
            if access_log_write_fail:
                if site_err_m and site_err_m.group(1) != "/dev/null":
                    line = (
                        f'[alert] write() to "/dev/full" failed (28: No space left on device) while logging request, '
                        f'client: 127.0.0.1, server: passport, request: "{requestline}", '
                        f'host: "{headers.get("Host", "")}"'
                    )
                    if headers.get("Referer"):
                        line += f', referrer: "{headers["Referer"]}"'
                    sinks["err"].append(line)
                return
            sinks["access"].append(_render_nginx_access_line(method, norm_path, query, status, headers))

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
                        if _guard_hit(cond, self.path, norm_path, query, self.headers):
                            _emit_nginx_access(
                                self.requestline, self.path, self.command, norm_path, query, code, self.headers, loc_acc_off=False
                            )
                            self._reply(code)  # `return` writes nothing to error_log
                            return
                    in_secret_loc = norm_path.startswith("/xiaozhi/ota/d/")
                    err_sink_null = in_secret_loc and ota_d_block_m and "error_log /dev/null emerg;" in ota_d_block_m.group(1)
                    acc_off = bool(in_secret_loc and ota_d_block_m and "access_log off;" in ota_d_block_m.group(1))
                    if in_secret_loc and not re.match(r"^/xiaozhi/ota/d/[^/]+/?$", norm_path):
                        _emit_nginx_access(
                            self.requestline, self.path, self.command, norm_path, query, 404, self.headers, loc_acc_off=acc_off
                        )
                        self._reply(404)
                        return
                    if not _upstream_fails():
                        raise AssertionError("dead upstream port unexpectedly accepted")
                    if not err_sink_null and site_err_m:
                        line = (
                            f"[error] connect() failed (111: Connection refused) while connecting to upstream, "
                            f'client: 127.0.0.1, server: passport, request: "{self.requestline}", '
                            f'upstream: "http://127.0.0.1:{dead_port}{self.path}", host: "{self.headers.get("Host", "")}"'
                        )
                        if self.headers.get("Referer"):
                            line += f', referrer: "{self.headers["Referer"]}"'
                        sinks["err"].append(line)
                    _emit_nginx_access(
                        self.requestline, self.path, self.command, norm_path, query, 502, self.headers, loc_acc_off=acc_off
                    )
                    self._reply(502)
                    return
                # Caddy: original request is captured before `rewrite` for error logs, and
                # adapted route ordering ensures `@unsafe_query` returns 400 before proxy.
                original_request = {
                    "remote_ip": "127.0.0.1",
                    "method": self.command,
                    "host": self.headers.get("Host", ""),
                    "uri": self.path,
                    "headers": {
                        "-".join(p.capitalize() for p in k.split("-")): [v]
                        for k, v in self.headers.items()
                    },
                }

                def _dead_caddy_upstream(_m, _up, _tp, _rq, _fh, _bd):
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
                    return 502, b"{}", "application/json"

                assert caddy_adapted is not None
                status, _, _ = _caddy_execute_routes(
                    caddy_adapted,
                    method=self.command,
                    raw_target=self.path,
                    headers={k: v for k, v in self.headers.items()},
                    body=b"{}",
                    upstream_fn=_dead_caddy_upstream,
                    sinks=sinks,
                )
                self._reply(status)

            def do_GET(self):
                self._handle()

            def do_POST(self):
                self._handle()

        return _Handler

    def _drive(flavor: str, template: str, sinks, requests_spec, *, access_log_write_fail: bool = False) -> list[int]:
        srv = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _make_handler(flavor, template, sinks, access_log_write_fail=access_log_write_fail),
        )
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        statuses = []
        try:
            port = int(srv.server_address[1])
            for method, path, referer in requests_spec:
                headers = {
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "Device-Id": "aa:bb:cc:dd:ee:99",
                }
                if referer is not None:
                    headers["Referer"] = referer
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    conn.request(method, path, body=b"{}" if method == "POST" else None, headers=headers)
                    resp = conn.getresponse()
                    resp.read()
                    statuses.append(resp.status)
                finally:
                    conn.close()
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

    # --- Caddy: 502 backend failure on secret/normal routes & 400 pre-proxy query guard ---
    caddy_sinks = _caddy_log_sinks(caddy_text)
    caddy_status = _drive(
        "caddy",
        caddy_text,
        caddy_sinks,
        [
            ("POST", f"/xiaozhi/ota/d/{syn}/", secret_ref),
            ("POST", "/xiaozhi/ota/", secret_ref),
            ("POST", f"/xiaozhi/ota/?token={syn}", secret_ref),
            ("GET", f"/xiaozhi/ota/?%74oken={syn}", secret_ref),
            ("GET", f"/xiaozhi/v1/?from=mqtt_gateway&%74oken={syn}", secret_ref),
            ("GET", "/xiaozhi/v1/?FROM=MQTT_GATEWAY", secret_ref),
            ("POST", f"/xiaozhi/ota/d/{syn}/?token={syn}", secret_ref),
            ("GET", f"/xiaozhi/ota/d/{syn}/../../", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/..", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e/", None),
            ("GET", f"/%78iaozhi/ota/d/{syn}/../../", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/../", None),
            ("GET", "/xiaozhi/v1/?from=mqtt_gateway", "https://passport.example/"),
        ],
    )
    assert caddy_status == [502, 502, 400, 400, 400, 400, 400, 400, 400, 400, 400, 404, 502], caddy_status
    err_sink = [s for s in caddy_sinks if "http.log.error" in s["include"]]
    assert err_sink and len(err_sink[0]["lines"]) == 6, (
        f"Caddy runtime error sink expected 6 entries from the three 502s, got: {len(err_sink[0]['lines']) if err_sink else 0}"
    )
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

    # --- Nginx: site error log and access log across literal & equivalent percent-encoded Referers, query creds, & traversal paths ---
    guards = _nginx_server_guards(nginx_text)
    assert ("$passport_unsafe_referer", 400) in guards, f"Missing server-level Referer guard: {guards}"
    assert ("$passport_unsafe_query", 400) in guards, f"Missing server-level query guard: {guards}"
    assert ("$passport_unsafe_path", 400) in guards, f"Missing server-level path guard: {guards}"
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
            ("POST", f"/xiaozhi/ota/?token={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/v1/?api_key={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/ota/?%74oken={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/ota/?%54oken={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/v1/?from=mqtt_gateway&%74oken={syn}", "https://passport.example/"),
            ("GET", "/xiaozhi/v1/?FROM=MQTT_GATEWAY", "https://passport.example/"),
            ("GET", f"/xiaozhi/ota/?probe={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/ota/d/{syn}/../../", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/../..", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e/", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e", None),
            ("GET", f"/%78iaozhi/ota/d/{syn}/../../", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/../../../", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/../../../../xiaozhi/v1/", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/../", None),
            ("POST", "/xiaozhi/ota/", "https://passport.example/"),
            ("POST", f"/xiaozhi/ota/d/{syn}/", None),
            ("POST", f"/%78iaozhi/%6fta/%64/{syn}/", None),
            ("POST", f"/%78iaozhi/%6fta/%64/{syn}/", encoded_letter_3),
            ("GET", "/xiaozhi/v1/?from=mqtt_gateway", "https://passport.example/"),
        ],
    )
    assert nginx_status == [400] * 26 + [404, 502, 502, 502, 400, 502], nginx_status
    assert len(nginx_logs["err"]) == 2 and all('referrer: "https://passport.example/"' in ln for ln in nginx_logs["err"]), (
        f"nginx stand-in error_log unexpected: {nginx_logs['err']}"
    )
    assert len(nginx_logs["access"]) == 2 and all(" 502 " in ln for ln in nginx_logs["access"]), (
        f"expected 2 safe access log entries (400s & secret paths skipped), got {nginx_logs['access']}"
    )
    assert not any(syn in line for line in nginx_logs["err"] + nginx_logs["access"]), (
        "nginx template-driven stand-in leaked OTA secret into error_log or access_log"
    )

    # Access-log write failure simulation: unsafe-Referer 400s, disallowed/encoded-query 400s,
    # traversal-path 400s, single-dot 404 negative controls, and server-level secret-URI query
    # rejections all skip access_log, so neither error_log `[alert]` nor access_log captures leaks.
    fail_logs: dict[str, list[str]] = {"err": [], "access": []}
    fail_status = _drive(
        "nginx",
        nginx_text,
        fail_logs,
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
            ("POST", f"/xiaozhi/ota/?token={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/v1/?api_key={syn}", "https://passport.example/"),
            ("POST", "/xiaozhi/ota/", "https://passport.example/"),
            ("POST", f"/xiaozhi/ota/d/{syn}/", None),
            ("POST", f"/%78iaozhi/%6fta/%64/{syn}/", None),
            ("POST", f"/%78iaozhi/%6fta/%64/{syn}/", encoded_letter_3),
            ("POST", f"/xiaozhi/ota/d/{syn}/?token={syn}", None),
            ("GET", f"/xiaozhi/ota/?%74oken={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/ota/?%54oken={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/v1/?from=mqtt_gateway&%74oken={syn}", "https://passport.example/"),
            ("GET", "/xiaozhi/v1/?FROM=MQTT_GATEWAY", "https://passport.example/"),
            ("GET", f"/xiaozhi/ota/?probe={syn}", "https://passport.example/"),
            ("GET", f"/xiaozhi/ota/d/{syn}/../../", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/../..", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e/", None),
            ("GET", f"/%78iaozhi/ota/d/{syn}/../../", None),
            ("GET", f"/xiaozhi/ota/d/{syn}/../", None),
            ("GET", "/xiaozhi/v1/?from=mqtt_gateway", "https://passport.example/"),
        ],
        access_log_write_fail=True,
    )
    assert fail_status == [400] * 14 + [502, 502, 502] + [400] * 11 + [404, 502], fail_status
    assert fail_logs["access"] == []
    assert len(fail_logs["err"]) == 4 and all('referrer: "https://passport.example/"' in ln for ln in fail_logs["err"]), (
        f"unexpected fail_logs err: {fail_logs['err']}"
    )
    assert any("[alert]" in ln for ln in fail_logs["err"])
    assert not any(syn in line for line in fail_logs["err"] + fail_logs["access"])

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

    # Negative control 3: stripping `if=$passport_log_access` under access_log write failure leaks raw Referer & raw query via [alert].
    nginx_uncond_acc = nginx_text.replace(" if=$passport_log_access", "")
    assert nginx_uncond_acc != nginx_text
    uncond_logs: dict[str, list[str]] = {"err": [], "access": []}
    uncond_status = _drive(
        "nginx",
        nginx_uncond_acc,
        uncond_logs,
        [
            ("POST", "/xiaozhi/ota/", secret_ref),
            ("POST", "/xiaozhi/ota/", encoded_letter_3),
            ("POST", f"/xiaozhi/ota/d/{syn}/?token={syn}", None),
            ("POST", f"/xiaozhi/ota/?token={syn}", "https://passport.example/"),
        ],
        access_log_write_fail=True,
    )
    assert uncond_status == [400, 400, 400, 400]
    assert len(uncond_logs["err"]) == 4 and all(syn in line and "[alert]" in line for line in uncond_logs["err"]), (
        f"unconditional access_log negative control failed to detect [alert] leak: {uncond_logs['err']}"
    )

    # Negative control 4: reverting to raw `$args` literal key denylist lets `?%74oken=...` pass to upstream (502)
    # and leaks the raw request line in BOTH upstream connect() failure AND access_log [alert].
    legacy_raw_q_map = (
        "map $args $passport_unsafe_query {\n"
        "    ~*(^|&)(authorization|token|access_token|refresh_token|id_token|secret|ota_secret|key|api_key|apikey|password|sig|signature|auth)= 1;\n"
        "    default 0;\n"
        "}"
    )
    nginx_legacy_raw_q = re.sub(
        r"map \"\$is_args\$args\|\$uri\" \$passport_unsafe_query \{.*?\}",
        lambda _m: legacy_raw_q_map,
        nginx_text,
        count=1,
        flags=re.DOTALL,
    )
    assert nginx_legacy_raw_q != nginx_text
    legacy_q_logs: dict[str, list[str]] = {"err": [], "access": []}
    legacy_q_status = _drive(
        "nginx",
        nginx_legacy_raw_q,
        legacy_q_logs,
        [("GET", f"/xiaozhi/ota/?%74oken={syn}", "https://passport.example/")],
        access_log_write_fail=True,
    )
    assert legacy_q_status == [502], f"Negative control 4 failed to pass %74oken: {legacy_q_status}"
    assert len(legacy_q_logs["err"]) == 2
    assert any("connect() failed" in ln and syn in ln for ln in legacy_q_logs["err"])
    assert any("[alert]" in ln and syn in ln for ln in legacy_q_logs["err"])

    # Negative control 5: stripping `$passport_unsafe_path` guard & its `$passport_log_access` term lets
    # `/xiaozhi/ota/d/<syn>/../../` reach ordinary `/xiaozhi/ota/` (502) and leak `<syn>` into BOTH
    # `connect() failed` AND `[alert]`.
    nginx_no_path_guard = re.sub(
        r"\n\s*if \(\$passport_unsafe_path\) \{\s*return 400;\s*\}", "", nginx_text, count=1
    )
    nginx_no_path_guard = re.sub(
        r'map "\$passport_unsafe_referer:\$passport_unsafe_query:\$passport_unsafe_path:\$passport_secret_ota_uri" \$passport_log_access \{.*?\}',
        'map "$passport_unsafe_referer:$passport_unsafe_query:$passport_secret_ota_uri" $passport_log_access {\n'
        '    "0:0:0"  1;\n'
        '    default  0;\n'
        '}',
        nginx_no_path_guard,
        count=1,
        flags=re.DOTALL,
    )
    assert nginx_no_path_guard != nginx_text
    no_path_logs: dict[str, list[str]] = {"err": [], "access": []}
    no_path_status = _drive(
        "nginx",
        nginx_no_path_guard,
        no_path_logs,
        [("GET", f"/xiaozhi/ota/d/{syn}/../../", None)],
        access_log_write_fail=True,
    )
    assert no_path_status == [502], f"Negative control 5 failed to pass two-dot traversal: {no_path_status}"
    assert len(no_path_logs["err"]) == 2
    assert any("connect() failed" in ln and syn in ln for ln in no_path_logs["err"])
    assert any("[alert]" in ln and syn in ln for ln in no_path_logs["err"])
    print(
        "[PASS] round-2/3/4/5: Caddy/Nginx template-driven stand-ins record zero OTA secrets across "
        "literal, letter-percent-encoded, two-dot traversal, and simulated access_log write failures"
    )


def _find_nginx_binary() -> Optional[Path]:
    """Locate an installed or user-space nginx binary without altering system state."""
    candidates: list[Path] = []
    if os.environ.get("PASSPORT_NGINX_BIN"):
        candidates.append(Path(os.environ["PASSPORT_NGINX_BIN"]))
    which_nginx = shutil.which("nginx")
    if which_nginx:
        candidates.append(Path(which_nginx))
    candidates.extend(
        [
            Path("/usr/sbin/nginx"),
            Path("/sbin/nginx"),
            Path.home() / ".local" / "passport-nginx" / "usr" / "sbin" / "nginx",
            Path("/tmp/passport-nginx/usr/sbin/nginx"),
        ]
    )
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _render_loopback_nginx_server(
    server_tpl: str,
    *,
    listen_port: int,
    http_upstream_port: int,
    ws_upstream_port: int,
    access_log_path: str,
    error_log_path: str,
    strip_access_if: bool = False,
) -> str:
    """Adapt the repo Nginx server{} block verbatim to a loopback HTTP test port."""
    s = server_tpl
    s = re.sub(r"^\s*listen\s+443\s+ssl;\n", f"    listen 127.0.0.1:{listen_port};\n", s, flags=re.MULTILINE)
    s = re.sub(r"^\s*http2\s+on;\n", "", s, flags=re.MULTILINE)
    s = re.sub(r"^\s*ssl_(?:certificate|certificate_key|protocols)\b.*;\n", "", s, flags=re.MULTILINE)
    s = s.replace("127.0.0.1:18013", f"127.0.0.1:{http_upstream_port}")
    s = s.replace("127.0.0.1:18010", f"127.0.0.1:{ws_upstream_port}")
    s = s.replace("/var/log/nginx/passport_access.log", access_log_path)
    s = s.replace("/var/log/nginx/passport_error.log", error_log_path)
    if strip_access_if:
        s = s.replace(" if=$passport_log_access", "")
    return s


def test_real_nginx_log_isolation(ota_base: str, dev_a: dict) -> set[str]:
    """Run real Nginx acceptance (nginx -t, counting upstream zero-hit/forward, 502 failure, /dev/full)."""
    nginx_bin = _find_nginx_binary()
    if nginx_bin is None:
        print(
            "[INFO] real nginx binary unavailable on host/user-space; skipping real Nginx acceptance "
            "(in-process Python stand-ins are NOT real Nginx acceptance)"
        )
        return set()

    ver_res = subprocess.run([str(nginx_bin), "-v"], capture_output=True, text=True)
    nginx_ver = (ver_res.stderr or ver_res.stdout).strip()
    nginx_text = (ROOT / "proxy" / "nginx-passport.conf.example").read_text(encoding="utf-8")
    http_m = re.search(r"# --- BEGIN http \{\} scope.*?---\n(.*?)# --- END http \{\} scope", nginx_text, re.DOTALL)
    srv_m = re.search(r"^(server\s*\{.*?\n\})\s*\Z", nginx_text, re.DOTALL | re.MULTILINE)
    assert http_m and srv_m, "Failed to extract http{} and server{} blocks from nginx-passport.conf.example"
    http_block = http_m.group(1)
    srv_tpl = srv_m.group(1)

    live_http_port = urlsplit(ota_base).port
    assert live_http_port is not None
    syn = "realnginx_ota_" + secrets.token_hex(12)
    q_syn = "realnginx_q_" + secrets.token_hex(10)
    benign_q = "realnginx_benign_" + secrets.token_hex(8)
    issued_tokens: set[str] = set()
    forbidden_all: set[str] = {syn, q_syn, benign_q, dev_a["ota_secret"]}
    last_response: dict = {}

    def _raw_http(
        port: int,
        method: str,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
        label: str = "",
    ) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            hdrs = {"Connection": "close", **(headers or {})}
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            last_response.clear()
            last_response.update(
                {
                    "label": label or str(port),
                    "port": port,
                    "method": method,
                    "path": path,
                    "status": resp.status,
                    "body_preview": data.decode("utf-8", "replace")[:512],
                }
            )
            return resp.status, data
        finally:
            conn.close()

    cnt_srv, cnt_port, cnt_hits, cnt_lock = _start_counting_upstream()
    try:
        with tempfile.TemporaryDirectory() as tmpdir, _ReservedPortPool() as port_pool:
            tmp = Path(tmpdir)
            for d in ("client_body_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"):
                (tmp / d).mkdir()

            port_pool.register_external("live_ota_http", live_http_port)
            port_pool.register_external("counting_upstream", cnt_port)
            dead_port = port_pool.reserve_dead("dead_upstream")
            p_count = port_pool.reserve_listen("nginx_count")
            p_live = port_pool.reserve_listen("nginx_live")
            p_dead = port_pool.reserve_listen("nginx_dead")

            cnt_acc = tmp / "cnt_access.log"
            cnt_err = tmp / "cnt_error.log"
            live_acc = tmp / "live_access.log"
            live_err = tmp / "live_error.log"
            dead_acc = tmp / "dead_access.log"
            dead_err = tmp / "dead_error.log"
            global_err = tmp / "global_error.log"

            servers = [
                _render_loopback_nginx_server(
                    srv_tpl,
                    listen_port=p_count,
                    http_upstream_port=cnt_port,
                    ws_upstream_port=cnt_port,
                    access_log_path=str(cnt_acc),
                    error_log_path=str(cnt_err),
                ),
                _render_loopback_nginx_server(
                    srv_tpl,
                    listen_port=p_live,
                    http_upstream_port=live_http_port,
                    ws_upstream_port=cnt_port,
                    access_log_path=str(live_acc),
                    error_log_path=str(live_err),
                ),
                _render_loopback_nginx_server(
                    srv_tpl,
                    listen_port=p_dead,
                    http_upstream_port=dead_port,
                    ws_upstream_port=dead_port,
                    access_log_path=str(dead_acc),
                    error_log_path=str(dead_err),
                ),
            ]

            has_dev_full = Path("/dev/full").exists()
            full_specs: list[tuple[str, int, Path, str, str, Optional[str], int, str]] = []
            legacy_http_extra = ""
            if has_dev_full:
                legacy_http_extra = (
                    "map $args $passport_legacy_cred_query {\n"
                    "    ~*(^|&)(authorization|token|access_token|refresh_token|id_token|secret|ota_secret|key|api_key|apikey|password|sig|signature|auth)= 1;\n"
                    "    default 0;\n"
                    "}\n"
                    "map \"$passport_unsafe_referer:$passport_legacy_cred_query:$passport_unsafe_path:$passport_secret_ota_uri\" $passport_legacy_log_access {\n"
                    "    \"0:0:0:0\"  1;\n"
                    "    default    0;\n"
                    "}\n"
                    "map \"$passport_unsafe_referer:$passport_unsafe_query:$passport_secret_ota_uri\" $passport_legacy_no_path_log_access {\n"
                    "    \"0:0:0\"  1;\n"
                    "    default  0;\n"
                    "}\n"
                )
                # Separate server{} blocks give each probe an isolated ngx_http_log_t (bypassing Nginx's 60s error_log_time throttle).
                full_cases = [
                    ("fixed_lit", "POST", "/xiaozhi/ota/", f"https://passport.example/xiaozhi/ota/d/{syn}/", 400, "fixed"),
                    ("fixed_part_enc", "POST", "/xiaozhi/ota/", f"https://passport.example/%78iaozhi/%6fta/%64/{syn}/", 400, "fixed"),
                    (
                        "fixed_full_enc",
                        "POST",
                        "/xiaozhi/ota/",
                        f"https://passport.example/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn}/",
                        400,
                        "fixed",
                    ),
                    (
                        "fixed_enc_uri_ref",
                        "POST",
                        f"/%78iaozhi/%6fta/%64/{syn}/",
                        f"https://passport.example/%78iaozhi/%6fta/%64/{syn}/",
                        400,
                        "fixed",
                    ),
                    ("fixed_secret_q", "POST", f"/xiaozhi/ota/d/{syn}/?token={q_syn}", None, 400, "fixed"),
                    ("fixed_secret_enc_q", "POST", f"/xiaozhi/ota/d/{syn}/?%74oken={q_syn}", None, 400, "fixed"),
                    ("fixed_ota_q_ref", "POST", f"/xiaozhi/ota/?token={q_syn}", "https://passport.example/", 400, "fixed"),
                    ("fixed_ota_enc_q_ref", "GET", f"/xiaozhi/ota/?%74oken={q_syn}", "https://passport.example/", 400, "fixed"),
                    ("fixed_ota_enc_q_upper", "GET", f"/xiaozhi/ota/?%54oken={q_syn}", "https://passport.example/", 400, "fixed"),
                    ("fixed_ota_probe_q", "GET", f"/xiaozhi/ota/?probe={benign_q}", "https://passport.example/", 400, "fixed"),
                    ("fixed_ota_q_noref", "GET", f"/xiaozhi/ota/?api_key={q_syn}", None, 400, "fixed"),
                    ("fixed_ws_q_ref", "GET", f"/xiaozhi/v1/?foo=1&Authorization={q_syn}", "https://passport.example/", 400, "fixed"),
                    ("fixed_ws_enc_q_ref", "GET", f"/xiaozhi/v1/?from=mqtt_gateway&%74oken={q_syn}", "https://passport.example/", 400, "fixed"),
                    ("fixed_v1_upper_q", "GET", "/xiaozhi/v1/?FROM=MQTT_GATEWAY", "https://passport.example/", 400, "fixed"),
                    ("fixed_twodot_slash", "GET", f"/xiaozhi/ota/d/{syn}/../../", None, 400, "fixed"),
                    ("fixed_twodot_noslash", "GET", f"/xiaozhi/ota/d/{syn}/../..", None, 400, "fixed"),
                    ("fixed_twodot_pct", "GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e/", None, 400, "fixed"),
                    ("fixed_twodot_pct_nosl", "GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e", None, 400, "fixed"),
                    ("fixed_twodot_enc_pfx", "GET", f"/%78iaozhi/ota/d/{syn}/../../", None, 400, "fixed"),
                    ("fixed_twodot_full_enc", "GET", f"/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn}/../../", None, 400, "fixed"),
                    ("fixed_threedot_root", "GET", f"/xiaozhi/ota/d/{syn}/../../../", None, 400, "fixed"),
                    ("fixed_onedot_ctrl", "GET", f"/xiaozhi/ota/d/{syn}/../", None, 404, "fixed"),
                    ("fixed_safe_pos", "GET", "/xiaozhi/ota/", "https://passport.example/", 200, "fixed_pos"),
                    ("fixed_ws_mqtt_pos", "GET", "/xiaozhi/v1/?from=mqtt_gateway", "https://passport.example/", 200, "fixed_pos"),
                    ("neg_uncond_lit", "POST", "/xiaozhi/ota/", f"https://passport.example/xiaozhi/ota/d/{syn}/", 400, "neg_uncond"),
                    ("neg_uncond_enc", "POST", "/xiaozhi/ota/", f"https://passport.example/%78iaozhi/%6fta/%64/{syn}/", 400, "neg_uncond"),
                    ("neg_uncond_ota_q", "POST", f"/xiaozhi/ota/?token={q_syn}", "https://passport.example/", 400, "neg_uncond"),
                    ("neg_uncond_enc_q", "GET", f"/xiaozhi/ota/?%74oken={q_syn}", "https://passport.example/", 400, "neg_uncond"),
                    ("neg_legacy_raw_q", "GET", f"/xiaozhi/ota/?%74oken={q_syn}", "https://passport.example/", 502, "neg_legacy_raw_q"),
                    ("neg_legacy_path_twodot", "GET", f"/xiaozhi/ota/d/{syn}/../../", None, 502, "neg_legacy_path_twodot"),
                ]
                for label, method, path, ref, exp_code, mode_tag in full_cases:
                    fp = port_pool.reserve_listen(f"nginx_full_{label}")
                    ferr = tmp / f"full_{label}.log"
                    full_specs.append((label, fp, ferr, method, path, ref, exp_code, mode_tag))
                    use_dead = mode_tag in ("neg_legacy_raw_q", "neg_legacy_path_twodot")
                    rendered_srv = _render_loopback_nginx_server(
                        srv_tpl,
                        listen_port=fp,
                        http_upstream_port=dead_port if use_dead else live_http_port,
                        ws_upstream_port=dead_port if use_dead else cnt_port,
                        access_log_path="/dev/full",
                        error_log_path=str(ferr),
                        strip_access_if=(mode_tag == "neg_uncond"),
                    )
                    if mode_tag == "neg_legacy_raw_q":
                        rendered_srv = rendered_srv.replace("$passport_unsafe_query", "$passport_legacy_cred_query")
                        rendered_srv = rendered_srv.replace("$passport_log_access", "$passport_legacy_log_access")
                    elif mode_tag == "neg_legacy_path_twodot":
                        rendered_srv = re.sub(
                            r"\n\s*if \(\$passport_unsafe_path\) \{\s*return 400;\s*\}",
                            "",
                            rendered_srv,
                            count=1,
                        )
                        rendered_srv = rendered_srv.replace("$passport_log_access", "$passport_legacy_no_path_log_access")
                    servers.append(rendered_srv)

            port_pool.assert_all_disjoint("real_nginx_pre_config")
            listen_port_count = 3 + len(full_specs)
            nginx_stderr = ""
            try:
                conf = tmp / "nginx.conf"
                conf.write_text(
                    f"worker_processes 1;\n"
                    f"daemon off;\n"
                    f"pid {tmp / 'nginx.pid'};\n"
                    f"error_log {global_err} warn;\n"
                    f"events {{ worker_connections 64; }}\n"
                    f"http {{\n"
                    f"    client_body_temp_path {tmp / 'client_body_temp'};\n"
                    f"    proxy_temp_path {tmp / 'proxy_temp'};\n"
                    f"    fastcgi_temp_path {tmp / 'fastcgi_temp'};\n"
                    f"    uwsgi_temp_path {tmp / 'uwsgi_temp'};\n"
                    f"    scgi_temp_path {tmp / 'scgi_temp'};\n"
                    f"{http_block}\n"
                    f"{legacy_http_extra}"
                    + "\n".join(servers)
                    + "\n}\n",
                    encoding="utf-8",
                )

                test_res = subprocess.run([str(nginx_bin), "-t", "-p", str(tmp), "-c", str(conf)], capture_output=True, text=True)
                assert test_res.returncode == 0, f"nginx -t failed ({test_res.returncode}):\n{test_res.stderr}"

                # Release listen placeholders right before starting Nginx; keep dead_port bound-unlistening throughout.
                port_pool.release_listen_ports()
                proc = subprocess.Popen(
                    [str(nginx_bin), "-p", str(tmp), "-c", str(conf)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    for wait_port in (p_count, p_live, p_dead):
                        deadline = time.monotonic() + 8.0
                        while time.monotonic() < deadline:
                            if proc.poll() is not None:
                                nginx_stderr = proc.stderr.read() if proc.stderr else ""
                                raise RuntimeError(f"Real nginx exited prematurely ({proc.returncode}): {nginx_stderr}")
                            try:
                                with socket.create_connection(("127.0.0.1", wait_port), timeout=0.5):
                                    break
                            except OSError:
                                time.sleep(0.05)
                        else:
                            raise TimeoutError(f"Real nginx port 127.0.0.1:{wait_port} did not become ready")

                    port_pool.assert_dead_ports_unreachable("real_nginx_after_start")

                    # Scenario 0 (counting upstream): verify zero upstream hits for all rejected literal,
                    # percent-encoded, smuggled, and non-allowlisted queries, unsafe Referers, and
                    # >=2 dot-segment / encoded OTA path traversals (+ single-dot 404 negative controls),
                    # plus exact upstream hits and header scrubbing for permitted requests.
                    for method, bad_path, bad_hdrs in (
                        ("GET", f"/xiaozhi/ota/?token={q_syn}", {"Referer": "https://passport.example/"}),
                        ("GET", f"/xiaozhi/ota/?%74oken={q_syn}", {"Referer": "https://passport.example/"}),
                        ("GET", f"/xiaozhi/ota/?%54oken={q_syn}", {"Referer": "https://passport.example/"}),
                        ("GET", f"/xiaozhi/ota/?%20token={q_syn}", {"Referer": "https://passport.example/"}),
                        ("POST", f"/xiaozhi/ota/?%61pi_key={q_syn}", {"Content-Type": "application/json", "Referer": "https://passport.example/"}),
                        ("GET", f"/xiaozhi/v1/?from=mqtt_gateway&%74oken={q_syn}", {"Referer": "https://passport.example/"}),
                        ("GET", "/xiaozhi/v1/?%66rom=mqtt_gateway", {"Referer": "https://passport.example/"}),
                        ("GET", "/xiaozhi/v1/?FROM=MQTT_GATEWAY", {"Referer": "https://passport.example/"}),
                        ("POST", f"/mcp/vision/explain?%73ecret={q_syn}", {"Content-Type": "application/json", "Referer": "https://passport.example/"}),
                        ("GET", f"/xiaozhi/ota/?|token={q_syn}", {"Referer": "https://passport.example/"}),
                        ("GET", f"/xiaozhi/ota/?probe={benign_q}", {"Referer": "https://passport.example/"}),
                        ("GET", "/xiaozhi/ota/?from=mqtt_gateway", {"Referer": "https://passport.example/"}),
                        ("POST", f"/xiaozhi/ota/d/{syn}/?%74oken={q_syn}", {"Content-Type": "application/json"}),
                        ("GET", "/xiaozhi/ota/", {"Referer": f"https://passport.example/%78iaozhi/%6fta/%64/{syn}/"}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../", {}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../..", {}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e/", {}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e", {}),
                        ("GET", f"/%78iaozhi/ota/d/{syn}/../../", {}),
                        ("GET", f"/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn}/../../", {}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/..%2f../", {}),
                        ("GET", f"/%58iaozhi/%4fta/%44/{syn}/../../", {}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../../", {}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../../../xiaozhi/v1/", {}),
                        ("POST", f"/xiaozhi/ota/d/{syn}/../../../../mcp/vision/explain", {"Content-Type": "application/json"}),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../download/fw_1.0.bin", {}),
                    ):
                        st_cnt_bad, _ = _raw_http(
                            p_count,
                            method,
                            bad_path,
                            headers=bad_hdrs,
                            body=b"{}" if method == "POST" else None,
                            label="p_count",
                        )
                        assert st_cnt_bad == 400, f"Counting nginx failed to reject {method} {bad_path}: {st_cnt_bad}"
                    for onedot_ctrl in (
                        f"/xiaozhi/ota/d/{syn}/../",
                        f"/xiaozhi/ota/d/{syn}/..",
                        f"/xiaozhi/ota/d/{syn}/%2e%2e/",
                        f"/%78iaozhi/ota/d/{syn}/../",
                    ):
                        st_cnt_404, _ = _raw_http(p_count, "GET", onedot_ctrl, label="p_count")
                        assert st_cnt_404 == 404, f"Counting nginx single-dot negative control {onedot_ctrl} returned {st_cnt_404}"
                    with cnt_lock:
                        assert cnt_hits == [], f"Rejected/404 requests reached real nginx counting upstream: {cnt_hits}"

                    st_cnt_ota, _ = _raw_http(
                        p_count, "GET", "/xiaozhi/ota/", headers={"Referer": "https://passport.example/"}, label="p_count"
                    )
                    assert st_cnt_ota == 200, st_cnt_ota
                    st_cnt_ws, _ = _raw_http(
                        p_count, "GET", "/xiaozhi/v1/?from=mqtt_gateway", headers={"Referer": "https://passport.example/"}, label="p_count"
                    )
                    assert st_cnt_ws == 200, st_cnt_ws
                    st_cnt_dl, _ = _raw_http(
                        p_count, "GET", "/xiaozhi/ota/download/fw_1.0.bin", headers={"Referer": "https://passport.example/"}, label="p_count"
                    )
                    assert st_cnt_dl == 200, st_cnt_dl
                    st_cnt_sec, _ = _raw_http(
                        p_count,
                        "POST",
                        f"/xiaozhi/ota/d/{syn}/",
                        headers={
                            "Content-Type": "application/json",
                            "X-Original-URI": f"/xiaozhi/ota/d/{syn}/",
                            "Referer": "https://passport.example/",
                            "Authorization": f"Bearer {q_syn}",
                        },
                        body=b"{}",
                        label="p_count",
                    )
                    assert st_cnt_sec == 200, st_cnt_sec
                    with cnt_lock:
                        assert len(cnt_hits) == 4, f"Expected 4 forwarded hits on counting upstream, got {len(cnt_hits)}"
                        assert cnt_hits[0]["path"] == "/xiaozhi/ota/"
                        assert cnt_hits[1]["path"] == "/xiaozhi/v1/?from=mqtt_gateway"
                        assert cnt_hits[2]["path"] == "/xiaozhi/ota/download/fw_1.0.bin"
                        assert cnt_hits[3]["path"] == "/xiaozhi/ota/"
                        assert cnt_hits[3]["headers"].get("x-ota-secret") == syn
                        for scrubbed in ("authorization", "x-original-uri", "referer"):
                            assert scrubbed not in cnt_hits[3]["headers"], f"Counting upstream still saw {scrubbed}"
                        cnt_hits.clear()

                    # Scenario 1: Normal rejection & live OTA forwarding.
                    for ota_path in (f"/xiaozhi/ota/d/{dev_a['ota_secret']}/", f"/%78iaozhi/%6fta/%64/{dev_a['ota_secret']}/"):
                        st, raw = _raw_http(
                            p_live,
                            "POST",
                            ota_path,
                            headers={
                                "Content-Type": "application/json",
                                "Device-Id": dev_a["device_id"],
                                "Client-Id": dev_a["client_id"],
                                "X-Original-URI": ota_path,
                                "Referer": "https://proxy.example/",
                            },
                            body=b"{}",
                            label="p_live",
                        )
                        assert st == 200, f"Real nginx live OTA forward failed ({st}): {raw!r}"
                        tok = json.loads(raw.decode("utf-8"))["websocket"]["token"]
                        assert tok
                        issued_tokens.add(tok)
                        forbidden_all.add(tok)

                    st_get, _ = _raw_http(p_live, "GET", "/xiaozhi/ota/", label="p_live")
                    assert st_get == 200, st_get
                    st_ws_mqtt, _ = _raw_http(p_live, "GET", "/xiaozhi/v1/?from=mqtt_gateway", label="p_live")
                    assert st_ws_mqtt == 200, st_ws_mqtt
                    st_get_probe, _ = _raw_http(p_live, "GET", f"/xiaozhi/ota/?probe={benign_q}", label="p_live")
                    assert st_get_probe == 400, st_get_probe
                    for q_headers in (
                        {"Content-Type": "application/json"},
                        {"Content-Type": "application/json", "Referer": "https://passport.example/"},
                    ):
                        for q_path in (f"/xiaozhi/ota/?token={q_syn}", f"/xiaozhi/ota/?%74oken={q_syn}"):
                            st_q, _ = _raw_http(
                                p_live,
                                "POST",
                                q_path,
                                headers=q_headers,
                                body=b"{}",
                                label="p_live",
                            )
                            assert st_q == 400, (q_path, st_q)
                    st_ws_q, _ = _raw_http(
                        p_live,
                        "GET",
                        f"/xiaozhi/v1/?foo=1&API_KEY={q_syn}",
                        headers={"Referer": "https://passport.example/"},
                        label="p_live",
                    )
                    assert st_ws_q == 400, st_ws_q
                    st_vis_q, _ = _raw_http(
                        p_live,
                        "POST",
                        f"/mcp/vision/explain?secret={q_syn}",
                        headers={"Content-Type": "application/json", "Referer": "https://passport.example/"},
                        body=b"{}",
                        label="p_live",
                    )
                    assert st_vis_q == 400, st_vis_q

                    unsafe_referers = [
                        f"https://passport.example/xiaozhi/ota/d/{syn}/",
                        f"https://passport.example/xiaozhi%2Fota%2Fd%2F{syn}%2F",
                        f"https://passport.example/%78iaozhi/%6fta/%64/{syn}/",
                        f"https://passport.example/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn}/",
                        f"https://passport.example/xia%6fzhi/o%74a/%64/{syn}/",
                        f"https://passport.example/xia%4fzhi/O%54a/%44/{syn}/",
                        f"https://passport.example/xiaozhi/./foo/../ota//d/{syn}/",
                        f"https://u:{syn}@passport.example/",
                        f"https://passport.example/?token={q_syn}",
                        "https://passport.example/docs",
                    ]
                    for bad_ref in unsafe_referers:
                        for req_path in ("/xiaozhi/ota/", f"/xiaozhi/ota/d/{dev_a['ota_secret']}/", f"/%78iaozhi/%6fta/%64/{syn}/"):
                            st_ref, _ = _raw_http(
                                p_live,
                                "POST",
                                req_path,
                                headers={"Content-Type": "application/json", "Referer": bad_ref},
                                body=b"{}",
                                label="p_live",
                            )
                            assert st_ref == 400, f"Real nginx failed to reject Referer on {req_path}: {st_ref}"
                    st_ws_ref, _ = _raw_http(p_live, "GET", "/xiaozhi/v1/", headers={"Referer": unsafe_referers[3]}, label="p_live")
                    assert st_ws_ref == 400, st_ws_ref

                    # Scenario 2: Dead upstream (502), unsafe Referer rejections, and literal/encoded query rejections.
                    for bad_ref in unsafe_referers:
                        st_d_ref, _ = _raw_http(
                            p_dead,
                            "POST",
                            "/xiaozhi/ota/",
                            headers={"Content-Type": "application/json", "Referer": bad_ref},
                            body=b"{}",
                            label="p_dead",
                        )
                        assert st_d_ref == 400, st_d_ref
                    for bad_dead_method, bad_dead_path in (
                        ("POST", f"/xiaozhi/ota/?token={q_syn}"),
                        ("GET", f"/xiaozhi/ota/?%74oken={q_syn}"),
                        ("GET", f"/xiaozhi/ota/?%54oken={q_syn}"),
                        ("GET", f"/xiaozhi/v1/?from=mqtt_gateway&%74oken={q_syn}"),
                        ("GET", "/xiaozhi/v1/?FROM=MQTT_GATEWAY"),
                        ("POST", f"/xiaozhi/ota/d/{syn}/?%74oken={q_syn}"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../.."),
                        ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e/"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e"),
                        ("GET", f"/%78iaozhi/ota/d/{syn}/../../"),
                        ("GET", f"/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn}/../../"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../../"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../../../xiaozhi/v1/"),
                    ):
                        st_d_q, _ = _raw_http(
                            p_dead,
                            bad_dead_method,
                            bad_dead_path,
                            headers={"Content-Type": "application/json", "Referer": "https://passport.example/"},
                            body=b"{}" if bad_dead_method == "POST" else None,
                            label="p_dead",
                        )
                        assert st_d_q == 400, (bad_dead_method, bad_dead_path, st_d_q)
                    for onedot_dead in (f"/xiaozhi/ota/d/{syn}/../", f"/xiaozhi/ota/d/{syn}/.."):
                        st_d_404, _ = _raw_http(p_dead, "GET", onedot_dead, label="p_dead")
                        assert st_d_404 == 404, (onedot_dead, st_d_404)
                    st_502_safe, _ = _raw_http(
                        p_dead,
                        "POST",
                        "/xiaozhi/ota/",
                        headers={"Content-Type": "application/json", "Referer": "https://passport.example/"},
                        body=b"{}",
                        label="p_dead_502_safe",
                    )
                    assert st_502_safe == 502, st_502_safe
                    for sec_path in (f"/xiaozhi/ota/d/{syn}/", f"/%78iaozhi/%6fta/%64/{syn}/"):
                        st_502_sec, _ = _raw_http(
                            p_dead,
                            "POST",
                            sec_path,
                            headers={"Content-Type": "application/json"},
                            body=b"{}",
                            label="p_dead_502_secret",
                        )
                        assert st_502_sec == 502, st_502_sec
                    port_pool.assert_dead_ports_unreachable("real_nginx_after_502")

                    # Scenario 3: Access log write failure (/dev/full) + positive triggers + negative controls.
                    for label, fp, _ferr, method, path, ref, exp_code, _mtag in full_specs:
                        hdrs = {"Content-Type": "application/json"} if method == "POST" else {}
                        if ref is not None:
                            hdrs["Referer"] = ref
                        st_f, _ = _raw_http(
                            fp,
                            method,
                            path,
                            headers=hdrs,
                            body=b"{}" if method == "POST" else None,
                            label=f"full_{label}",
                        )
                        assert st_f == exp_code, f"/dev/full case {label} returned {st_f}, expected {exp_code}"

                    _wait_for_log_substring([cnt_acc], "/xiaozhi/ota/download/fw_1.0.bin")
                    _wait_for_log_substring([dead_err], "connect() failed")
                    _wait_for_log_substring([live_acc], "/xiaozhi/v1/?[REDACTED]")
                    if full_specs:
                        _wait_for_log_substring([tmp / "full_fixed_safe_pos.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_fixed_ws_mqtt_pos.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_neg_uncond_lit.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_neg_uncond_enc.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_neg_uncond_ota_q.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_neg_uncond_enc_q.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_neg_legacy_raw_q.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_neg_legacy_raw_q.log"], "connect() failed")
                        _wait_for_log_substring([tmp / "full_neg_legacy_path_twodot.log"], "[alert]")
                        _wait_for_log_substring([tmp / "full_neg_legacy_path_twodot.log"], "connect() failed")
                    time.sleep(0.15)
                finally:
                    proc.terminate()
                    _, nginx_stderr = proc.communicate(timeout=5)

                cnt_acc_lines = [ln for ln in cnt_acc.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
                cnt_err_txt = cnt_err.read_text(encoding="utf-8", errors="replace")
                live_acc_lines = [ln for ln in live_acc.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
                live_err_txt = live_err.read_text(encoding="utf-8", errors="replace")
                dead_acc_lines = [ln for ln in dead_acc.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
                dead_err_txt = dead_err.read_text(encoding="utf-8", errors="replace")
                global_err_txt = global_err.read_text(encoding="utf-8", errors="replace")

                assert len(cnt_acc_lines) == 3, f"Unexpected real nginx cnt_access.log lines: {cnt_acc_lines}"
                assert '"GET /xiaozhi/ota/ HTTP/1.1" 200' in cnt_acc_lines[0]
                assert '"GET /xiaozhi/v1/?[REDACTED] HTTP/1.1" 200' in cnt_acc_lines[1]
                assert '"GET /xiaozhi/ota/download/fw_1.0.bin HTTP/1.1" 200' in cnt_acc_lines[2]
                assert cnt_err_txt == "", f"Expected empty cnt_error.log, got: {redact_text(cnt_err_txt)}"

                assert len(live_acc_lines) == 2, f"Unexpected real nginx live_access.log lines: {live_acc_lines}"
                assert all('"-"' in ln for ln in live_acc_lines), live_acc_lines
                assert '"GET /xiaozhi/ota/ HTTP/1.1" 200' in live_acc_lines[0]
                assert '"GET /xiaozhi/v1/?[REDACTED] HTTP/1.1" 200' in live_acc_lines[1]
                assert live_err_txt == "", f"Expected empty live_error.log, got: {redact_text(live_err_txt)}"

                assert len(dead_acc_lines) == 1 and '"POST /xiaozhi/ota/ HTTP/1.1" 502' in dead_acc_lines[0], dead_acc_lines
                dead_err_lines = [ln for ln in dead_err_txt.splitlines() if ln.strip()]
                assert len(dead_err_lines) == 1 and 'referrer: "https://passport.example/"' in dead_err_lines[0], (
                    f"Unexpected dead_error.log: {redact_text(dead_err_txt)}"
                )
                assert f"127.0.0.1:{dead_port}" in dead_err_lines[0] and "Connection refused" in dead_err_lines[0], (
                    f"dead_error.log did not target held dead_port={dead_port}: {redact_text(dead_err_txt)}"
                )

                all_fixed_logs = [
                    "\n".join(cnt_acc_lines),
                    cnt_err_txt,
                    "\n".join(live_acc_lines),
                    live_err_txt,
                    "\n".join(dead_acc_lines),
                    dead_err_txt,
                    global_err_txt,
                ]
                for label, _fp, ferr, _m, _p, _r, _ec, mode_tag in full_specs:
                    ftxt = ferr.read_text(encoding="utf-8", errors="replace")
                    if mode_tag in ("fixed", "fixed_pos"):
                        all_fixed_logs.append(ftxt)
                        if mode_tag == "fixed_pos":
                            assert "[alert]" in ftxt and 'write() to "/dev/full" failed' in ftxt
                            assert 'referrer: "https://passport.example/"' in ftxt
                        else:
                            assert ftxt == "", (
                                f"/dev/full case {label} unexpectedly wrote to error_log: "
                                f"{ftxt.replace(syn, '[REDACTED]').replace(q_syn, '[REDACTED]').replace(benign_q, '[REDACTED]')}"
                            )
                    elif mode_tag == "neg_uncond":
                        expected_leak = q_syn if label in ("neg_uncond_ota_q", "neg_uncond_enc_q") else syn
                        assert "[alert]" in ftxt and 'write() to "/dev/full" failed' in ftxt and expected_leak in ftxt, (
                            f"Real nginx negative control {label} failed to reproduce [alert] leak"
                        )
                    elif mode_tag == "neg_legacy_raw_q":
                        assert "connect() failed" in ftxt and "[alert]" in ftxt and ftxt.count(q_syn) >= 2, (
                            f"Real nginx legacy-query negative control failed to leak in both connect() and [alert]: {ftxt!r}"
                        )
                    else:
                        assert mode_tag == "neg_legacy_path_twodot"
                        assert "connect() failed" in ftxt and "[alert]" in ftxt and ftxt.count(syn) >= 2, (
                            f"Real nginx legacy-path two-dot negative control failed to leak in both connect() and [alert]: {ftxt!r}"
                        )

                joined_fixed = "\n".join(all_fixed_logs)
                for secret_val in forbidden_all:
                    assert secret_val not in joined_fixed, "Real nginx log leaked secret!"
                assert "/xiaozhi/ota/d/" not in joined_fixed, "Real nginx log recorded /xiaozhi/ota/d/!"
                port_pool.assert_dead_ports_unreachable("real_nginx_end")
            except BaseException as exc:
                diag_files = {
                    "global_error": global_err,
                    "cnt_error": cnt_err,
                    "live_error": live_err,
                    "dead_error": dead_err,
                }
                for label, _fp, ferr, _m, _p, _r, _ec, _mt in full_specs:
                    if ferr.is_file() and ferr.stat().st_size > 0:
                        diag_files[f"full_{label}"] = ferr
                diag_path = _save_proxy_failure_diag(
                    "real-nginx",
                    port_map=port_pool.port_map(),
                    dead_hold_state=port_pool.dead_hold_state(),
                    last_response=last_response or None,
                    log_files=diag_files,
                    extra_logs={"nginx_stderr": nginx_stderr} if nginx_stderr else None,
                    forbidden_secrets=forbidden_all,
                    error=exc,
                )
                print(f"[DIAG] saved redacted real-nginx failure diagnostics to {diag_path}", file=sys.stderr)
                raise
    finally:
        cnt_srv.shutdown()
        cnt_srv.server_close()

    print(
        f"[PASS] real {nginx_ver} (loopback 127.0.0.1, {listen_port_count} distinct listen ports, "
        f"held dead_port={dead_port}, nginx -t rc=0): counting upstream zero-hit/forward, "
        f"502 upstream failure, and /dev/full={has_dev_full} access_log failure (Referer + literal/encoded query) "
        f"+ negative controls passed with zero secret leaks"
    )
    return issued_tokens


def _find_caddy_binary() -> Optional[Path]:
    """Locate an installed or user-space caddy binary without altering system state."""
    candidates: list[Path] = []
    if os.environ.get("PASSPORT_CADDY_BIN"):
        candidates.append(Path(os.environ["PASSPORT_CADDY_BIN"]))
    which_caddy = shutil.which("caddy")
    if which_caddy:
        candidates.append(Path(which_caddy))
    candidates.extend(
        [
            Path.home() / ".local" / "bin" / "caddy",
            Path.home() / ".local" / "passport-caddy" / "usr" / "bin" / "caddy",
            Path("/usr/local/bin/caddy"),
            Path("/usr/bin/caddy"),
            Path("/tmp/passport-caddy/caddy"),
            Path("/tmp/passport-caddy/usr/bin/caddy"),
        ]
    )
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def test_real_caddy_adapt_and_routing(ota_base: str, dev_a: dict) -> set[str]:
    """Run real `caddy adapt` and loopback `caddy run` acceptance with counting upstreams, 502 error log check, and host state isolation."""
    caddy_bin = _find_caddy_binary()
    if caddy_bin is None:
        print(
            "[INFO] real caddy binary unavailable on host/user-space; skipping real Caddy acceptance "
            "(in-process Caddyfile adapter/router model is NOT real Caddy acceptance)"
        )
        return set()

    ver_res = subprocess.run([str(caddy_bin), "version"], capture_output=True, text=True)
    caddy_ver = (ver_res.stdout or ver_res.stderr).strip()
    caddy_text = (ROOT / "proxy" / "Caddyfile.example").read_text(encoding="utf-8")
    host_before = _snapshot_host_caddy_state()

    cnt_http_srv, cnt_http_port, cnt_http_hits, cnt_http_lock = _start_counting_upstream()
    cnt_ws_srv, cnt_ws_port, cnt_ws_hits, cnt_ws_lock = _start_counting_upstream()
    syn = "realcaddy_ota_" + secrets.token_hex(12)
    q_syn = "realcaddy_q_" + secrets.token_hex(10)
    bearer_syn = "realcaddy_bearer_" + secrets.token_hex(10)
    benign_q = "realcaddy_benign_" + secrets.token_hex(8)
    forbidden_all = {syn, q_syn, bearer_syn, benign_q, dev_a["ota_secret"]}
    live_http_port = urlsplit(ota_base).port
    last_response: dict = {}

    try:
        with tempfile.TemporaryDirectory() as tmpdir, _ReservedPortPool() as port_pool:
            tmp = Path(tmpdir)
            if live_http_port is not None:
                port_pool.register_external("live_ota_http", live_http_port)
            port_pool.register_external("counting_http", cnt_http_port)
            port_pool.register_external("counting_ws", cnt_ws_port)
            dead_port = port_pool.reserve_dead("dead_upstream")
            live_port = port_pool.reserve_listen("caddy_live")
            dead_proxy_port = port_pool.reserve_listen("caddy_dead")
            port_pool.assert_all_disjoint("real_caddy_pre_adapt")

            live_acc_log = tmp / "caddy_live_access.log"
            dead_acc_log = tmp / "caddy_dead_access.log"
            err_log = tmp / "caddy_error.log"
            caddy_stderr = ""
            try:
                cf_path, caddy_env, iso_dirs = _prepare_real_caddy_fixture(
                    caddy_text,
                    tmp,
                    live_port=live_port,
                    counting_http_port=cnt_http_port,
                    counting_ws_port=cnt_ws_port,
                    dead_proxy_port=dead_proxy_port,
                    dead_port=dead_port,
                    live_acc_log=live_acc_log,
                    dead_acc_log=dead_acc_log,
                    err_log=err_log,
                )

                adapt_res = subprocess.run(
                    [str(caddy_bin), "adapt", "--config", str(cf_path), "--adapter", "caddyfile"],
                    env=caddy_env,
                    capture_output=True,
                    text=True,
                )
                assert adapt_res.returncode == 0, f"caddy adapt failed ({adapt_res.returncode}):\n{adapt_res.stderr}"
                adapted_json = json.loads(adapt_res.stdout)
                admin_cfg = adapted_json.get("admin") or {}
                assert admin_cfg.get("disabled") is True, f"Expected admin disabled in adapted JSON: {admin_cfg}"
                assert (admin_cfg.get("config") or {}).get("persist") is False, (
                    f"Expected admin.config.persist=false in adapted JSON: {admin_cfg}"
                )
                servers_json = (adapted_json.get("apps") or {}).get("http", {}).get("servers") or {}
                assert servers_json and all(srv.get("routes") for srv in servers_json.values()), (
                    f"Unexpected adapted Caddy servers/routes: {adapted_json}"
                )

                # Release listen placeholders right before starting Caddy; keep dead_port bound-unlistening throughout.
                port_pool.release_listen_ports()
                proc = subprocess.Popen(
                    [str(caddy_bin), "run", "--config", str(cf_path), "--adapter", "caddyfile"],
                    env=caddy_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    for wait_port in (live_port, dead_proxy_port):
                        deadline = time.monotonic() + 8.0
                        while time.monotonic() < deadline:
                            if proc.poll() is not None:
                                caddy_stderr = proc.stderr.read() if proc.stderr else ""
                                raise RuntimeError(
                                    f"Real caddy exited prematurely ({proc.returncode}): {caddy_stderr}"
                                )
                            try:
                                with socket.create_connection(("127.0.0.1", wait_port), timeout=0.5):
                                    break
                            except OSError:
                                time.sleep(0.05)
                        else:
                            raise TimeoutError(f"Real caddy port 127.0.0.1:{wait_port} did not become ready")

                    port_pool.assert_dead_ports_unreachable("real_caddy_after_start")

                    live_base = f"http://127.0.0.1:{live_port}"
                    dead_base = f"http://127.0.0.1:{dead_proxy_port}"

                    def _record_last(label: str, port: int, method: str, path: str, status: int, preview: str) -> None:
                        last_response.clear()
                        last_response.update(
                            {
                                "label": label,
                                "port": port,
                                "method": method,
                                "path": path,
                                "status": status,
                                "body_preview": preview[:512],
                            }
                        )

                    def _caddy_raw_http(
                        port: int,
                        method: str,
                        path: str,
                        *,
                        headers: Optional[dict[str, str]] = None,
                        body: Optional[bytes] = None,
                        label: str = "",
                    ) -> int:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            hdrs = {"Connection": "close", **(headers or {})}
                            conn.request(method, path, body=body, headers=hdrs)
                            resp = conn.getresponse()
                            data = resp.read()
                            _record_last(
                                label or str(port),
                                port,
                                method,
                                path,
                                resp.status,
                                data.decode("utf-8", "replace"),
                            )
                            return resp.status
                        finally:
                            conn.close()

                    def _caddy_post_json(base_url: str, route: str, hdrs: dict, *, label: str) -> tuple[int, dict]:
                        port = urlsplit(base_url).port or 0
                        st, body = post_json(f"{base_url}{route}", hdrs)
                        _record_last(label, port, "POST", route, st, json.dumps(body, ensure_ascii=False))
                        return st, body

                    def _caddy_get_status(base_url: str, route: str, *, label: str) -> int:
                        port = urlsplit(base_url).port or 0
                        try:
                            with urllib.request.urlopen(f"{base_url}{route}", timeout=5) as resp:
                                raw = resp.read().decode("utf-8", "replace")
                                _record_last(label, port, "GET", route, resp.status, raw)
                                return resp.status
                        except urllib.error.HTTPError as exc:
                            raw = exc.read().decode("utf-8", "replace")
                            _record_last(label, port, "GET", route, exc.code, raw)
                            return exc.code

                    # 1. All literal, uppercase, percent-encoded credential queries, unexpected queries,
                    #    and non-canonical OTA traversal paths must be rejected at the proxy (400 / 404)
                    #    with ZERO hits on both counting upstreams.
                    for qk in sorted(SENSITIVE_QUERY_KEYS):
                        enc_l = f"%{ord(qk[0].lower()):02x}{qk[1:]}"
                        enc_u = f"%{ord(qk[0].upper()):02X}{qk[1:]}"
                        for q_pair in (
                            f"{qk}={q_syn}",
                            f"{qk.upper()}={q_syn}",
                            f"{enc_l}={q_syn}",
                            f"{enc_u}={q_syn}",
                            f"from=mqtt_gateway&{enc_l}={q_syn}",
                        ):
                            for route_path in (
                                "/xiaozhi/ota/",
                                f"/xiaozhi/ota/d/{syn}/",
                                "/mcp/vision/explain",
                                "/xiaozhi/v1/",
                            ):
                                st_cq, _ = _caddy_post_json(
                                    live_base,
                                    f"{route_path}?{q_pair}",
                                    {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
                                    label="caddy_live",
                                )
                                assert st_cq == 400, f"Real caddy failed to reject {route_path}?{q_pair}: {st_cq}"
                    for bad_get in (
                        f"/xiaozhi/ota/?%74oken={q_syn}",
                        f"/xiaozhi/ota/?%54oken={q_syn}",
                        f"/xiaozhi/ota/?probe={benign_q}",
                        "/xiaozhi/ota/?from=mqtt_gateway",
                        "/xiaozhi/v1/?%66rom=mqtt_gateway",
                        "/xiaozhi/v1/?FROM=MQTT_GATEWAY",
                    ):
                        st_bg = _caddy_get_status(live_base, bad_get, label="caddy_live")
                        assert st_bg == 400, f"Real caddy returned {st_bg} for GET {bad_get}"
                    for raw_method, raw_trav in (
                        ("GET", f"/xiaozhi/ota/d/{syn}/.."),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../.."),
                        ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e/"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/%2e%2e/%2e%2e"),
                        ("GET", f"/%78iaozhi/ota/d/{syn}/../../"),
                        ("GET", f"/%78%69%61%6f%7a%68%69/%6f%74%61/%64/{syn}/../../"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/..%2f../"),
                        ("GET", f"/%58iaozhi/%4fta/%44/{syn}/../../"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../../"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../../../xiaozhi/v1/"),
                        ("POST", f"/xiaozhi/ota/d/{syn}/../../../../mcp/vision/explain"),
                        ("GET", f"/xiaozhi/ota/d/{syn}/../../download/fw_1.0.bin"),
                    ):
                        st_trav = _caddy_raw_http(
                            live_port,
                            raw_method,
                            raw_trav,
                            headers={"Content-Type": "application/json"} if raw_method == "POST" else None,
                            body=b"{}" if raw_method == "POST" else None,
                            label="caddy_live",
                        )
                        assert st_trav == 400, f"Real caddy failed to reject traversal {raw_method} {raw_trav}: {st_trav}"
                    for raw_onedot in (
                        f"/xiaozhi/ota/d/{syn}/../",
                        f"/xiaozhi/ota/d/{syn}/%2e%2e/",
                        f"/%78iaozhi/ota/d/{syn}/../",
                    ):
                        st_404 = _caddy_raw_http(live_port, "GET", raw_onedot, label="caddy_live")
                        assert st_404 == 404, f"Real caddy single-dot negative control {raw_onedot} returned {st_404}"
                    with cnt_http_lock:
                        assert cnt_http_hits == [], f"Rejected requests hit Caddy HTTP counting upstream: {cnt_http_hits}"
                    with cnt_ws_lock:
                        assert cnt_ws_hits == [], f"Rejected requests hit Caddy WS counting upstream: {cnt_ws_hits}"

                    # 2. Normal permitted requests must actually forward to the counting upstreams.
                    assert _caddy_get_status(live_base, "/xiaozhi/ota/", label="caddy_live") == 200
                    assert _caddy_get_status(live_base, "/xiaozhi/ota/download/fw_1.0.bin", label="caddy_live") == 200
                    st_sec, _ = _caddy_post_json(
                        live_base,
                        f"/xiaozhi/ota/d/{syn}/",
                        {
                            "Device-Id": dev_a["device_id"],
                            "Client-Id": dev_a["client_id"],
                            "X-Original-URI": f"/xiaozhi/ota/d/{syn}/",
                            "Referer": f"https://proxy.example/xiaozhi/ota/d/{syn}/",
                            "Authorization": f"Bearer {bearer_syn}",
                        },
                        label="caddy_live",
                    )
                    assert st_sec == 200, st_sec
                    st_sec_enc, _ = _caddy_post_json(
                        live_base,
                        f"/%78iaozhi/%6fta/%64/{syn}/",
                        {"Device-Id": dev_a["device_id"], "Client-Id": dev_a["client_id"]},
                        label="caddy_live",
                    )
                    assert st_sec_enc == 200, st_sec_enc
                    st_extra_404, _ = _caddy_post_json(live_base, f"/xiaozhi/ota/d/{syn}/extra", {}, label="caddy_live")
                    assert st_extra_404 == 404, st_extra_404
                    assert _caddy_get_status(live_base, "/xiaozhi/v1/?from=mqtt_gateway", label="caddy_live") == 200

                    with cnt_http_lock:
                        assert len(cnt_http_hits) == 4, f"Expected 4 HTTP upstream hits, got {cnt_http_hits}"
                        assert cnt_http_hits[0]["path"] == "/xiaozhi/ota/"
                        assert cnt_http_hits[1]["path"] == "/xiaozhi/ota/download/fw_1.0.bin"
                        assert cnt_http_hits[2]["path"] == "/xiaozhi/ota/"
                        assert cnt_http_hits[2]["headers"].get("x-ota-secret") == syn
                        for scrubbed in ("authorization", "x-original-uri", "referer"):
                            assert scrubbed not in cnt_http_hits[2]["headers"], f"Caddy leaked {scrubbed} upstream"
                        assert cnt_http_hits[3]["path"] == "/xiaozhi/ota/"
                        assert cnt_http_hits[3]["headers"].get("x-ota-secret") == syn
                    with cnt_ws_lock:
                        assert len(cnt_ws_hits) == 1 and cnt_ws_hits[0]["path"] == "/xiaozhi/v1/?from=mqtt_gateway"

                    # 3. Dead upstream site: disallowed query & traversal paths return 400 (no 502),
                    #    single-dot returns 404, while valid requests trigger real 502.
                    st_dead_q = _caddy_get_status(dead_base, f"/xiaozhi/ota/?%74oken={q_syn}", label="caddy_dead")
                    assert st_dead_q == 400, f"Expected 400 on dead Caddy site ?%74oken, got {st_dead_q}"
                    for dead_trav in (
                        f"/xiaozhi/ota/d/{syn}/../../",
                        f"/xiaozhi/ota/d/{syn}/..",
                        f"/%78iaozhi/ota/d/{syn}/../../",
                    ):
                        assert _caddy_raw_http(dead_proxy_port, "GET", dead_trav, label="caddy_dead") == 400, dead_trav
                    assert _caddy_raw_http(dead_proxy_port, "GET", f"/xiaozhi/ota/d/{syn}/../", label="caddy_dead") == 404
                    st_502_sec, _ = _caddy_post_json(
                        dead_base,
                        f"/xiaozhi/ota/d/{syn}/",
                        {
                            "Referer": f"https://proxy.example/xiaozhi/ota/d/{syn}/",
                            "Authorization": f"Bearer {bearer_syn}",
                        },
                        label="caddy_dead_502_secret",
                    )
                    assert st_502_sec == 502, st_502_sec
                    st_502_ota, _ = _caddy_post_json(
                        dead_base,
                        "/xiaozhi/ota/",
                        {"Referer": f"https://proxy.example/xiaozhi/ota/d/{syn}/"},
                        label="caddy_dead_502_ota",
                    )
                    assert st_502_ota == 502, st_502_ota
                    st_502_ws = _caddy_get_status(dead_base, "/xiaozhi/v1/?from=mqtt_gateway", label="caddy_dead_502_ws")
                    assert st_502_ws == 502, f"Expected 502 on dead Caddy WS route, got {st_502_ws}"
                    port_pool.assert_dead_ports_unreachable("real_caddy_after_502")

                    _wait_for_log_substring([err_log], "502")
                    _wait_for_log_substring([live_acc_log], "[REDACTED]")
                    _wait_for_log_substring([dead_acc_log], "[REDACTED]")
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    _, caddy_stderr = proc.communicate(timeout=5)

                # 4. Error & access log files MUST exist, be non-empty, and be strictly redacted.
                assert err_log.is_file() and err_log.stat().st_size > 0, (
                    f"Expected non-empty Caddy error log at {err_log}"
                )
                assert live_acc_log.is_file() and live_acc_log.stat().st_size > 0, (
                    f"Expected non-empty Caddy live access log at {live_acc_log}"
                )
                assert dead_acc_log.is_file() and dead_acc_log.stat().st_size > 0, (
                    f"Expected non-empty Caddy dead access log at {dead_acc_log}"
                )

                err_records = [json.loads(ln) for ln in err_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
                assert any(
                    str(r.get("logger", "")).startswith("http.log.error")
                    and r.get("status") == 502
                    and f"127.0.0.1:{dead_port}" in str(r.get("msg", ""))
                    and "connection refused" in str(r.get("msg", "")).lower()
                    for r in err_records
                ), f"Caddy error log missing 502 record targeting held dead_port={dead_port}: {err_records}"
                for rec in err_records:
                    req_obj = rec.get("request")
                    if isinstance(req_obj, dict):
                        assert req_obj.get("uri") == "[REDACTED]", f"Unredacted request.uri in Caddy err_log: {rec}"
                        assert req_obj.get("orig_uri", "[REDACTED]") == "[REDACTED]", (
                            f"Unredacted request.orig_uri in Caddy err_log: {rec}"
                        )
                        hdrs = req_obj.get("headers") or {}
                        for hk in ("Authorization", "X-Ota-Secret", "Referer", "X-Original-Uri"):
                            if hk in hdrs:
                                assert hdrs[hk] == "[REDACTED]", f"Unredacted {hk} in Caddy err_log: {rec}"

                live_acc_records = [
                    json.loads(ln) for ln in live_acc_log.read_text(encoding="utf-8").splitlines() if ln.strip()
                ]
                assert len(live_acc_records) == 3, (
                    f"Expected 3 redacted live access records (OTA/d & 400 skipped), got {len(live_acc_records)}"
                )
                for rec in live_acc_records:
                    assert rec["request"]["uri"] == "[REDACTED]"

                dead_acc_records = [
                    json.loads(ln) for ln in dead_acc_log.read_text(encoding="utf-8").splitlines() if ln.strip()
                ]
                assert len(dead_acc_records) == 2, (
                    f"Expected 2 redacted dead access records (OTA/d & 400 skipped), got {len(dead_acc_records)}"
                )

                joined = "\n".join(
                    [
                        err_log.read_text(encoding="utf-8", errors="replace"),
                        live_acc_log.read_text(encoding="utf-8", errors="replace"),
                        dead_acc_log.read_text(encoding="utf-8", errors="replace"),
                        caddy_stderr,
                    ]
                )
                assert "http.log.error" not in caddy_stderr and "http.handlers.reverse_proxy" not in caddy_stderr, (
                    "Caddy stderr unexpectedly captured error/reverse_proxy loggers"
                )
                for secret_val in forbidden_all:
                    assert secret_val not in joined, "Real caddy log/stderr leaked secret!"
                assert "/xiaozhi/ota/d/" not in joined, "Real caddy log/stderr recorded /xiaozhi/ota/d/!"
                port_pool.assert_dead_ports_unreachable("real_caddy_end")

                # 5. Persistence must remain disabled and host Caddy state directories untouched.
                assert not (iso_dirs["xdg_config"] / "caddy" / "autosave.json").exists(), (
                    "persist_config off failed: autosave.json written to isolated XDG_CONFIG_HOME"
                )
                assert not (iso_dirs["home"] / ".config" / "caddy" / "autosave.json").exists(), (
                    "persist_config off failed: autosave.json written to isolated HOME"
                )
                _assert_host_caddy_state_unchanged(host_before, "post-real-caddy acceptance")
            except BaseException as exc:
                diag_path = _save_proxy_failure_diag(
                    "real-caddy",
                    port_map=port_pool.port_map(),
                    dead_hold_state=port_pool.dead_hold_state(),
                    last_response=last_response or None,
                    log_files={
                        "caddy_error": err_log,
                        "caddy_live_access": live_acc_log,
                        "caddy_dead_access": dead_acc_log,
                    },
                    extra_logs={"caddy_stderr": caddy_stderr} if caddy_stderr else None,
                    forbidden_secrets=forbidden_all,
                    error=exc,
                )
                print(f"[DIAG] saved redacted real-caddy failure diagnostics to {diag_path}", file=sys.stderr)
                raise
    finally:
        cnt_http_srv.shutdown()
        cnt_http_srv.server_close()
        cnt_ws_srv.shutdown()
        cnt_ws_srv.server_close()

    print(
        f"[PASS] real {caddy_ver} (loopback 127.0.0.1, distinct listen ports {live_port}/{dead_proxy_port}, "
        f"held dead_port={dead_port}, caddy adapt rc=0): counting upstream zero-hit/forward, "
        f"502 redacted error log, and host persistence isolation verified"
    )
    return set()


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


def test_auto_realtime_asr_cancel_unit(server_home: Path) -> None:
    """Verify auto/realtime VAD ASR shares connection-scoped task dispatch, abort/close cancel, and barge-in safety."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        srv_home = _make_srv_home(server_home, tmp / "asr_cancel_srv_home")
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
                "aa:bb:cc:dd:ee:77",
                "--client-id",
                "asr-cancel-client",
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
                PASSPORT_FAKE_BASE="http://127.0.0.1:18019",
            ),
            check=True,
            capture_output=True,
            text=True,
        )

        probe_code = """
import asyncio, os, sys, time

os.chdir(os.environ["XIAOZHI_HOME"])
for p in (os.environ["PASSPORT_ROOT"], os.environ["XIAOZHI_HOME"]):
    if p not in sys.path:
        sys.path.insert(0, p)

from config.config_loader import load_config
import core.handle.abortHandle as abort_handle
import core.handle.receiveAudioHandle as receive_audio_handle
import core.handle.reportHandle as report_handle
import core.handle.textHandler.abortMessageHandler as abort_msg_handler

events_log = []

def spy_enqueue_asr_report(conn, text, opus_data):
    events_log.append(("enqueue", conn.client_listen_mode, text))

async def spy_start_to_chat(conn, text):
    if conn.client_is_speaking and conn.client_listen_mode != "manual":
        await abort_handle.handleAbortMessage(conn)
    events_log.append(("chat", conn.client_listen_mode, text))

receive_audio_handle.startToChat = spy_start_to_chat
report_handle.enqueue_asr_report = spy_enqueue_asr_report

from passport_server.patches import apply_all_patches
apply_all_patches()

from core.connection import ConnectionHandler
from core.providers.asr.base import ASRProviderBase
from core.providers.asr.dto.dto import InterfaceType

class FakeWS:
    def __init__(self):
        self.closed = False
        self.sent = []
    async def send(self, msg):
        self.sent.append(msg)
    async def close(self):
        self.closed = True

class SpyVAD:
    def __init__(self, next_voice=False):
        self.calls = 0
        self.next_voice = next_voice
        self.released = 0
    def is_vad(self, conn, pcm_frame):
        self.calls += 1
        if self.next_voice:
            conn.client_have_voice = True
        return self.next_voice
    def release_conn_resources(self, conn):
        self.released += 1
        for attr in ("_vad_state", "_vad_context"):
            if hasattr(conn, attr):
                delattr(conn, attr)

class ControllableASR(ASRProviderBase):
    def __init__(self, output_dir):
        super().__init__()
        self.interface_type = InterfaceType.NON_STREAM
        self.output_dir = output_dir
        self.delete_audio_file = True
        self.started = None
        self.cancelled = None
        self.release = None
        self.swallow_cancel = False
        self.next_text = "ok"
        self.call_count = 0

    async def speech_to_text(self, opus_data, session_id, artifacts=None):
        self.call_count += 1
        return self.next_text, None

    async def speech_to_text_wrapper(self, pcm_data, session_id):
        self.call_count += 1
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                if self.cancelled is not None:
                    self.cancelled.set()
                if not self.swallow_cancel:
                    raise
        return self.next_text, None

async def run():
    cfg = await load_config()
    cfg["delete_audio"] = True
    pcm_chunk = b"\\x01\\x00" * 1920 * 16  # > 1920 * 15 threshold

    for mode in ("auto", "realtime"):
        # 1. Abort cancels in-flight VAD-triggered ASR immediately and clears registration.
        asr = ControllableASR(os.environ["TEST_AUDIO_OUT"])
        asr.started = asyncio.Event()
        asr.cancelled = asyncio.Event()
        asr.release = asyncio.Event()
        asr.next_text = f"STALE_{mode.upper()}_ABORT"
        conn = ConnectionHandler(cfg, None, asr, None, None, None)
        conn.loop = asyncio.get_running_loop()
        conn.asr = asr
        conn.websocket = FakeWS()
        conn.client_listen_mode = mode
        conn.asr_audio = [pcm_chunk]
        conn.client_have_voice = True
        conn.client_voice_stop = True
        events_log.clear()

        t0 = time.monotonic()
        await asr.receive_audio(conn, b"\\x00" * 1920, False)
        assert time.monotonic() - t0 < 0.2, f"{mode} receive_audio blocked on ASR"
        task = conn._passport_asr_task
        assert task is not None and not task.done(), f"{mode} ASR task not registered"
        await asyncio.wait_for(asr.started.wait(), 1.0)
        await abort_handle.handleAbortMessage(conn)
        await asyncio.wait_for(asr.cancelled.wait(), 1.0)
        await asyncio.sleep(0.02)
        assert task.done() and conn._passport_asr_task is None
        assert events_log == [], f"{mode} aborted ASR leaked to report/chat: {events_log}"
        await conn.close()

        # 2. Even if a provider swallows cancellation and returns after abort, stale generation blocks STT/LLM.
        asr_sw = ControllableASR(os.environ["TEST_AUDIO_OUT"])
        asr_sw.started = asyncio.Event()
        asr_sw.cancelled = asyncio.Event()
        asr_sw.release = asyncio.Event()
        asr_sw.swallow_cancel = True
        asr_sw.next_text = f"SWALLOWED_{mode.upper()}"
        conn_sw = ConnectionHandler(cfg, None, asr_sw, None, None, None)
        conn_sw.loop = asyncio.get_running_loop()
        conn_sw.asr = asr_sw
        conn_sw.websocket = FakeWS()
        conn_sw.client_listen_mode = mode
        conn_sw.asr_audio = [pcm_chunk]
        conn_sw.client_have_voice = True
        conn_sw.client_voice_stop = True
        events_log.clear()

        await asr_sw.receive_audio(conn_sw, b"\\x00" * 1920, False)
        sw_task = conn_sw._passport_asr_task
        await asyncio.wait_for(asr_sw.started.wait(), 1.0)
        await abort_handle.handleAbortMessage(conn_sw)
        await asyncio.wait_for(asr_sw.cancelled.wait(), 1.0)
        await asyncio.wait_for(sw_task, 1.0)
        assert events_log == [], f"{mode} stale swallowed result entered report/chat: {events_log}"
        await conn_sw.close()

        # 3. Close cancels in-flight VAD-triggered ASR and blocks post-close dispatches.
        asr_cl = ControllableASR(os.environ["TEST_AUDIO_OUT"])
        asr_cl.started = asyncio.Event()
        asr_cl.cancelled = asyncio.Event()
        asr_cl.release = asyncio.Event()
        asr_cl.next_text = f"STALE_{mode.upper()}_CLOSE"
        conn_cl = ConnectionHandler(cfg, None, asr_cl, None, None, None)
        conn_cl.loop = asyncio.get_running_loop()
        conn_cl.asr = asr_cl
        conn_cl.websocket = FakeWS()
        conn_cl.client_listen_mode = mode
        conn_cl.asr_audio = [pcm_chunk]
        conn_cl.client_have_voice = True
        conn_cl.client_voice_stop = True
        events_log.clear()

        await asr_cl.receive_audio(conn_cl, b"\\x00" * 1920, False)
        cl_task = conn_cl._passport_asr_task
        assert cl_task is not None
        await asyncio.wait_for(asr_cl.started.wait(), 1.0)
        await conn_cl.close()
        assert asr_cl.cancelled.is_set() and cl_task.done()
        assert conn_cl._passport_asr_task is None and conn_cl.stop_event.is_set()
        assert events_log == [], f"{mode} closed ASR leaked to report/chat: {events_log}"

        # Post-close receive_audio must not spawn new tasks.
        conn_cl.asr_audio = [pcm_chunk]
        conn_cl.client_have_voice = True
        conn_cl.client_voice_stop = True
        await asr_cl.receive_audio(conn_cl, b"\\x00" * 1920, False)
        assert conn_cl._passport_asr_task is None

        # 4. Barge-in when client_is_speaking=True must NOT self-cancel the winning ASR task
        #    or discard newly buffered/queued audio.
        asr_bi = ControllableASR(os.environ["TEST_AUDIO_OUT"])
        asr_bi.next_text = f"BARGE_IN_{mode.upper()}"
        conn_bi = ConnectionHandler(cfg, None, asr_bi, None, None, None)
        conn_bi.loop = asyncio.get_running_loop()
        conn_bi.asr = asr_bi
        conn_bi.websocket = FakeWS()
        conn_bi.client_listen_mode = mode
        conn_bi.client_is_speaking = True
        conn_bi.asr_audio = [pcm_chunk]
        conn_bi.client_have_voice = True
        conn_bi.client_voice_stop = True
        events_log.clear()

        await asr_bi.receive_audio(conn_bi, b"\\x00" * 1920, False)
        bi_task = conn_bi._passport_asr_task
        assert bi_task is not None
        conn_bi.asr_audio.append(b"\\x02\\x00" * 960)
        conn_bi.asr_audio_queue.put(b"\\x03\\x00" * 960)
        epoch_before_bi = conn_bi._passport_audio_epoch
        await asyncio.wait_for(bi_task, 1.0)
        assert events_log == [
            ("enqueue", mode, f"BARGE_IN_{mode.upper()}"),
            ("chat", mode, f"BARGE_IN_{mode.upper()}"),
        ], f"{mode} barge-in self-cancelled winning ASR task: {events_log}"
        assert conn_bi.websocket.sent, "barge-in did not send tts.stop before chat"
        assert conn_bi._passport_audio_epoch == epoch_before_bi
        assert len(conn_bi.asr_audio) == 1 and not conn_bi.asr_audio_queue.empty()
        await conn_bi.close()

        # 5. Pre-VAD abort (before sentence end, no ASR task yet) clears buffers, resets VAD state,
        #    invalidates queued + pre-popped frames, blocks stale silence dispatch, and allows recovery.
        asr_pre = ControllableASR(os.environ["TEST_AUDIO_OUT"])
        asr_pre.next_text = f"STALE_PRE_VAD_{mode.upper()}"
        conn_pre = ConnectionHandler(cfg, None, asr_pre, None, None, None)
        conn_pre.loop = asyncio.get_running_loop()
        conn_pre.vad = SpyVAD(next_voice=False)
        conn_pre.asr = asr_pre
        conn_pre.websocket = FakeWS()
        conn_pre.client_listen_mode = mode
        conn_pre.asr_audio = [b"\\x01\\x00" * 960 for _ in range(17)]  # 32,640 bytes > 28,800
        conn_pre.client_have_voice = True
        conn_pre.client_voice_stop = False
        conn_pre.client_audio_buffer.extend(b"\\x02\\x00" * 200)
        conn_pre.client_voice_window.append(True)
        conn_pre._vad_state = "stale"
        conn_pre._vad_context = "stale"
        assert conn_pre._passport_asr_task is None
        conn_pre.asr_audio_queue.put(b"\\x05\\x00" * 960)
        conn_pre.asr_audio_queue.put(b"\\x06\\x00" * 960)
        pre_popped = conn_pre.asr_audio_queue.get_nowait()
        events_log.clear()

        await abort_handle.handleAbortMessage(conn_pre)
        assert conn_pre.asr_audio == [], conn_pre.asr_audio
        assert conn_pre.client_have_voice is False
        assert conn_pre.client_voice_stop is False
        assert len(conn_pre.client_audio_buffer) == 0
        assert len(conn_pre.client_voice_window) == 0
        assert conn_pre.asr_audio_queue.empty()
        assert not hasattr(conn_pre, "_vad_state") and not hasattr(conn_pre, "_vad_context")
        assert conn_pre.vad.released == 1
        assert conn_pre._passport_audio_epoch == 1
        assert conn_pre._passport_asr_task is None

        # Stale frame already popped before abort must be ignored on event loop.
        await receive_audio_handle.handleAudioMessage(conn_pre, pre_popped)
        assert conn_pre.vad.calls == 0
        assert conn_pre.asr_audio == []

        # Subsequent silence / voice_stop must NOT dispatch stale ASR or trigger report/chat.
        conn_pre.client_voice_stop = True
        await asr_pre.receive_audio(conn_pre, b"\\x00" * 1920, False)
        assert conn_pre._passport_asr_task is None
        assert asr_pre.call_count == 0
        assert events_log == [], f"{mode} pre-VAD abort leaked to report/chat: {events_log}"

        # Also verify abortMessageHandler path directly on queued/buffered state.
        conn_pre.client_voice_stop = False
        conn_pre.asr_audio = [b"\\x07\\x00" * 960 for _ in range(17)]
        conn_pre.client_have_voice = True
        conn_pre.asr_audio_queue.put(b"\\x08\\x00" * 960)
        await abort_msg_handler.handleAbortMessage(conn_pre)
        assert conn_pre.asr_audio == [] and conn_pre.client_have_voice is False
        assert conn_pre.asr_audio_queue.empty() and conn_pre._passport_audio_epoch == 2

        # Fresh audio after pre-VAD abort on the SAME connection completes cleanly.
        asr_pre.next_text = f"FRESH_{mode.upper()}_POST_ABORT"
        conn_pre.vad.next_voice = True
        conn_pre.asr_audio_queue.put(b"\\x09\\x00" * 960)
        fresh_frame = conn_pre.asr_audio_queue.get_nowait()
        await receive_audio_handle.handleAudioMessage(conn_pre, fresh_frame)
        assert conn_pre.vad.calls == 1 and len(conn_pre.asr_audio) == 1
        conn_pre.asr_audio.append(pcm_chunk)
        conn_pre.client_voice_stop = True
        await asr_pre.receive_audio(conn_pre, b"\\x00" * 1920, False)
        assert conn_pre._passport_asr_task is not None
        await asyncio.wait_for(conn_pre._passport_asr_task, 1.0)
        assert asr_pre.call_count == 1
        assert events_log == [
            ("enqueue", mode, f"FRESH_{mode.upper()}_POST_ABORT"),
            ("chat", mode, f"FRESH_{mode.upper()}_POST_ABORT"),
        ], f"{mode} post-abort recovery failed: {events_log}"
        await conn_pre.close()

        # 6. Pre-VAD disconnect (conn.close() before VAD sentence end) discards buffers & queued/pre-popped frames.
        asr_pre_cl = ControllableASR(os.environ["TEST_AUDIO_OUT"])
        asr_pre_cl.next_text = f"STALE_PRE_VAD_{mode.upper()}_CLOSE"
        conn_pre_cl = ConnectionHandler(cfg, None, asr_pre_cl, None, None, None)
        conn_pre_cl.loop = asyncio.get_running_loop()
        conn_pre_cl.vad = SpyVAD(next_voice=False)
        conn_pre_cl.asr = asr_pre_cl
        conn_pre_cl.websocket = FakeWS()
        conn_pre_cl.client_listen_mode = mode
        conn_pre_cl.asr_audio = [b"\\x0a\\x00" * 960 for _ in range(17)]
        conn_pre_cl.client_have_voice = True
        conn_pre_cl.client_voice_stop = False
        conn_pre_cl._vad_state = "stale"
        conn_pre_cl.asr_audio_queue.put(b"\\x0b\\x00" * 960)
        conn_pre_cl.asr_audio_queue.put(b"\\x0c\\x00" * 960)
        pre_popped_cl = conn_pre_cl.asr_audio_queue.get_nowait()
        events_log.clear()

        await conn_pre_cl.close()
        assert conn_pre_cl.stop_event.is_set()
        assert conn_pre_cl.asr_audio == [] and conn_pre_cl.client_have_voice is False
        assert conn_pre_cl.asr_audio_queue.empty()
        assert not hasattr(conn_pre_cl, "_vad_state")
        assert conn_pre_cl._passport_asr_task is None
        await receive_audio_handle.handleAudioMessage(conn_pre_cl, pre_popped_cl)
        conn_pre_cl.client_voice_stop = True
        await asr_pre_cl.receive_audio(conn_pre_cl, b"\\x00" * 1920, False)
        assert conn_pre_cl.vad.calls == 0 and asr_pre_cl.call_count == 0 and events_log == []

        # 7. Server-side AEC barge-in inside handleAudioMessage sends tts.stop without wiping new speech.
        asr_aec = ControllableASR(os.environ["TEST_AUDIO_OUT"])
        conn_aec = ConnectionHandler(cfg, None, asr_aec, None, None, None)
        conn_aec.loop = asyncio.get_running_loop()
        conn_aec.vad = SpyVAD(next_voice=True)
        conn_aec.asr = asr_aec
        conn_aec.websocket = FakeWS()
        conn_aec.client_listen_mode = mode
        conn_aec.client_aec = True
        conn_aec.client_is_speaking = True
        conn_aec.asr_audio_queue.put(b"\\x0d\\x00" * 960)
        await receive_audio_handle.handleAudioMessage(conn_aec, b"\\x0e\\x00" * 960)
        assert conn_aec.websocket.sent, f"{mode} AEC barge-in did not send tts.stop"
        assert conn_aec.client_have_voice is True
        assert len(conn_aec.asr_audio) == 1
        assert conn_aec._passport_audio_epoch == 0
        assert not conn_aec.asr_audio_queue.empty()
        await conn_aec.close()

asyncio.run(run())
"""
        res = subprocess.run(
            [sys.executable, "-c", probe_code],
            env=_base_env(
                XIAOZHI_HOME=str(srv_home),
                PASSPORT_ROOT=str(ROOT),
                PASSPORT_LOG_DIR=str(srv_home / "tmp"),
                TEST_AUDIO_OUT=str(tmp / "asr_out"),
            ),
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert res.returncode == 0, (
            f"auto/realtime ASR unit cancel probe failed ({res.returncode}):\n{res.stdout}\n{res.stderr}"
        )
    print(
        "[PASS] auto/realtime ASR unit cancellation, pre-VAD abort/close discard, "
        "stale-gen guard, close guard, and barge-in safety verified"
    )


def test_manual_listen_stop_queue_ordering_unit(server_home: Path) -> None:
    """Verify manual listen.stop is strictly ordered behind queued/in-flight PCM and invalidated on abort/close/new turn."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        srv_home = _make_srv_home(server_home, tmp / "manual_stop_order_srv_home")
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
                "aa:bb:cc:dd:ee:88",
                "--client-id",
                "manual-stop-order-client",
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
                PASSPORT_FAKE_BASE="http://127.0.0.1:18019",
            ),
            check=True,
            capture_output=True,
            text=True,
        )

        probe_code = """
import asyncio, json, math, os, queue, struct, sys, threading, time
import opuslib_next
from opuslib_next import constants

os.chdir(os.environ["XIAOZHI_HOME"])
for p in (os.environ["PASSPORT_ROOT"], os.environ["XIAOZHI_HOME"]):
    if p not in sys.path:
        sys.path.insert(0, p)

from config.config_loader import load_config
import core.handle.receiveAudioHandle as receive_audio_handle
import core.providers.asr.base as asr_base
from passport_server.patches import apply_all_patches

apply_all_patches()

from core.connection import ConnectionHandler
from core.handle.textHandler.listenMessageHandler import ListenTextMessageHandler
from core.providers.asr.base import ASRProviderBase
from core.providers.asr.dto.dto import InterfaceType

def make_opus_frames(count: int) -> list[bytes]:
    encoder = opuslib_next.Encoder(16000, 1, constants.APPLICATION_AUDIO)
    frames = []
    for index in range(count):
        pcm = bytearray()
        for sample in range(960):
            value = int(6000 * math.sin(2 * math.pi * 330 * (index * 960 + sample) / 16000))
            pcm += struct.pack("<h", value)
        frames.append(encoder.encode(bytes(pcm), 960))
    return frames

def pcm_len(frames) -> int:
    if not frames:
        return 0
    if isinstance(frames, (bytes, bytearray)):
        return len(frames)
    return sum(len(f) for f in frames)

class HeldQueue(queue.Queue):
    def __init__(self):
        super().__init__()
        self.gate = threading.Event()
        self.at_gate = threading.Event()

    def get(self, block=True, timeout=None):
        deadline = None if timeout is None else (time.monotonic() + timeout)
        while True:
            if not self.gate.is_set():
                if not block:
                    raise queue.Empty
                self.at_gate.set()
                remaining = 30 if deadline is None else max(0.0, deadline - time.monotonic())
                if remaining == 0 or not self.gate.wait(remaining):
                    raise queue.Empty
                continue
            self.at_gate.clear()
            if not block:
                return super().get(block=False)
            remaining = 0.01 if deadline is None else max(0.0, deadline - time.monotonic())
            if remaining == 0:
                raise queue.Empty
            try:
                return super().get(block=True, timeout=min(0.01, remaining))
            except queue.Empty:
                if deadline is not None and time.monotonic() >= deadline:
                    raise

class FakeWS:
    def __init__(self):
        self.closed = False
        self.sent = []
    async def send(self, msg):
        self.sent.append(msg)
    async def close(self):
        self.closed = True

class SpyVAD:
    def __init__(self):
        self.calls = 0
    def is_vad(self, conn, pcm_frame):
        self.calls += 1
        return False
    def release_conn_resources(self, conn):
        return None

async def wait_for(predicate, timeout_s=3.0, interval=0.005):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return False

async def route_listen(conn, state: str, mode: str | None = None):
    payload = {"session_id": conn.session_id, "type": "listen", "state": state}
    if mode is not None:
        payload["mode"] = mode
    await conn._route_message(json.dumps(payload))

async def route_abort(conn):
    await conn._route_message(json.dumps({"session_id": conn.session_id, "type": "abort", "reason": "wake_word_detected"}))

async def route_frames(conn, frames):
    for f in frames:
        await conn._route_message(f)

async def new_conn(cfg, rec, *, hold_worker: bool, start_worker: bool = True):
    class ControllableASR(ASRProviderBase):
        def __init__(self):
            super().__init__()
            self.interface_type = InterfaceType.NON_STREAM
            self.output_dir = os.environ["TEST_AUDIO_OUT"]
            self.delete_audio_file = True
            self.next_text = "MANUAL_ORDER_OK"
            self.call_count = 0

        async def speech_to_text(self, opus_data, session_id, artifacts=None):
            return self.next_text, None

        async def speech_to_text_wrapper(self, pcm_data, session_id):
            self.call_count += 1
            rec["asr"].append(pcm_len(pcm_data))
            return self.next_text, None

        async def close(self):
            return None

    asr = ControllableASR()
    conn = ConnectionHandler(cfg, None, asr, None, None, None)
    conn.loop = asyncio.get_running_loop()
    conn.asr = asr
    conn.vad = SpyVAD()
    conn.websocket = FakeWS()
    conn.need_bind = False
    conn.bind_completed_event.set()
    conn.last_activity_time = 0.0
    if hold_worker:
        conn.asr_audio_queue = HeldQueue()
        assert isinstance(conn.asr_audio_queue, HeldQueue)
    if start_worker:
        await asr.open_audio_channels(conn)
    return conn, asr

async def shutdown_conn(conn):
    conn.stop_event.set()
    q = getattr(conn, "asr_audio_queue", None)
    if isinstance(q, HeldQueue):
        q.gate.set()
    thread = getattr(conn, "asr_priority_thread", None)
    if thread is not None and thread.is_alive():
        thread.join(timeout=2.0)
    await conn.close()

async def run():
    cfg = await load_config()
    cfg["delete_audio"] = True
    cfg["close_connection_no_voice_time"] = 10_000
    frames17 = make_opus_frames(17)
    expected17 = 1920 * 17
    rec = {"asr": [], "reports": [], "chats": []}

    def install_spies():
        rec["asr"].clear()
        rec["reports"].clear()
        rec["chats"].clear()
        def spy_enqueue(conn, text, opus_data):
            rec["reports"].append(text)
        async def spy_chat(conn, text):
            rec["chats"].append(text)
        asr_base.enqueue_asr_report = spy_enqueue
        asr_base.startToChat = spy_chat

    # 1. Full backlog (HeldQueue, 0 wait): start + 17 frames + stop -> single dispatch of full 32,640 bytes.
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=True)
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17)
    await route_listen(conn, "stop")
    assert pcm_len(conn.asr_audio) == 0 and conn.asr_audio_queue.qsize() == 18
    assert rec == {"asr": [], "reports": [], "chats": []}
    conn.asr_audio_queue.gate.set()
    assert await wait_for(lambda: len(rec["chats"]) == 1 and conn.asr_audio_queue.empty())
    assert rec == {"asr": [expected17], "reports": ["MANUAL_ORDER_OK"], "chats": ["MANUAL_ORDER_OK"]}, rec
    assert pcm_len(conn.asr_audio) == 0 and conn.asr_audio_queue.empty()
    # Duplicate stop must not re-dispatch anything.
    await route_listen(conn, "stop")
    assert await wait_for(lambda: conn.asr_audio_queue.empty())
    await asyncio.sleep(0.02)
    assert rec == {"asr": [expected17], "reports": ["MANUAL_ORDER_OK"], "chats": ["MANUAL_ORDER_OK"]}, rec
    await shutdown_conn(conn)

    # 2. Partial backlog (HeldQueue, 10 drained + 7 queued + immediate stop): single dispatch of full 32,640 bytes.
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=True)
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17[:10])
    conn.asr_audio_queue.gate.set()
    assert await wait_for(lambda: len(conn.asr_audio) == 10 and conn.asr_audio_queue.empty())
    conn.asr_audio_queue.gate.clear()
    assert conn.asr_audio_queue.at_gate.wait(1.0)
    assert len(conn.asr_audio) == 10 and rec["asr"] == []
    await route_frames(conn, frames17[10:])
    await route_listen(conn, "stop")
    assert len(conn.asr_audio) == 10 and conn.asr_audio_queue.qsize() == 8 and rec["asr"] == []
    conn.asr_audio_queue.gate.set()
    assert await wait_for(lambda: len(rec["chats"]) == 1 and conn.asr_audio_queue.empty())
    assert rec == {"asr": [expected17], "reports": ["MANUAL_ORDER_OK"], "chats": ["MANUAL_ORDER_OK"]}, rec
    assert pcm_len(conn.asr_audio) == 0
    await route_listen(conn, "stop")
    assert await wait_for(lambda: conn.asr_audio_queue.empty())
    await asyncio.sleep(0.02)
    assert rec["asr"] == [expected17], f"tail left behind for second stop: {rec}"
    await shutdown_conn(conn)

    # 3. Control (drain all 17 before stop): still dispatches full 32,640 bytes once.
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=True)
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17)
    conn.asr_audio_queue.gate.set()
    assert await wait_for(lambda: len(conn.asr_audio) == 17 and conn.asr_audio_queue.empty())
    await route_listen(conn, "stop")
    assert await wait_for(lambda: len(rec["chats"]) == 1 and conn.asr_audio_queue.empty())
    assert rec == {"asr": [expected17], "reports": ["MANUAL_ORDER_OK"], "chats": ["MANUAL_ORDER_OK"]}, rec
    await shutdown_conn(conn)

    # 4. Real unheld queue, 0 wait between last frame and stop across 3 consecutive rounds.
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=False)
    for round_idx in range(1, 4):
        asr.next_text = f"UNHELD_R{round_idx}"
        await route_listen(conn, "start", "manual")
        await route_frames(conn, frames17)
        await route_listen(conn, "stop")
        assert await wait_for(lambda idx=round_idx: len(rec["chats"]) == idx and conn.asr_audio_queue.empty())
    assert rec["asr"] == [expected17, expected17, expected17], rec
    assert rec["reports"] == ["UNHELD_R1", "UNHELD_R2", "UNHELD_R3"], rec
    assert rec["chats"] == ["UNHELD_R1", "UNHELD_R2", "UNHELD_R3"], rec
    assert pcm_len(conn.asr_audio) == 0
    await shutdown_conn(conn)

    # 5a. Client abort while stop is still pending in HeldQueue + same-connection recovery (without and with listen.start).
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=True)
    asr.next_text = "STALE_PENDING_ABORT"
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17)
    await route_listen(conn, "stop")
    epoch_before_abort = conn._passport_audio_epoch
    await route_abort(conn)
    assert conn._passport_audio_epoch == epoch_before_abort + 1
    conn.asr_audio_queue.gate.set()
    assert await wait_for(lambda: conn.asr_audio_queue.empty())
    assert rec == {"asr": [], "reports": [], "chats": []} and conn.asr_audio == []
    # Immediate next turn on same connection WITHOUT re-sending listen.start (proves epoch-0 frames + stop did not pollute).
    asr.next_text = "RECOVER_NO_START"
    await route_frames(conn, frames17[:9])
    await route_listen(conn, "stop")
    assert await wait_for(lambda: len(rec["chats"]) == 1 and conn.asr_audio_queue.empty())
    assert rec == {"asr": [1920 * 9], "reports": ["RECOVER_NO_START"], "chats": ["RECOVER_NO_START"]}, rec
    # Next turn WITH listen.start.
    asr.next_text = "RECOVER_WITH_START"
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17[:11])
    await route_listen(conn, "stop")
    assert await wait_for(lambda: len(rec["chats"]) == 2 and conn.asr_audio_queue.empty())
    assert rec == {
        "asr": [1920 * 9, 1920 * 11],
        "reports": ["RECOVER_NO_START", "RECOVER_WITH_START"],
        "chats": ["RECOVER_NO_START", "RECOVER_WITH_START"],
    }, rec
    await shutdown_conn(conn)

    # 5b. Pre-popped _QueuedListenStop fed directly to handleAudioMessage after abort is ignored.
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=True, start_worker=False)
    conn.client_listen_mode = "manual"
    conn.asr_audio = [b"\\x01\\x00" * 960 for _ in range(17)]
    conn.asr_audio_queue.put(b"\\x02\\x00" * 960)
    await route_listen(conn, "stop")
    conn.asr_audio_queue.gate.set()
    _ = conn.asr_audio_queue.get_nowait()
    pre_popped_stop = conn.asr_audio_queue.get_nowait()
    await route_abort(conn)
    await receive_audio_handle.handleAudioMessage(conn, pre_popped_stop)
    assert rec == {"asr": [], "reports": [], "chats": []}, rec
    assert asr.call_count == 0 and conn.asr_audio == []
    await shutdown_conn(conn)

    # 6. Connection close while stop is pending in HeldQueue + pre-popped marker + new connection recovery.
    install_spies()
    conn_cl, asr_cl = await new_conn(cfg, rec, hold_worker=True)
    asr_cl.next_text = "STALE_PENDING_CLOSE"
    await route_listen(conn_cl, "start", "manual")
    await route_frames(conn_cl, frames17)
    await route_listen(conn_cl, "stop")
    # Also grab a real _QueuedListenStop marker before closing.
    conn_helper, _ = await new_conn(cfg, rec, hold_worker=True, start_worker=False)
    conn_helper.asr_audio_queue.put(b"\\x02\\x00" * 960)
    await route_listen(conn_helper, "stop")
    conn_helper.asr_audio_queue.gate.set()
    _ = conn_helper.asr_audio_queue.get_nowait()
    pre_popped_close_stop = conn_helper.asr_audio_queue.get_nowait()
    await shutdown_conn(conn_helper)

    await conn_cl.close()
    conn_cl.asr_audio_queue.gate.set()
    conn_cl.asr_priority_thread.join(timeout=2.0)
    await receive_audio_handle.handleAudioMessage(conn_cl, pre_popped_close_stop)
    assert asr_cl.call_count == 0 and rec == {"asr": [], "reports": [], "chats": []}, rec
    assert conn_cl._passport_asr_task is None and conn_cl.asr_audio == []

    # Fresh connection completes full manual turn with 0 wait.
    install_spies()
    conn_new, asr_new = await new_conn(cfg, rec, hold_worker=False)
    asr_new.next_text = "FRESH_CONN_AFTER_CLOSE"
    await route_listen(conn_new, "start", "manual")
    await route_frames(conn_new, frames17)
    await route_listen(conn_new, "stop")
    assert await wait_for(lambda: len(rec["chats"]) == 1 and conn_new.asr_audio_queue.empty())
    assert rec == {"asr": [expected17], "reports": ["FRESH_CONN_AFTER_CLOSE"], "chats": ["FRESH_CONN_AFTER_CLOSE"]}, rec
    await shutdown_conn(conn_new)

    # 7. Old-generation pending stop must NOT block or double-dispatch a subsequent listen.start round.
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=True)
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17)
    await route_listen(conn, "stop")
    # New turn starts while old frames + old stop are still held in queue.
    asr.next_text = "NEW_GEN_ONLY"
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17[:9])
    await route_listen(conn, "stop")
    conn.asr_audio_queue.gate.set()
    assert await wait_for(lambda: len(rec["chats"]) == 1 and conn.asr_audio_queue.empty())
    await asyncio.sleep(0.03)
    assert rec == {"asr": [1920 * 9], "reports": ["NEW_GEN_ONLY"], "chats": ["NEW_GEN_ONLY"]}, rec
    await shutdown_conn(conn)

    # 8. Two back-to-back manual utterances in the SAME epoch without listen.start between them.
    install_spies()
    conn, asr = await new_conn(cfg, rec, hold_worker=False)
    asr.next_text = "SAME_EPOCH_TWO_TURNS"
    await route_listen(conn, "start", "manual")
    await route_frames(conn, frames17)
    await route_listen(conn, "stop")
    await route_frames(conn, frames17[:9])
    await route_listen(conn, "stop")
    assert await wait_for(lambda: len(rec["chats"]) == 2 and conn.asr_audio_queue.empty())
    assert rec["asr"] == [expected17, 1920 * 9], rec
    assert pcm_len(conn.asr_audio) == 0
    await shutdown_conn(conn)

    # 9. Worker-less fallback: empty queue without audio thread dispatches buffered asr_audio directly.
    install_spies()
    conn_nw, asr_nw = await new_conn(cfg, rec, hold_worker=False, start_worker=False)
    conn_nw.client_listen_mode = "manual"
    conn_nw.asr_audio = [b"\\x01\\x00" * 960 for _ in range(17)]
    await ListenTextMessageHandler().handle(conn_nw, {"session_id": conn_nw.session_id, "type": "listen", "state": "stop"})
    assert conn_nw._passport_asr_task is not None
    await asyncio.wait_for(conn_nw._passport_asr_task, 1.0)
    assert rec == {"asr": [expected17], "reports": ["MANUAL_ORDER_OK"], "chats": ["MANUAL_ORDER_OK"]}, rec
    await shutdown_conn(conn_nw)

asyncio.run(run())
"""
        res = subprocess.run(
            [sys.executable, "-c", probe_code],
            env=_base_env(
                XIAOZHI_HOME=str(srv_home),
                PASSPORT_ROOT=str(ROOT),
                PASSPORT_LOG_DIR=str(srv_home / "tmp"),
                TEST_AUDIO_OUT=str(tmp / "asr_out"),
            ),
            capture_output=True,
            text=True,
            timeout=25,
        )
        assert res.returncode == 0, (
            f"manual listen.stop queue ordering probe failed ({res.returncode}):\n{res.stdout}\n{res.stderr}"
        )
    print(
        "[PASS] manual listen.stop FIFO queue ordering (full/partial backlog, 0-wait live worker, "
        "pending abort/close invalidation, cross-epoch isolation, and worker-less fallback) verified"
    )


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


def _vad_utterance_opus_frames(server_home: Path) -> tuple[list[bytes], bytes]:
    """Encode bundled 16 kHz mono speech WAV (>15 frames) plus a silence frame to trigger real Silero VAD."""
    wav_path = server_home / "config" / "assets" / "wakeup_words_short.wav"
    assert wav_path.is_file(), f"Missing bundled speech asset: {wav_path}"
    with wave.open(str(wav_path), "rb") as wf:
        assert wf.getframerate() == 16000 and wf.getnchannels() == 1 and wf.getsampwidth() == 2, (
            f"Unexpected WAV format in {wav_path}: sr={wf.getframerate()} ch={wf.getnchannels()} sw={wf.getsampwidth()}"
        )
        raw_pcm = wf.readframes(wf.getnframes())
    encoder = opuslib_next.Encoder(16000, 1, constants.APPLICATION_AUDIO)
    speech_frames: list[bytes] = []
    for off in range(0, len(raw_pcm), 1920):
        chunk = raw_pcm[off : off + 1920]
        if len(chunk) < 1920:
            chunk += b"\x00" * (1920 - len(chunk))
        speech_frames.append(encoder.encode(chunk, 960))
    assert len(speech_frames) > 15, f"Speech asset too short for VAD trigger: {len(speech_frames)} frames"
    silence_frame = encoder.encode(b"\x00" * 1920, 960)
    return speech_frames, silence_frame


async def _send_vad_utterance(
    ws,
    session_id: str,
    mode: str,
    speech_frames: list[bytes],
    silence_frame: bytes,
    *,
    silence_count: int = 12,
    silence_interval_s: float = 0.035,
    send_listen_start: bool = True,
) -> None:
    """Send listen.start (optional) + speech + silence in auto/realtime mode until VAD triggers voice stop."""
    if send_listen_start:
        await ws.send(
            json.dumps({"session_id": session_id, "type": "listen", "state": "start", "mode": mode})
        )
    for frame in speech_frames:
        await ws.send(frame)
    for _ in range(silence_count):
        await asyncio.sleep(silence_interval_s)
        await ws.send(silence_frame)


async def _collect_ws_turn_response(ws, timeout_s: float = 15.0) -> dict:
    """Collect STT, TTS states, and decoded TTS PCM byte count until tts.stop."""
    texts: list[str] = []
    tts_states: list[str] = []
    decoded = 0
    decoder = opuslib_next.Decoder(16000, 1)
    deadline = asyncio.get_running_loop().time() + timeout_s
    while asyncio.get_running_loop().time() < deadline:
        try:
            raw = await asyncio.wait_for(ws.recv(), 2.0)
        except asyncio.TimeoutError:
            if tts_states and tts_states[-1] == "stop":
                break
            continue
        if isinstance(raw, bytes):
            decoded += len(decoder.decode(raw, 960))
            continue
        msg = json.loads(raw)
        if msg.get("type") == "stt":
            texts.append(msg.get("text", ""))
        elif msg.get("type") == "tts":
            tts_states.append(msg.get("state"))
            if msg.get("state") == "stop":
                break
    return {"stt": texts, "tts_states": tts_states, "decoded_pcm_bytes": decoded}


async def _run_vad_turn(
    ws,
    session_id: str,
    mode: str,
    speech_frames: list[bytes],
    silence_frame: bytes,
    timeout_s: float = 15.0,
    send_listen_start: bool = True,
) -> dict:
    """Execute a complete VAD-triggered voice turn in auto or realtime mode and verify TTS completion."""
    await _send_vad_utterance(
        ws,
        session_id,
        mode,
        speech_frames,
        silence_frame,
        send_listen_start=send_listen_start,
    )
    return await _collect_ws_turn_response(ws, timeout_s=timeout_s)


async def _run_live_server_regressions(
    ota_base: str,
    ws_url: str,
    fake_url: str,
    devices_file: Path,
    auth_key: str,
    dev_a: dict,
    dev_b: dict,
    server_home: Path,
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

    # 3d & 3e. Auto and realtime VAD-triggered ASR abort cancellation + stale STT/LLM block + recovery.
    speech_frames, silence_frame = _vad_utterance_opus_frames(server_home)
    last_seen_req_id = req_disc_id
    try:
        for mode in ("auto", "realtime"):
            stale_marker = f"STALE_{mode.upper()}_ABORT"
            async with websockets.connect(ws_url, additional_headers=headers_a) as ws_vad:
                hello_vad = await send_hello(ws_vad)
                sid_vad = hello_vad["session_id"]
                llm_before = int(_get_json(f"{fake_url}/_stats")["llm_total"])

                post_json(
                    f"{fake_url}/_control",
                    {},
                    {"asr_delays": [15.0], "transcript": stale_marker},
                )
                await _send_vad_utterance(ws_vad, sid_vad, mode, speech_frames, silence_frame)

                t_wait_vad = time.monotonic()
                req_vad_abort_id = None
                while time.monotonic() - t_wait_vad < 5.0:
                    stats = _get_json(f"{fake_url}/_stats")
                    newer = [rid for rid in stats["asr_in_flight_ids"] if rid > last_seen_req_id]
                    if newer:
                        req_vad_abort_id = newer[-1]
                        break
                    await asyncio.sleep(0.05)
                else:
                    raise AssertionError(f"{mode} VAD slow ASR request never reached fake_provider")
                last_seen_req_id = req_vad_abort_id
                t_vad_started = time.monotonic()

                t_vad_abort_sent = time.monotonic()
                await ws_vad.send(
                    json.dumps({"session_id": sid_vad, "type": "abort", "reason": "wake_word_detected"})
                )
                stop_deadline = t_vad_abort_sent + 1.5
                stop_seen = False
                while time.monotonic() < stop_deadline:
                    rem = max(0.01, stop_deadline - time.monotonic())
                    raw_msg = await asyncio.wait_for(ws_vad.recv(), rem)
                    if isinstance(raw_msg, bytes):
                        continue
                    assert stale_marker not in raw_msg, f"{mode} aborted stale text reached client: {raw_msg!r}"
                    parsed_msg = json.loads(raw_msg)
                    if parsed_msg.get("type") == "tts" and parsed_msg.get("state") == "stop":
                        stop_seen = True
                        break
                assert stop_seen, f"{mode} did not receive tts.stop within 1.5s after abort"

                while time.monotonic() - t_vad_abort_sent < 1.2:
                    stats = _get_json(f"{fake_url}/_stats")
                    rec = next((r for r in stats["asr_requests"] if r["id"] == req_vad_abort_id), None)
                    if (
                        rec is not None
                        and rec["state"] == "aborted"
                        and req_vad_abort_id not in stats["asr_in_flight_ids"]
                    ):
                        break
                    await asyncio.sleep(0.03)
                else:
                    raise AssertionError(
                        f"{mode} aborted ASR req_id={req_vad_abort_id} did not disconnect within 1.2s"
                    )
                assert time.monotonic() - t_vad_started < 2.2, (
                    f"{mode} aborted ASR elapsed too close to 4.0s ASR timeout"
                )

                # Observe briefly to confirm stale transcript never enters STT or LLM.
                observe_end = time.monotonic() + 0.3
                while time.monotonic() < observe_end:
                    rem = max(0.01, observe_end - time.monotonic())
                    try:
                        extra = await asyncio.wait_for(ws_vad.recv(), rem)
                    except asyncio.TimeoutError:
                        break
                    if isinstance(extra, str):
                        assert stale_marker not in extra, f"{mode} aborted stale text reached client: {extra!r}"
                assert int(_get_json(f"{fake_url}/_stats")["llm_total"]) == llm_before, (
                    f"{mode} aborted ASR unexpectedly triggered LLM"
                )

                # Next VAD turn in the same mode completes cleanly.
                post_json(f"{fake_url}/_control", {}, {"asr_delays": [0.0], "transcript": "合约测试"})
                turn_ok = await _run_vad_turn(ws_vad, sid_vad, mode, speech_frames, silence_frame)
                assert "合约测试" in "".join(turn_ok["stt"]), (mode, turn_ok)
                assert turn_ok["decoded_pcm_bytes"] > 0 and "stop" in turn_ok["tts_states"], (mode, turn_ok)
                assert int(_get_json(f"{fake_url}/_stats")["llm_total"]) == llm_before + 1

        # 3f & 3g. Auto and realtime VAD-triggered ASR abrupt disconnect cancel + reconnect recovery.
        for mode in ("auto", "realtime"):
            stale_disc_marker = f"STALE_{mode.upper()}_DISC"
            llm_before_disc = int(_get_json(f"{fake_url}/_stats")["llm_total"])
            post_json(
                f"{fake_url}/_control",
                {},
                {"asr_delays": [15.0], "transcript": stale_disc_marker},
            )
            ws_vad_disc = await websockets.connect(ws_url, additional_headers=headers_a)
            try:
                hello_vd = await send_hello(ws_vad_disc)
                await _send_vad_utterance(
                    ws_vad_disc, hello_vd["session_id"], mode, speech_frames, silence_frame
                )

                t_vd_wait = time.monotonic()
                req_vd_id = None
                while time.monotonic() - t_vd_wait < 5.0:
                    stats = _get_json(f"{fake_url}/_stats")
                    newer = [rid for rid in stats["asr_in_flight_ids"] if rid > last_seen_req_id]
                    if newer:
                        req_vd_id = newer[-1]
                        break
                    await asyncio.sleep(0.05)
                else:
                    raise AssertionError(f"{mode} disconnect-test ASR request never started")
                last_seen_req_id = req_vd_id
                t_vd_started = time.monotonic()

                t_vd_dropped = time.monotonic()
                if ws_vad_disc.transport is not None:
                    ws_vad_disc.transport.abort()
                else:
                    await ws_vad_disc.close()
            finally:
                if ws_vad_disc.transport is not None and not ws_vad_disc.transport.is_closing():
                    ws_vad_disc.transport.abort()

            while time.monotonic() - t_vd_dropped < 1.5:
                stats = _get_json(f"{fake_url}/_stats")
                rec = next((r for r in stats["asr_requests"] if r["id"] == req_vd_id), None)
                if rec is not None and rec["state"] == "aborted" and req_vd_id not in stats["asr_in_flight_ids"]:
                    break
                await asyncio.sleep(0.03)
            else:
                raise AssertionError(f"{mode} disconnected WS ASR req_id={req_vd_id} did not abort within 1.5s")
            assert time.monotonic() - t_vd_started < 2.5, (
                f"{mode} WebSocket disconnect cancel elapsed too close to 4.0s ASR timeout"
            )
            await asyncio.sleep(0.3)
            assert int(_get_json(f"{fake_url}/_stats")["llm_total"]) == llm_before_disc, (
                f"{mode} disconnected ASR unexpectedly triggered LLM"
            )

            post_json(f"{fake_url}/_control", {}, {"asr_delays": [0.0], "transcript": "合约测试"})
            async with websockets.connect(ws_url, additional_headers=headers_a) as ws_vd_rec:
                hello_vdr = await send_hello(ws_vd_rec)
                turn_vdr = await _run_vad_turn(
                    ws_vd_rec, hello_vdr["session_id"], mode, speech_frames, silence_frame
                )
                assert "合约测试" in "".join(turn_vdr["stt"]), (mode, turn_vdr)
                assert turn_vdr["decoded_pcm_bytes"] > 0 and "stop" in turn_vdr["tts_states"], (mode, turn_vdr)
                assert int(_get_json(f"{fake_url}/_stats")["llm_total"]) == llm_before_disc + 1

        # 3h. Pre-VAD abort (before sentence end, no ASR task dispatched yet):
        #     both buffered speech and queued speech frames are discarded so subsequent silence
        #     never triggers STT/LLM, and the same connection recovers cleanly on the next turn.
        pre_vad_frames = speech_frames[:20]  # 20 * 1920 = 38,400 bytes (>28,800 threshold), active speech ends at frame 19
        for mode in ("auto", "realtime"):
            stale_prevad = f"STALE_PREVAD_{mode.upper()}"
            async with websockets.connect(ws_url, additional_headers=headers_a) as ws_pre:
                hello_pre = await send_hello(ws_pre)
                sid_pre = hello_pre["session_id"]
                stats_before = _get_json(f"{fake_url}/_stats")
                asr_before_pre = int(stats_before["asr_total"])
                llm_before_pre = int(stats_before["llm_total"])

                post_json(
                    f"{fake_url}/_control",
                    {},
                    {"asr_delays": [0.0], "transcript": stale_prevad},
                )
                # (i) Abort after frames are buffered in conn.asr_audio with client_have_voice=True, before VAD end.
                await ws_pre.send(
                    json.dumps({"session_id": sid_pre, "type": "listen", "state": "start", "mode": mode})
                )
                for frame in pre_vad_frames:
                    await ws_pre.send(frame)
                await asyncio.sleep(0.12)

                stats_mid = _get_json(f"{fake_url}/_stats")
                assert int(stats_mid["asr_total"]) == asr_before_pre and int(stats_mid["asr_in_flight"]) == 0, (
                    f"{mode} pre-VAD setup unexpectedly dispatched ASR before abort: {stats_mid}"
                )

                await ws_pre.send(
                    json.dumps({"session_id": sid_pre, "type": "abort", "reason": "wake_word_detected"})
                )
                stop_deadline = time.monotonic() + 1.5
                stop_seen = False
                while time.monotonic() < stop_deadline:
                    rem = max(0.01, stop_deadline - time.monotonic())
                    raw_msg = await asyncio.wait_for(ws_pre.recv(), rem)
                    if isinstance(raw_msg, bytes):
                        continue
                    assert stale_prevad not in raw_msg, f"{mode} pre-VAD abort leaked stale text: {raw_msg!r}"
                    parsed_msg = json.loads(raw_msg)
                    if parsed_msg.get("type") == "tts" and parsed_msg.get("state") == "stop":
                        stop_seen = True
                        break
                assert stop_seen, f"{mode} did not receive tts.stop after pre-VAD abort"

                # Feed silence (> 200ms min_silence_duration_ms); aborted audio must NOT trigger ASR or LLM.
                for _ in range(12):
                    await asyncio.sleep(0.035)
                    await ws_pre.send(silence_frame)
                obs_end = time.monotonic() + 0.35
                while time.monotonic() < obs_end:
                    rem = max(0.01, obs_end - time.monotonic())
                    try:
                        extra = await asyncio.wait_for(ws_pre.recv(), rem)
                    except asyncio.TimeoutError:
                        break
                    if isinstance(extra, str):
                        assert stale_prevad not in extra, f"{mode} pre-VAD abort leaked stale text on silence: {extra!r}"
                stats_after_buf = _get_json(f"{fake_url}/_stats")
                assert int(stats_after_buf["asr_total"]) == asr_before_pre, (
                    f"{mode} buffered pre-VAD audio triggered ASR after abort+silence: {stats_after_buf}"
                )
                assert int(stats_after_buf["llm_total"]) == llm_before_pre, (
                    f"{mode} buffered pre-VAD audio triggered LLM after abort+silence: {stats_after_buf}"
                )

                # (ii) Immediate pre-VAD abort while frames may still sit in asr_audio_queue.
                for frame in pre_vad_frames:
                    await ws_pre.send(frame)
                await ws_pre.send(
                    json.dumps({"session_id": sid_pre, "type": "abort", "reason": "wake_word_detected"})
                )
                stop_deadline2 = time.monotonic() + 1.5
                stop_seen2 = False
                while time.monotonic() < stop_deadline2:
                    rem = max(0.01, stop_deadline2 - time.monotonic())
                    raw_msg = await asyncio.wait_for(ws_pre.recv(), rem)
                    if isinstance(raw_msg, bytes):
                        continue
                    assert stale_prevad not in raw_msg, f"{mode} queued pre-VAD abort leaked stale text: {raw_msg!r}"
                    parsed_msg = json.loads(raw_msg)
                    if parsed_msg.get("type") == "tts" and parsed_msg.get("state") == "stop":
                        stop_seen2 = True
                        break
                assert stop_seen2, f"{mode} did not receive tts.stop after queued pre-VAD abort"

                for _ in range(12):
                    await asyncio.sleep(0.035)
                    await ws_pre.send(silence_frame)
                await asyncio.sleep(0.35)
                stats_after_q = _get_json(f"{fake_url}/_stats")
                assert int(stats_after_q["asr_total"]) == asr_before_pre, (
                    f"{mode} queued pre-VAD audio triggered ASR after abort+silence: {stats_after_q}"
                )
                assert int(stats_after_q["llm_total"]) == llm_before_pre, (
                    f"{mode} queued pre-VAD audio triggered LLM after abort+silence: {stats_after_q}"
                )

                # (iii) Same connection completes a fresh post-abort utterance (even without re-sending listen.start).
                fresh_marker = f"FRESH_POST_ABORT_{mode.upper()}"
                post_json(
                    f"{fake_url}/_control",
                    {},
                    {"asr_delays": [0.0], "transcript": fresh_marker},
                )
                turn_fresh = await _run_vad_turn(
                    ws_pre,
                    sid_pre,
                    mode,
                    speech_frames,
                    silence_frame,
                    send_listen_start=False,
                )
                assert fresh_marker in "".join(turn_fresh["stt"]), (mode, turn_fresh)
                assert turn_fresh["decoded_pcm_bytes"] > 0 and "stop" in turn_fresh["tts_states"], (mode, turn_fresh)
                stats_after_fresh = _get_json(f"{fake_url}/_stats")
                assert int(stats_after_fresh["asr_total"]) == asr_before_pre + 1
                assert int(stats_after_fresh["llm_total"]) == llm_before_pre + 1

        # 3i. Pre-VAD abrupt disconnect during buffering stage does not consume buffered/queued audio
        #     after close, and reconnecting recovers cleanly in both auto and realtime modes.
        for mode in ("auto", "realtime"):
            stale_prevad_disc = f"STALE_PREVAD_DISC_{mode.upper()}"
            stats_before_pd = _get_json(f"{fake_url}/_stats")
            asr_before_pd = int(stats_before_pd["asr_total"])
            llm_before_pd = int(stats_before_pd["llm_total"])
            post_json(
                f"{fake_url}/_control",
                {},
                {"asr_delays": [0.0], "transcript": stale_prevad_disc},
            )
            ws_pre_disc = await websockets.connect(ws_url, additional_headers=headers_a)
            try:
                hello_pd = await send_hello(ws_pre_disc)
                await ws_pre_disc.send(
                    json.dumps({"session_id": hello_pd["session_id"], "type": "listen", "state": "start", "mode": mode})
                )
                for frame in pre_vad_frames:
                    await ws_pre_disc.send(frame)
                await asyncio.sleep(0.12)
                stats_mid_pd = _get_json(f"{fake_url}/_stats")
                assert int(stats_mid_pd["asr_total"]) == asr_before_pd and int(stats_mid_pd["asr_in_flight"]) == 0
                for _ in range(2):
                    await asyncio.sleep(0.035)
                    await ws_pre_disc.send(silence_frame)
                if ws_pre_disc.transport is not None:
                    ws_pre_disc.transport.abort()
                else:
                    await ws_pre_disc.close()
            finally:
                if ws_pre_disc.transport is not None and not ws_pre_disc.transport.is_closing():
                    ws_pre_disc.transport.abort()

            await asyncio.sleep(0.5)
            stats_after_pd = _get_json(f"{fake_url}/_stats")
            assert int(stats_after_pd["asr_total"]) == asr_before_pd, (
                f"{mode} pre-VAD disconnected session unexpectedly dispatched ASR: {stats_after_pd}"
            )
            assert int(stats_after_pd["llm_total"]) == llm_before_pd, (
                f"{mode} pre-VAD disconnected session unexpectedly triggered LLM: {stats_after_pd}"
            )

            rec_marker = f"RECONNECT_PREVAD_{mode.upper()}"
            post_json(f"{fake_url}/_control", {}, {"asr_delays": [0.0], "transcript": rec_marker})
            async with websockets.connect(ws_url, additional_headers=headers_a) as ws_pd_rec:
                hello_pdr = await send_hello(ws_pd_rec)
                turn_pdr = await _run_vad_turn(
                    ws_pd_rec, hello_pdr["session_id"], mode, speech_frames, silence_frame
                )
                assert rec_marker in "".join(turn_pdr["stt"]), (mode, turn_pdr)
                assert turn_pdr["decoded_pcm_bytes"] > 0 and "stop" in turn_pdr["tts_states"], (mode, turn_pdr)
                stats_after_pdr = _get_json(f"{fake_url}/_stats")
                assert int(stats_after_pdr["asr_total"]) == asr_before_pd + 1
                assert int(stats_after_pdr["llm_total"]) == llm_before_pd + 1

        # 3j. Manual listen.stop queue ordering on the live server (0-sleep frame bursts,
        #     partial backlog, pending abort invalidation + same-session recovery, and
        #     pending close invalidation + reconnect recovery).
        manual_frames_17 = opus_frames(17)
        expected_17_bytes = 1920 * 17
        async with websockets.connect(ws_url, additional_headers=headers_a) as ws_man:
            hello_man = await send_hello(ws_man)
            sid_man = hello_man["session_id"]

            # (i) Full burst with 0 sleep before stop -> single ASR call receives all 32,640 bytes.
            post_json(f"{fake_url}/_control", {}, {"asr_delays": [0.0], "transcript": "MANUAL_LIVE_FULL"})
            st_before_m1 = _get_json(f"{fake_url}/_stats")
            prev_id_m1 = max((r["id"] for r in st_before_m1["asr_requests"]), default=0)
            asr_before_m1 = int(st_before_m1["asr_total"])
            llm_before_m1 = int(st_before_m1["llm_total"])

            await ws_man.send(
                json.dumps({"session_id": sid_man, "type": "listen", "state": "start", "mode": "manual"})
            )
            for frame in manual_frames_17:
                await ws_man.send(frame)
            await ws_man.send(json.dumps({"session_id": sid_man, "type": "listen", "state": "stop"}))

            turn_m1 = await _collect_ws_turn_response(ws_man)
            assert "MANUAL_LIVE_FULL" in "".join(turn_m1["stt"]), turn_m1
            assert turn_m1["decoded_pcm_bytes"] > 0 and "stop" in turn_m1["tts_states"], turn_m1
            st_after_m1 = _get_json(f"{fake_url}/_stats")
            reqs_m1 = [r for r in st_after_m1["asr_requests"] if r["id"] > prev_id_m1]
            assert int(st_after_m1["asr_total"]) == asr_before_m1 + 1, st_after_m1
            assert int(st_after_m1["llm_total"]) == llm_before_m1 + 1, st_after_m1
            assert len(reqs_m1) == 1 and reqs_m1[0]["pcm_bytes"] == expected_17_bytes, reqs_m1

            # (ii) Partial drain (10 frames digested, then 7 tail frames + immediate 0-sleep stop)
            #      -> single ASR call receives full 32,640 bytes and duplicate stop triggers nothing.
            post_json(f"{fake_url}/_control", {}, {"asr_delays": [0.0], "transcript": "MANUAL_LIVE_PARTIAL"})
            st_before_m2 = _get_json(f"{fake_url}/_stats")
            prev_id_m2 = max((r["id"] for r in st_before_m2["asr_requests"]), default=0)
            asr_before_m2 = int(st_before_m2["asr_total"])
            llm_before_m2 = int(st_before_m2["llm_total"])

            await ws_man.send(
                json.dumps({"session_id": sid_man, "type": "listen", "state": "start", "mode": "manual"})
            )
            for frame in manual_frames_17[:10]:
                await ws_man.send(frame)
            await asyncio.sleep(0.12)
            for frame in manual_frames_17[10:]:
                await ws_man.send(frame)
            await ws_man.send(json.dumps({"session_id": sid_man, "type": "listen", "state": "stop"}))

            turn_m2 = await _collect_ws_turn_response(ws_man)
            assert "MANUAL_LIVE_PARTIAL" in "".join(turn_m2["stt"]), turn_m2
            assert turn_m2["decoded_pcm_bytes"] > 0 and "stop" in turn_m2["tts_states"], turn_m2
            st_after_m2 = _get_json(f"{fake_url}/_stats")
            reqs_m2 = [r for r in st_after_m2["asr_requests"] if r["id"] > prev_id_m2]
            assert int(st_after_m2["asr_total"]) == asr_before_m2 + 1, st_after_m2
            assert int(st_after_m2["llm_total"]) == llm_before_m2 + 1, st_after_m2
            assert len(reqs_m2) == 1 and reqs_m2[0]["pcm_bytes"] == expected_17_bytes, reqs_m2

            await ws_man.send(json.dumps({"session_id": sid_man, "type": "listen", "state": "stop"}))
            await asyncio.sleep(0.25)
            st_dup_m2 = _get_json(f"{fake_url}/_stats")
            assert int(st_dup_m2["asr_total"]) == asr_before_m2 + 1, st_dup_m2
            assert int(st_dup_m2["llm_total"]) == llm_before_m2 + 1, st_dup_m2

            # (iii) Immediate abort after stop invalidates pending/in-flight stop; same session recovers cleanly.
            stale_man_abort = "STALE_MANUAL_PENDING_ABORT"
            llm_before_m3 = int(_get_json(f"{fake_url}/_stats")["llm_total"])
            post_json(
                f"{fake_url}/_control",
                {},
                {"asr_delays": [15.0], "transcript": stale_man_abort},
            )
            await ws_man.send(
                json.dumps({"session_id": sid_man, "type": "listen", "state": "start", "mode": "manual"})
            )
            for frame in manual_frames_17:
                await ws_man.send(frame)
            await ws_man.send(json.dumps({"session_id": sid_man, "type": "listen", "state": "stop"}))
            await ws_man.send(
                json.dumps({"session_id": sid_man, "type": "abort", "reason": "wake_word_detected"})
            )

            stop_deadline_m3 = time.monotonic() + 1.5
            stop_seen_m3 = False
            while time.monotonic() < stop_deadline_m3:
                rem = max(0.01, stop_deadline_m3 - time.monotonic())
                raw_msg = await asyncio.wait_for(ws_man.recv(), rem)
                if isinstance(raw_msg, bytes):
                    continue
                assert stale_man_abort not in raw_msg, f"manual abort leaked stale text: {raw_msg!r}"
                parsed_msg = json.loads(raw_msg)
                if parsed_msg.get("type") == "tts" and parsed_msg.get("state") == "stop":
                    stop_seen_m3 = True
                    break
            assert stop_seen_m3, "manual abort after pending stop did not receive tts.stop"

            t_m3_clear = time.monotonic()
            while time.monotonic() - t_m3_clear < 1.2:
                if int(_get_json(f"{fake_url}/_stats")["asr_in_flight"]) == 0:
                    break
                await asyncio.sleep(0.03)
            else:
                raise AssertionError("manual abort left ASR request in flight")

            obs_end_m3 = time.monotonic() + 0.3
            while time.monotonic() < obs_end_m3:
                rem = max(0.01, obs_end_m3 - time.monotonic())
                try:
                    extra = await asyncio.wait_for(ws_man.recv(), rem)
                except asyncio.TimeoutError:
                    break
                if isinstance(extra, str):
                    assert stale_man_abort not in extra, f"manual abort leaked stale text: {extra!r}"
            assert int(_get_json(f"{fake_url}/_stats")["llm_total"]) == llm_before_m3

            # Same-connection recovery without re-sending listen.start (verifies zero stale buffered bytes).
            post_json(f"{fake_url}/_control", {}, {"asr_delays": [0.0], "transcript": "MANUAL_POST_ABORT_OK"})
            st_pre_rec3 = _get_json(f"{fake_url}/_stats")
            prev_id_rec3 = max((r["id"] for r in st_pre_rec3["asr_requests"]), default=0)
            for frame in manual_frames_17[:11]:
                await ws_man.send(frame)
            await ws_man.send(json.dumps({"session_id": sid_man, "type": "listen", "state": "stop"}))
            turn_rec3 = await _collect_ws_turn_response(ws_man)
            assert "MANUAL_POST_ABORT_OK" in "".join(turn_rec3["stt"]), turn_rec3
            assert turn_rec3["decoded_pcm_bytes"] > 0 and "stop" in turn_rec3["tts_states"], turn_rec3
            st_post_rec3 = _get_json(f"{fake_url}/_stats")
            reqs_rec3 = [r for r in st_post_rec3["asr_requests"] if r["id"] > prev_id_rec3]
            assert int(st_post_rec3["llm_total"]) == llm_before_m3 + 1, st_post_rec3
            assert len(reqs_rec3) == 1 and reqs_rec3[0]["pcm_bytes"] == 1920 * 11, reqs_rec3

        # (iv) Immediate disconnect after stop invalidates pending/in-flight stop; reconnect recovers cleanly.
        llm_before_m4 = int(_get_json(f"{fake_url}/_stats")["llm_total"])
        post_json(
            f"{fake_url}/_control",
            {},
            {"asr_delays": [15.0], "transcript": "STALE_MANUAL_PENDING_DISC"},
        )
        ws_man_disc = await websockets.connect(ws_url, additional_headers=headers_a)
        try:
            hello_md = await send_hello(ws_man_disc)
            await ws_man_disc.send(
                json.dumps(
                    {
                        "session_id": hello_md["session_id"],
                        "type": "listen",
                        "state": "start",
                        "mode": "manual",
                    }
                )
            )
            for frame in manual_frames_17:
                await ws_man_disc.send(frame)
            await ws_man_disc.send(
                json.dumps({"session_id": hello_md["session_id"], "type": "listen", "state": "stop"})
            )
            if ws_man_disc.transport is not None:
                ws_man_disc.transport.abort()
            else:
                await ws_man_disc.close()
        finally:
            if ws_man_disc.transport is not None and not ws_man_disc.transport.is_closing():
                ws_man_disc.transport.abort()

        t_m4_clear = time.monotonic()
        while time.monotonic() - t_m4_clear < 1.5:
            if int(_get_json(f"{fake_url}/_stats")["asr_in_flight"]) == 0:
                break
            await asyncio.sleep(0.03)
        else:
            raise AssertionError("manual disconnect left ASR request in flight")
        await asyncio.sleep(0.4)
        st_after_md = _get_json(f"{fake_url}/_stats")
        assert int(st_after_md["llm_total"]) == llm_before_m4, st_after_md
        assert int(st_after_md["asr_in_flight"]) == 0, st_after_md

        post_json(f"{fake_url}/_control", {}, {"asr_delays": [0.0], "transcript": "MANUAL_RECONNECT_OK"})
        st_pre_rec4 = _get_json(f"{fake_url}/_stats")
        prev_id_rec4 = max((r["id"] for r in st_pre_rec4["asr_requests"]), default=0)
        async with websockets.connect(ws_url, additional_headers=headers_a) as ws_man_rec:
            hello_mr = await send_hello(ws_man_rec)
            await ws_man_rec.send(
                json.dumps(
                    {
                        "session_id": hello_mr["session_id"],
                        "type": "listen",
                        "state": "start",
                        "mode": "manual",
                    }
                )
            )
            for frame in manual_frames_17[:13]:
                await ws_man_rec.send(frame)
            await ws_man_rec.send(
                json.dumps({"session_id": hello_mr["session_id"], "type": "listen", "state": "stop"})
            )
            turn_rec4 = await _collect_ws_turn_response(ws_man_rec)
            assert "MANUAL_RECONNECT_OK" in "".join(turn_rec4["stt"]), turn_rec4
            assert turn_rec4["decoded_pcm_bytes"] > 0 and "stop" in turn_rec4["tts_states"], turn_rec4
        st_post_rec4 = _get_json(f"{fake_url}/_stats")
        reqs_rec4 = [r for r in st_post_rec4["asr_requests"] if r["id"] > prev_id_rec4]
        assert int(st_post_rec4["llm_total"]) == llm_before_m4 + 1, st_post_rec4
        assert len(reqs_rec4) == 1 and reqs_rec4[0]["pcm_bytes"] == 1920 * 13, reqs_rec4
    finally:
        post_json(f"{fake_url}/_control", {}, {"asr_delays": [], "transcript": "合约测试"})

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
        f"timeout, manual + auto/realtime pre-VAD & in-flight abort/disconnect cancel + recovery verified"
    )
    return {"secrets_to_check": issued_secrets}


def test_real_ttl_expiration(server_home: Path, fake_port: int) -> set[str]:
    """Verify a naturally issued token expires once expire_seconds elapses."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ws_port, http_port = _reserve_distinct_ports(2)
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
            ws_port_1, http_port_1 = _reserve_distinct_ports(2)
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
            ws_port_2, http_port_2 = _reserve_distinct_ports(2)
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
            with _ReservedPortPool() as unused_pool:
                unused_pool.register_external("fake_provider", fake_port)
                unused_port = unused_pool.reserve_dead("unused_tts")
                unused_pool.assert_all_disjoint("tts_userinfo_probe")
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
    test_port_fixture_mutual_exclusion_and_diag_redaction()
    test_concurrent_registry_locking_and_auth_key()
    test_real_mode_refuses_disabled_or_missing_auth(server_home)
    test_real_vs_demo_config_persistence(server_home)
    test_demo_isolation_preserves_real_state(server_home)
    test_demo_pip_controlled_install_isolation(server_home)
    test_proxy_runtime_error_logs_redacted()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        fake_port, ws_port, http_port = _reserve_distinct_ports(3)

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
            test_auto_realtime_asr_cancel_unit(server_home)
            test_manual_listen_stop_queue_ordering_unit(server_home)

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
            nginx_tokens = test_real_nginx_log_isolation(ota_base, dev_a)
            caddy_tokens = test_real_caddy_adapt_and_routing(ota_base, dev_a)

            res = asyncio.run(
                _run_live_server_regressions(
                    ota_base=ota_base,
                    ws_url=ws_url,
                    fake_url=f"http://127.0.0.1:{fake_port}",
                    devices_file=devices_file,
                    auth_key=auth_key,
                    dev_a=dev_a,
                    dev_b=dev_b,
                    server_home=server_home,
                )
            )
            res["secrets_to_check"].update(nginx_tokens)
            res["secrets_to_check"].update(caddy_tokens)
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
