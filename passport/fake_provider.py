#!/usr/bin/env python3
"""Local stand-in for ASR, LLM, and TTS HTTP APIs with test delay/failure controls.

This is not speech understanding or synthesis. It returns a configurable
transcript, a configurable chat reply, and a sine-wave WAV so the real
xiaozhi-server process can complete its WebSocket session without a cloud model
key, and so regression tests can simulate slow, hanging, or failing providers.
"""

import argparse
import io
import json
import math
import select
import socket
import struct
import threading
import time
import wave
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_KEY = "local-fake-provider"
DEFAULT_TRANSCRIPT = "合约测试"
DEFAULT_REPLY = "收到。这是本地假模型，不是语音理解。"


def sine_wav(seconds: float = 1.5, sample_rate: int = 16000, frequency: int = 440) -> bytes:
    frames = max(1, int(seconds * sample_rate))
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        pcm = bytearray()
        for i in range(frames):
            sample = int(8000 * math.sin(2 * math.pi * frequency * i / sample_rate))
            pcm += struct.pack("<h", sample)
        wav.writeframes(pcm)
    return buffer.getvalue()


class ProviderState:
    """Thread-safe test control and observability state for fake_provider."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.asr_delays: list[float] = []
            self.asr_status: int = 200
            self.asr_error_body: str = ""
            self.tts_status: int = 200
            self.tts_error_body: str = ""
            self.accepted_api_keys: list[str] = []
            self.tts_seconds: float = 1.5
            self._wav_cache_seconds: float = 1.5
            self._wav_cache: bytes = sine_wav(1.5)
            self.transcript: str = DEFAULT_TRANSCRIPT
            self.reply: str = DEFAULT_REPLY
            self.next_asr_req_id: int = 1
            self.asr_requests: dict[int, dict] = {}
            self.asr_in_flight: int = 0
            self.asr_total: int = 0
            self.asr_completed: int = 0
            self.asr_aborted: int = 0
            self.llm_total: int = 0
            self.tts_total: int = 0

    def get_wav(self) -> bytes:
        with self.lock:
            if self.tts_seconds != self._wav_cache_seconds:
                self._wav_cache = sine_wav(self.tts_seconds)
                self._wav_cache_seconds = self.tts_seconds
            return self._wav_cache

    def stats(self) -> dict:
        with self.lock:
            in_flight_ids = sorted(
                req_id
                for req_id, info in self.asr_requests.items()
                if info["state"] == "in_flight"
            )
            recent_requests = [
                dict(self.asr_requests[req_id])
                for req_id in sorted(self.asr_requests.keys())[-50:]
            ]
            return {
                "asr_in_flight": self.asr_in_flight,
                "asr_in_flight_ids": in_flight_ids,
                "asr_requests": recent_requests,
                "asr_total": self.asr_total,
                "asr_completed": self.asr_completed,
                "asr_aborted": self.asr_aborted,
                "llm_total": self.llm_total,
                "tts_total": self.tts_total,
                "tts_seconds": self.tts_seconds,
                "asr_status": self.asr_status,
                "tts_status": self.tts_status,
                "pending_asr_delays": list(self.asr_delays),
            }


STATE = ProviderState()


def _client_disconnected(sock: socket.socket) -> bool:
    """Return True if the peer closed the TCP connection while delaying."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        if not readable:
            return False
        data = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        return data == b""
    except (BlockingIOError, InterruptedError):
        return False
    except OSError:
        return True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        safe_args = tuple(
            arg.split("?", 1)[0] if isinstance(arg, str) and "?" in arg else arg
            for arg in args
        )
        print("fake-provider", self.address_string(), fmt % safe_args, flush=True)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        if header == f"Bearer {FAKE_KEY}":
            return True
        with STATE.lock:
            extra = list(STATE.accepted_api_keys)
        return any(header == f"Bearer {key}" for key in extra if key)

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reject(self, code: int, message: str) -> None:
        self._send_json(code, {"error": message})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/_stats":
            self._send_json(200, STATE.stats())
            return
        self._reject(404, "unknown fake provider path")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length > 0 else b""
        path = self.path.split("?", 1)[0]

        if path == "/_control":
            data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            if data.get("reset"):
                STATE.reset()
            with STATE.lock:
                if "asr_delays" in data:
                    STATE.asr_delays = [float(x) for x in (data["asr_delays"] or [])]
                if "asr_status" in data:
                    STATE.asr_status = int(data["asr_status"])
                if "asr_error_body" in data:
                    STATE.asr_error_body = str(data["asr_error_body"] or "")
                if "tts_status" in data:
                    STATE.tts_status = int(data["tts_status"])
                if "tts_error_body" in data:
                    STATE.tts_error_body = str(data["tts_error_body"] or "")
                if "accepted_api_keys" in data:
                    STATE.accepted_api_keys = [
                        str(x) for x in (data["accepted_api_keys"] or []) if x
                    ]
                if "tts_seconds" in data:
                    STATE.tts_seconds = float(data["tts_seconds"])
                if "transcript" in data:
                    STATE.transcript = str(data["transcript"])
                if "reply" in data:
                    STATE.reply = str(data["reply"])
            self._send_json(200, {"ok": True, **STATE.stats()})
            return

        if not self._authorized():
            self._reject(401, "fake provider rejected credential")
            return

        if path == "/v1/audio/transcriptions":
            with STATE.lock:
                req_id = STATE.next_asr_req_id
                STATE.next_asr_req_id += 1
                STATE.asr_requests[req_id] = {
                    "id": req_id,
                    "state": "in_flight",
                    "started_at": time.monotonic(),
                    "ended_at": None,
                }
                STATE.asr_in_flight += 1
                STATE.asr_total += 1
                delay = STATE.asr_delays.pop(0) if STATE.asr_delays else 0.0
                status = STATE.asr_status
                error_body = STATE.asr_error_body
                transcript = STATE.transcript
            aborted = False
            try:
                if delay > 0:
                    deadline = time.monotonic() + delay
                    while time.monotonic() < deadline:
                        if _client_disconnected(self.connection):
                            aborted = True
                            break
                        time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
                if aborted:
                    with STATE.lock:
                        STATE.asr_aborted += 1
                        STATE.asr_requests[req_id]["state"] = "aborted"
                        STATE.asr_requests[req_id]["ended_at"] = time.monotonic()
                    return
                if status != 200:
                    with STATE.lock:
                        STATE.asr_requests[req_id]["state"] = "error"
                        STATE.asr_requests[req_id]["ended_at"] = time.monotonic()
                    self._reject(status, error_body or f"simulated ASR error {status}")
                    return
                self._send_json(200, {"text": transcript})
                with STATE.lock:
                    STATE.asr_completed += 1
                    STATE.asr_requests[req_id]["state"] = "completed"
                    STATE.asr_requests[req_id]["ended_at"] = time.monotonic()
            except (BrokenPipeError, ConnectionResetError):
                with STATE.lock:
                    STATE.asr_aborted += 1
                    STATE.asr_requests[req_id]["state"] = "aborted"
                    STATE.asr_requests[req_id]["ended_at"] = time.monotonic()
            finally:
                with STATE.lock:
                    STATE.asr_in_flight = max(0, STATE.asr_in_flight - 1)
                    if STATE.asr_requests[req_id]["state"] == "in_flight":
                        STATE.asr_requests[req_id]["state"] = "error"
                        STATE.asr_requests[req_id]["ended_at"] = time.monotonic()
            return

        if path == "/v1/chat/completions":
            with STATE.lock:
                STATE.llm_total += 1
                reply = STATE.reply
            chunk = {
                "id": "fake",
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": reply},
                        "finish_reason": None,
                    }
                ],
            }
            payload = (
                f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                "data: [DONE]\n\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/v1/audio/speech":
            with STATE.lock:
                STATE.tts_total += 1
                tts_status = STATE.tts_status
                tts_error_body = STATE.tts_error_body
            if tts_status != 200:
                self._reject(tts_status, tts_error_body or f"simulated TTS error {tts_status}")
                return
            wav_bytes = STATE.get_wav()
            self.send_response(200)
            self.send_header("Content-Type", "audio/wav")
            self.send_header("Content-Length", str(len(wav_bytes)))
            self.end_headers()
            self.wfile.write(wav_bytes)
            return

        self._reject(404, "unknown fake provider path")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18019)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"fake provider listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
