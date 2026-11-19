#!/usr/bin/env python3
"""Local stand-in for ASR, LLM and TTS HTTP APIs.

This is not speech understanding or synthesis. It returns a fixed transcript,
a fixed chat reply, and a sine-wave WAV so the real xiaozhi-server process can
complete its WebSocket session without a cloud model key.
"""

import argparse
import io
import json
import math
import struct
import wave
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_KEY = "local-fake-provider"
TRANSCRIPT = "合约测试"
REPLY = "收到。这是本地假模型，不是语音理解。"


def sine_wav(seconds=1.5, sample_rate=16000, frequency=440):
    frames = int(seconds * sample_rate)
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


WAV = sine_wav()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("fake-provider", self.address_string(), fmt % args)

    def _authorized(self):
        header = self.headers.get("Authorization", "")
        return header == f"Bearer {FAKE_KEY}"

    def _reject(self, code, message):
        body = json.dumps({"error": message}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if not self._authorized():
            self._reject(401, "fake provider rejected credential")
            return
        path = self.path.split("?", 1)[0]
        if path == "/v1/audio/transcriptions":
            body = json.dumps({"text": TRANSCRIPT}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/v1/chat/completions":
            chunk = {
                "id": "fake",
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": REPLY},
                        "finish_reason": None,
                    }
                ],
            }
            payload = (
                f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                "data: [DONE]\n\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/v1/audio/speech":
            self.send_response(200)
            self.send_header("Content-Type", "audio/wav")
            self.send_header("Content-Length", str(len(WAV)))
            self.end_headers()
            self.wfile.write(WAV)
            return
        self._reject(404, "unknown fake provider path")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18019)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"fake provider listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
