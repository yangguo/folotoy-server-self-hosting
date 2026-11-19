#!/usr/bin/env python3
"""Write the upstream data/.config.yaml used by the pinned xiaozhi-server."""

import os
import secrets
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "config" / "server.config.example.yaml"
PLACEHOLDER = "replace-with-a-long-random-string"


def main():
    server_home = Path(os.environ["XIAOZHI_HOME"]).resolve()
    auth_key = os.environ.get("PASSPORT_AUTH_KEY", "").strip()
    if not auth_key or auth_key == PLACEHOLDER or "你" in auth_key:
        key_file = Path(os.environ.get("PASSPORT_AUTH_FILE", ROOT / "runtime" / "auth_key"))
        if key_file.is_file():
            auth_key = key_file.read_text().strip()
        else:
            auth_key = secrets.token_hex(32)
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_text(auth_key + "\n")
            os.chmod(key_file, 0o600)
    if len(auth_key) < 32 or auth_key == PLACEHOLDER:
        sys.exit("PASSPORT_AUTH_KEY must be at least 32 characters and not the example placeholder")

    ws = os.environ.get("PASSPORT_PUBLIC_WS", "ws://127.0.0.1:18010/xiaozhi/v1/")
    http = os.environ.get(
        "PASSPORT_PUBLIC_HTTP", "http://127.0.0.1:18013/mcp/vision/explain"
    )
    fake = os.environ.get("PASSPORT_FAKE_BASE", "http://127.0.0.1:18019").rstrip("/")
    config = yaml.safe_load(EXAMPLE.read_text())
    config["server"]["auth_key"] = auth_key
    config["server"]["ip"] = os.environ.get("PASSPORT_BIND", "127.0.0.1")
    if os.environ.get("PASSPORT_WS_BIND_PORT"):
        config["server"]["port"] = int(os.environ["PASSPORT_WS_BIND_PORT"])
    if os.environ.get("PASSPORT_HTTP_BIND_PORT"):
        config["server"]["http_port"] = int(os.environ["PASSPORT_HTTP_BIND_PORT"])
    config["server"]["websocket"] = ws
    config["server"]["vision_explain"] = http
    config["ASR"]["PassportLocalASR"]["base_url"] = fake + "/v1/audio/transcriptions"
    config["LLM"]["PassportLocalLLM"]["base_url"] = fake + "/v1"
    config["TTS"]["PassportLocalTTS"]["api_url"] = fake + "/v1/audio/speech"
    target = server_home / "data" / ".config.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
    os.chmod(target, 0o600)
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
