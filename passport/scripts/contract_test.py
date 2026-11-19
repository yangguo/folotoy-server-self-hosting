#!/usr/bin/env python3
"""Exercise a running xiaozhi-server. This is not a device test.

The model behind ASR/LLM/TTS is passport/fake_provider.py. A passing run
shows the pinned server's OTA, WebSocket, Opus and abort behavior. It does
not show that a real model understood speech or that a Passport played audio.
"""

import argparse
import asyncio
import json
import math
import struct
import sys
import urllib.error
import urllib.request

import opuslib_next
from opuslib_next import constants
import websockets


def post_ota(base, headers, body=b"{}"):
    request = urllib.request.Request(
        base.rstrip("/") + "/xiaozhi/ota/",
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return exc.code, payload


def opus_frames(count=4):
    encoder = opuslib_next.Encoder(16000, 1, constants.APPLICATION_AUDIO)
    frames = []
    for index in range(count):
        pcm = bytearray()
        for sample in range(960):
            value = int(
                6000
                * math.sin(2 * math.pi * 330 * (index * 960 + sample) / 16000)
            )
            pcm += struct.pack("<h", value)
        frames.append(encoder.encode(bytes(pcm), 960))
    return frames


async def read_json(ws, timeout):
    raw = await asyncio.wait_for(ws.recv(), timeout)
    if isinstance(raw, bytes):
        return {"_binary": raw}
    return json.loads(raw)


async def expect_hello(ws):
    for _ in range(8):
        message = await read_json(ws, 10)
        if message.get("type") == "hello":
            return message
    raise AssertionError("server hello was not received")


async def session(ws_url, token, device_id, client_id, abort):
    headers = {
        "Device-Id": device_id,
        "Client-Id": client_id,
        "Protocol-Version": "1",
        "Authorization": f"Bearer {token}",
    }
    async with websockets.connect(ws_url, additional_headers=headers) as ws:
        await ws.send(
            json.dumps(
                {
                    "type": "hello",
                    "version": 1,
                    "transport": "websocket",
                    "features": {"mcp": True},
                    "audio_params": {
                        "format": "opus",
                        "sample_rate": 16000,
                        "channels": 1,
                        "frame_duration": 60,
                    },
                }
            )
        )
        hello = await expect_hello(ws)
        session_id = hello["session_id"]
        # Upstream initializes ASR on a background task after hello. Frames
        # that arrive before that task finishes are dropped.
        await asyncio.sleep(3)
        await ws.send(
            json.dumps(
                {
                    "session_id": session_id,
                    "type": "listen",
                    "state": "start",
                    "mode": "manual",
                }
            )
        )
        for frame in opus_frames(8):
            await ws.send(frame)
        await asyncio.sleep(0.5)
        await ws.send(
            json.dumps(
                {"session_id": session_id, "type": "listen", "state": "stop"}
            )
        )
        texts = []
        opus_bytes = 0
        decoded = 0
        states = []
        decoder = opuslib_next.Decoder(16000, 1)
        aborted = False
        deadline = asyncio.get_event_loop().time() + 20
        while asyncio.get_event_loop().time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), 2)
            except asyncio.TimeoutError:
                if states and states[-1] == "stop":
                    break
                continue
            if isinstance(raw, bytes):
                opus_bytes += len(raw)
                pcm = decoder.decode(raw, 960)
                decoded += len(pcm)
                if abort and not aborted and opus_bytes > 0:
                    await ws.send(
                        json.dumps(
                            {
                                "session_id": session_id,
                                "type": "abort",
                                "reason": "wake_word_detected",
                            }
                        )
                    )
                    aborted = True
                continue
            message = json.loads(raw)
            if message.get("type") == "stt":
                texts.append(message.get("text", ""))
            if message.get("type") == "tts":
                states.append(message.get("state"))
                if message.get("state") == "stop":
                    break
        return {
            "session_id": session_id,
            "hello": {
                "transport": hello.get("transport"),
                "version": hello.get("version"),
                "audio_params": hello.get("audio_params"),
            },
            "stt": texts,
            "tts_states": states,
            "opus_bytes": opus_bytes,
            "decoded_pcm_bytes": decoded,
            "aborted": aborted,
        }


async def reject_bad_token(ws_url, device_id, client_id):
    headers = {
        "Device-Id": device_id,
        "Client-Id": client_id,
        "Protocol-Version": "1",
        "Authorization": "Bearer not-a-valid-token",
    }
    async with websockets.connect(ws_url, additional_headers=headers) as ws:
        try:
            raw = await asyncio.wait_for(ws.recv(), 5)
        except Exception as exc:
            return {"received": None, "error": str(exc)}
        text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
        return {"received": text}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ota", default="http://127.0.0.1:18013")
    parser.add_argument("--device-id", default="aa:bb:cc:dd:ee:10")
    parser.add_argument("--client-id", default="passport-contract-client")
    args = parser.parse_args()
    report = {"kind": "upstream-server-with-local-fake-providers"}
    missing_device = post_ota(args.ota, {})
    report["ota_missing_device_id"] = {
        "status": missing_device[0],
        "body": missing_device[1],
    }
    status, body = post_ota(
        args.ota,
        {"Device-Id": args.device_id, "Client-Id": args.client_id},
        json.dumps(
            {
                "application": {"version": "0.0.0"},
                "board": {"type": "ai-passport"},
            }
        ).encode(),
    )
    websocket = body.get("websocket") or {}
    token = websocket.get("token", "")
    url = websocket.get("url", "")
    report["ota"] = {
        "status": status,
        "websocket": {
            "url": url,
            "token_present": bool(token),
        },
        "has_mqtt": "mqtt" in body,
        "firmware": body.get("firmware"),
        "has_server_time": "server_time" in body,
    }
    if not token or not url:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        sys.exit("OTA did not return a websocket token")
    bad = asyncio.run(
        reject_bad_token(url, args.device_id, args.client_id)
    )
    report["bad_token"] = bad
    first = asyncio.run(
        session(url, token, args.device_id, args.client_id, abort=False)
    )
    second = asyncio.run(
        session(url, token, args.device_id, args.client_id, abort=True)
    )
    report["turn"] = first
    report["abort_turn"] = second
    report["reconnect_new_session"] = first["session_id"] != second["session_id"]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    problems = []
    if report["ota_missing_device_id"]["status"] != 200:
        problems.append("missing device id did not return the server error JSON")
    if report["ota_missing_device_id"]["body"].get("success") is not False:
        problems.append("missing device id was not rejected")
    if report["ota"]["has_mqtt"]:
        problems.append("OTA included MQTT; this profile is WebSocket only")
    audio = first["hello"]["audio_params"] or {}
    if audio.get("sample_rate") != 16000 or audio.get("frame_duration") != 60:
        problems.append(f"hello audio params were {audio}")
    if first["hello"]["transport"] != "websocket":
        problems.append("hello transport was not websocket")
    if "合约测试" not in "".join(first["stt"]):
        problems.append(f"STT text was {first['stt']}")
    if first["decoded_pcm_bytes"] <= 0 or "start" not in first["tts_states"]:
        problems.append("no opus playback was produced")
    if "stop" not in first["tts_states"]:
        problems.append("tts stop was not observed")
    if "认证失败" not in (bad.get("received") or ""):
        problems.append(f"bad token result was {bad}")
    if not second["aborted"] or "stop" not in second["tts_states"]:
        problems.append(f"abort turn was {second}")
    if not report["reconnect_new_session"]:
        problems.append("reconnect reused the session id")
    if problems:
        print("FAILED", *problems, sep="\n")
        sys.exit(1)
    print("PASSED upstream websocket contract with local fake providers")


if __name__ == "__main__":
    main()
