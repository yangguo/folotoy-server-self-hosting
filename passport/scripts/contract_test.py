#!/usr/bin/env python3
"""Exercise a running xiaozhi-server. This is not a device test.

The model behind ASR/LLM/TTS is passport/fake_provider.py. A passing run
verifies provisioned OTA authentication, immediate post-hello first turn (0 s
wait), strict abort truncation (cannot pass on natural playback completion),
same-session post-abort recovery, unclean disconnect reconnect recovery, and
explicit websocket.version=1 in OTA.
"""

import argparse
import asyncio
import json
import math
import os
import struct
import sys
import time
import urllib.error
import urllib.request

import opuslib_next
from opuslib_next import constants
import websockets

LONG_TTS_SECONDS = 6.0
DEFAULT_TTS_SECONDS = 1.5
MAX_ABORT_TOTAL_FRAMES = 18
MAX_ABORT_TAIL_FRAMES = 12
MAX_ABORT_STOP_LATENCY_S = 2.0


def post_json(url: str, headers: dict, payload: dict | bytes = b"{}") -> tuple[int, dict]:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return exc.code, parsed


def post_ota(base: str, headers: dict, body: bytes = b"{}", secret: str = "") -> tuple[int, dict]:
    root = base.rstrip("/")
    path = f"{root}/xiaozhi/ota/d/{secret}/" if secret else f"{root}/xiaozhi/ota/"
    return post_json(path, headers, body)


def opus_frames(count: int = 8) -> list[bytes]:
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


async def read_json(ws, timeout: float) -> dict:
    raw = await asyncio.wait_for(ws.recv(), timeout)
    if isinstance(raw, bytes):
        return {"_binary": raw}
    return json.loads(raw)


async def expect_hello(ws) -> dict:
    for _ in range(8):
        message = await read_json(ws, 10)
        if message.get("type") == "hello":
            return message
    raise AssertionError("server hello was not received")


async def send_hello(ws) -> dict:
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
    return await expect_hello(ws)


async def run_turn(
    ws,
    session_id: str,
    abort_after_frames: int | None = None,
    timeout_s: float = 20.0,
) -> dict:
    """Execute one manual listen -> ASR -> TTS turn on an already-open WebSocket.

    Does NOT sleep after hello, verifying the server accepts first-turn audio
    immediately once hello is emitted.
    """
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
    await asyncio.sleep(0.15)
    await ws.send(
        json.dumps({"session_id": session_id, "type": "listen", "state": "stop"})
    )

    texts = []
    opus_bytes = 0
    decoded = 0
    opus_frame_count = 0
    frames_before_abort = 0
    tail_frames_after_abort = 0
    frames_after_stop = 0
    states = []
    decoder = opuslib_next.Decoder(16000, 1)
    aborted = False
    abort_sent_at = None
    stop_received_at = None
    deadline = asyncio.get_running_loop().time() + timeout_s

    while asyncio.get_running_loop().time() < deadline:
        try:
            raw = await asyncio.wait_for(ws.recv(), 2.0)
        except asyncio.TimeoutError:
            if states and states[-1] == "stop":
                break
            continue
        if isinstance(raw, bytes):
            opus_frame_count += 1
            opus_bytes += len(raw)
            pcm = decoder.decode(raw, 960)
            decoded += len(pcm)
            if aborted:
                tail_frames_after_abort += 1
            if (
                abort_after_frames is not None
                and not aborted
                and opus_frame_count >= abort_after_frames
            ):
                frames_before_abort = opus_frame_count
                abort_sent_at = time.monotonic()
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
        elif message.get("type") == "tts":
            states.append(message.get("state"))
            if message.get("state") == "stop":
                stop_received_at = time.monotonic()
                break

    if aborted and stop_received_at is not None:
        # Drain briefly to ensure no trailing audio arrives after tts.stop.
        drain_until = asyncio.get_running_loop().time() + 0.35
        while asyncio.get_running_loop().time() < drain_until:
            try:
                extra = await asyncio.wait_for(ws.recv(), 0.1)
            except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                break
            if isinstance(extra, bytes):
                frames_after_stop += 1

    abort_stop_latency_s = (
        round(stop_received_at - abort_sent_at, 4)
        if abort_sent_at is not None and stop_received_at is not None
        else None
    )

    return {
        "session_id": session_id,
        "stt": texts,
        "tts_states": states,
        "opus_frame_count": opus_frame_count,
        "opus_bytes": opus_bytes,
        "decoded_pcm_bytes": decoded,
        "aborted": aborted,
        "frames_before_abort": frames_before_abort,
        "tail_frames_after_abort": tail_frames_after_abort,
        "frames_after_stop": frames_after_stop,
        "abort_stop_latency_s": abort_stop_latency_s,
    }


def validate_abort_metrics(result: dict, expected_long_frames_min: int = 50) -> list[str]:
    """Strictly assert that abort truncated TTS playback early rather than playing to completion."""
    problems = []
    if not result.get("aborted"):
        problems.append("abort was never sent")
    if "stop" not in (result.get("tts_states") or []):
        problems.append("tts stop was not observed on abort")
    total_frames = int(result.get("opus_frame_count") or 0)
    tail_frames = int(result.get("tail_frames_after_abort") or 0)
    after_stop = int(result.get("frames_after_stop") or 0)
    latency = result.get("abort_stop_latency_s")

    if total_frames >= expected_long_frames_min:
        problems.append(
            f"abort did not truncate long TTS audio ({total_frames} frames >= {expected_long_frames_min})"
        )
    if total_frames > MAX_ABORT_TOTAL_FRAMES:
        problems.append(
            f"too many total frames during aborted playback: {total_frames} > {MAX_ABORT_TOTAL_FRAMES}"
        )
    if tail_frames > MAX_ABORT_TAIL_FRAMES:
        problems.append(
            f"too many tail frames after abort: {tail_frames} > {MAX_ABORT_TAIL_FRAMES}"
        )
    if after_stop != 0:
        problems.append(f"received {after_stop} audio frames after tts.stop")
    if latency is None or latency > MAX_ABORT_STOP_LATENCY_S:
        problems.append(
            f"abort->stop latency too high: {latency!r} > {MAX_ABORT_STOP_LATENCY_S}s"
        )
    return problems


async def reject_bad_token(ws_url: str, device_id: str, client_id: str) -> dict:
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


async def run_ws_contract(
    ws_url: str,
    token: str,
    device_id: str,
    client_id: str,
    fake_control_url: str,
) -> dict:
    headers = {
        "Device-Id": device_id,
        "Client-Id": client_id,
        "Protocol-Version": "1",
        "Authorization": f"Bearer {token}",
    }

    # 1. Immediate first turn (0 s wait after hello), then strict abort + same-session recovery.
    async with websockets.connect(ws_url, additional_headers=headers) as ws:
        hello1 = await send_hello(ws)
        first = await run_turn(ws, hello1["session_id"], abort_after_frames=None)

        post_json(
            f"{fake_control_url.rstrip('/')}/_control",
            {},
            {"tts_seconds": LONG_TTS_SECONDS},
        )
        try:
            abort_turn = await run_turn(ws, hello1["session_id"], abort_after_frames=2)
        finally:
            post_json(
                f"{fake_control_url.rstrip('/')}/_control",
                {},
                {"tts_seconds": DEFAULT_TTS_SECONDS},
            )

        post_abort_turn = await run_turn(ws, hello1["session_id"], abort_after_frames=None)

    # 2. Abrupt mid-TTS transport drop, followed by reconnect recovery.
    post_json(
        f"{fake_control_url.rstrip('/')}/_control",
        {},
        {"tts_seconds": LONG_TTS_SECONDS},
    )
    dropped_session_id = ""
    try:
        ws_drop = await websockets.connect(ws_url, additional_headers=headers)
        try:
            hello_drop = await send_hello(ws_drop)
            dropped_session_id = hello_drop["session_id"]
            await ws_drop.send(
                json.dumps(
                    {
                        "session_id": dropped_session_id,
                        "type": "listen",
                        "state": "start",
                        "mode": "manual",
                    }
                )
            )
            for frame in opus_frames(8):
                await ws_drop.send(frame)
            await asyncio.sleep(0.15)
            await ws_drop.send(
                json.dumps(
                    {"session_id": dropped_session_id, "type": "listen", "state": "stop"}
                )
            )
            frames_seen = 0
            while frames_seen < 2:
                msg = await asyncio.wait_for(ws_drop.recv(), 10)
                if isinstance(msg, bytes):
                    frames_seen += 1
            if ws_drop.transport is not None:
                ws_drop.transport.abort()
        finally:
            if ws_drop.transport is not None and not ws_drop.transport.is_closing():
                ws_drop.transport.abort()
    finally:
        post_json(
            f"{fake_control_url.rstrip('/')}/_control",
            {},
            {"tts_seconds": DEFAULT_TTS_SECONDS},
        )

    async with websockets.connect(ws_url, additional_headers=headers) as ws_rec:
        hello_rec = await send_hello(ws_rec)
        reconnect_turn = await run_turn(
            ws_rec, hello_rec["session_id"], abort_after_frames=None
        )

    return {
        "hello": {
            "transport": hello1.get("transport"),
            "version": hello1.get("version"),
            "audio_params": hello1.get("audio_params"),
        },
        "first_turn_immediate": first,
        "abort_turn": abort_turn,
        "post_abort_same_session_turn": post_abort_turn,
        "abrupt_drop_session_id": dropped_session_id,
        "reconnect_after_drop_turn": reconnect_turn,
        "reconnect_new_session": dropped_session_id != reconnect_turn["session_id"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ota", default="http://127.0.0.1:18013")
    parser.add_argument("--fake-control", default="http://127.0.0.1:18019")
    parser.add_argument("--device-id", default="aa:bb:cc:dd:ee:10")
    parser.add_argument("--client-id", default="passport-contract-client")
    parser.add_argument(
        "--ota-secret",
        default=os.environ.get("PASSPORT_TEST_OTA_SECRET", ""),
    )
    args = parser.parse_args()
    if not args.ota_secret:
        sys.exit("OTA secret must be provided via --ota-secret or PASSPORT_TEST_OTA_SECRET")

    post_json(f"{args.fake_control.rstrip('/')}/_control", {}, {"reset": True})

    report: dict = {"kind": "upstream-server-with-local-fake-providers"}
    missing_device = post_ota(args.ota, {})
    report["ota_missing_device_id"] = {
        "status": missing_device[0],
        "body": missing_device[1],
    }
    missing_secret = post_ota(
        args.ota,
        {"Device-Id": args.device_id, "Client-Id": args.client_id},
    )
    report["ota_missing_credential"] = {
        "status": missing_secret[0],
        "has_websocket": "websocket" in missing_secret[1],
    }

    status, body = post_ota(
        args.ota,
        {"Device-Id": args.device_id, "Client-Id": args.client_id},
        json.dumps(
            {
                "application": {"version": "0.0.0"},
                "board": {"type": "ai-passport"},
            }
        ).encode("utf-8"),
        secret=args.ota_secret,
    )
    websocket = body.get("websocket") or {}
    token = websocket.get("token", "")
    url = websocket.get("url", "")
    report["ota"] = {
        "status": status,
        "websocket": {
            "url": url,
            "version": websocket.get("version"),
            "token_present": bool(token),
        },
        "has_mqtt": "mqtt" in body,
        "firmware": body.get("firmware"),
        "has_server_time": "server_time" in body,
    }
    if not token or not url:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        sys.exit("OTA did not return a websocket token")

    report["bad_token"] = asyncio.run(
        reject_bad_token(url, args.device_id, args.client_id)
    )
    ws_report = asyncio.run(
        run_ws_contract(
            url, token, args.device_id, args.client_id, args.fake_control
        )
    )
    report.update(ws_report)
    print(json.dumps(report, ensure_ascii=False, indent=2))

    problems = []
    if report["ota_missing_device_id"]["status"] != 400:
        problems.append("missing device id did not return HTTP 400")
    if report["ota_missing_device_id"]["body"].get("success") is not False:
        problems.append("missing device id was not rejected")
    if report["ota_missing_credential"]["status"] != 401 or report["ota_missing_credential"]["has_websocket"]:
        problems.append("OTA without device credential was not rejected with 401")
    if report["ota"]["status"] != 200:
        problems.append(f"provisioned OTA returned status {report['ota']['status']}")
    if report["ota"]["has_mqtt"]:
        problems.append("OTA included MQTT; this profile is WebSocket only")
    if report["ota"]["websocket"].get("version") != 1:
        problems.append(f"OTA websocket.version was {report['ota']['websocket'].get('version')}, expected 1")

    audio = report["hello"]["audio_params"] or {}
    if audio.get("sample_rate") != 16000 or audio.get("frame_duration") != 60:
        problems.append(f"hello audio params were {audio}")
    if report["hello"]["transport"] != "websocket":
        problems.append("hello transport was not websocket")

    for turn_key in (
        "first_turn_immediate",
        "post_abort_same_session_turn",
        "reconnect_after_drop_turn",
    ):
        turn = report[turn_key]
        if "合约测试" not in "".join(turn["stt"]):
            problems.append(f"{turn_key} STT text was {turn['stt']}")
        if turn["decoded_pcm_bytes"] <= 0 or "start" not in turn["tts_states"]:
            problems.append(f"{turn_key} produced no opus playback")
        if "stop" not in turn["tts_states"]:
            problems.append(f"{turn_key} did not observe tts stop")

    if "认证失败" not in (report["bad_token"].get("received") or ""):
        problems.append(f"bad token result was {report['bad_token']}")

    problems.extend(validate_abort_metrics(report["abort_turn"]))

    if not report["reconnect_new_session"]:
        problems.append("reconnect after abrupt drop reused the session id")

    if problems:
        print("FAILED", *problems, sep="\n")
        sys.exit(1)
    print("PASSED tightened upstream websocket contract with local fake providers")


if __name__ == "__main__":
    main()
