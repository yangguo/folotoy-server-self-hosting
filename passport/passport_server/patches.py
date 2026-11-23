"""Ordered runtime patches applied on top of pinned xiaozhi-server v0.9.8."""

import asyncio
import contextvars
import json
import os
import queue
import time
import traceback
from typing import Optional
from urllib.parse import urlsplit

import requests
from aiohttp import web

from passport_server.device_auth import (
    PassportDeviceAuth,
    normalize_device_id,
    validate_runtime_auth_config,
)
from passport_server.redaction import (
    has_sensitive_query_params,
    install_stdlib_redaction,
    redact_text,
    register_secrets_from_config,
    safe_endpoint_label,
    sanitize_url_or_path,
    strip_sensitive_ws_headers,
)

_PATCHES_APPLIED = False
_IN_INTERNAL_BARGE_IN: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "_passport_in_internal_barge_in", default=False
)
_CURRENT_AUDIO_FRAME_EPOCH: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "_passport_audio_frame_epoch", default=None
)


class _EpochAudioFrame:
    """Inbound PCM frame tagged with the connection audio epoch active when queued."""

    __slots__ = ("epoch", "pcm_frame")

    def __init__(self, epoch: int, pcm_frame: bytes):
        self.epoch = epoch
        self.pcm_frame = pcm_frame


class _QueuedListenStop:
    """Control marker ordered behind prior PCM frames in asr_audio_queue for listen.stop."""

    __slots__ = ("epoch", "mode")

    def __init__(self, epoch: int, mode: Optional[str] = None):
        self.epoch = epoch
        self.mode = mode


def _install_epoch_queue_put(conn, audio_q) -> None:
    """Wrap put() on custom asr_audio_queue instances so frames stay epoch-tagged and close-guarded."""
    if (
        audio_q is None
        or isinstance(audio_q, _PassportEpochAudioQueue)
        or getattr(audio_q, "_passport_epoch_put_conn", None) is conn
    ):
        return
    original_put = getattr(audio_q, "put", None)
    if not callable(original_put):
        return

    def wrapped_put(item, block=True, timeout=None):
        stop_ev = getattr(conn, "stop_event", None)
        if stop_ev is not None and stop_ev.is_set():
            return
        if not isinstance(item, (_EpochAudioFrame, _QueuedListenStop)):
            epoch = int(getattr(conn, "_passport_audio_epoch", 0) or 0)
            item = _EpochAudioFrame(epoch, item)
        return original_put(item, block=block, timeout=timeout)

    try:
        audio_q.put = wrapped_put
        audio_q._passport_epoch_put_conn = conn
    except Exception:
        pass


class _PassportEpochAudioQueue(queue.Queue):
    """Queue that tags inbound PCM frames with the connection's current audio epoch."""

    def __init__(self, conn):
        super().__init__()
        self._conn = conn

    def put(self, item, block=True, timeout=None):
        stop_ev = getattr(self._conn, "stop_event", None)
        if stop_ev is not None and stop_ev.is_set():
            return
        if not isinstance(item, (_EpochAudioFrame, _QueuedListenStop)):
            epoch = int(getattr(self._conn, "_passport_audio_epoch", 0) or 0)
            item = _EpochAudioFrame(epoch, item)
        super().put(item, block=block, timeout=timeout)


def _redact_loguru_record(record: dict) -> None:
    """In-place loguru patcher that scrubs sensitive credentials before formatting."""
    if isinstance(record.get("message"), str):
        record["message"] = redact_text(record["message"])
    extra = record.get("extra")
    if isinstance(extra, dict):
        for key, value in list(extra.items()):
            if isinstance(value, str):
                extra[key] = redact_text(value)


def _next_conn_asr_gen(conn) -> int:
    """Increment and return the connection-scoped ASR task generation counter."""
    gen = int(getattr(conn, "_passport_asr_gen", 0) or 0) + 1
    conn._passport_asr_gen = gen
    return gen


def _is_stale_conn_asr_task(conn) -> bool:
    """Return True if the connection is closing/stopped or the current ASR task was superseded."""
    stop_ev = getattr(conn, "stop_event", None)
    if stop_ev is not None and stop_ev.is_set():
        return True
    try:
        current = asyncio.current_task()
    except RuntimeError:
        current = None
    if current is None:
        return False
    task_gen = getattr(current, "_passport_asr_gen", None)
    if task_gen is None:
        return False
    return task_gen != getattr(conn, "_passport_asr_gen", None)


def _cancel_conn_asr_task(conn, *, bump_gen: bool = True) -> Optional[asyncio.Task]:
    """Cancel any other in-flight connection ASR task without cancelling the calling task itself."""
    task = getattr(conn, "_passport_asr_task", None)
    try:
        current = asyncio.current_task()
    except RuntimeError:
        current = None
    # Barge-in inside startToChat calls handleAbortMessage from within the winning ASR task;
    # never self-cancel or invalidate that winning task's generation.
    if task is not None and task is current:
        return None
    if bump_gen:
        _next_conn_asr_gen(conn)
    if task is not None and not task.done():
        task.cancel()
        return task
    return None


def _dispatch_conn_asr_task(conn, asr_provider, asr_audio_task) -> Optional[asyncio.Task]:
    """Cancel any prior ASR task and dispatch handle_voice_stop as a connection-managed task."""
    stop_ev = getattr(conn, "stop_event", None)
    if stop_ev is not None and stop_ev.is_set():
        return None
    _cancel_conn_asr_task(conn, bump_gen=False)
    gen = _next_conn_asr_gen(conn)

    async def _run_voice_stop() -> None:
        try:
            await asr_provider.handle_voice_stop(conn, asr_audio_task)
        except asyncio.CancelledError:
            pass
        finally:
            if getattr(conn, "_passport_asr_task", None) is asyncio.current_task():
                conn._passport_asr_task = None

    task = asyncio.create_task(_run_voice_stop())
    task._passport_asr_gen = gen
    conn._passport_asr_task = task
    return task


def _next_conn_audio_epoch(conn) -> int:
    """Advance and return the connection-scoped inbound audio epoch."""
    epoch = int(getattr(conn, "_passport_audio_epoch", 0) or 0) + 1
    conn._passport_audio_epoch = epoch
    return epoch


def _discard_conn_pending_audio(conn) -> int:
    """Invalidate queued/pre-popped audio frames and reset VAD/ASR buffers on abort/close."""
    epoch = _next_conn_audio_epoch(conn)
    audio_q = getattr(conn, "asr_audio_queue", None)
    if audio_q is not None:
        while True:
            try:
                audio_q.get_nowait()
            except queue.Empty:
                break

    reset_states = getattr(conn, "reset_audio_states", None)
    if callable(reset_states):
        reset_states()
    else:
        for attr in ("client_audio_buffer", "client_voice_window", "asr_audio"):
            buf = getattr(conn, attr, None)
            if buf is not None and hasattr(buf, "clear"):
                buf.clear()
        conn.client_have_voice = False
        conn.client_voice_stop = False
        conn.last_is_voice = False
        conn.vad_last_voice_time = 0.0

    vad = getattr(conn, "vad", None)
    release_vad = getattr(vad, "release_conn_resources", None)
    if callable(release_vad):
        try:
            release_vad(conn)
        except Exception:
            pass
    for attr in ("_vad_state", "_vad_context"):
        if hasattr(conn, attr):
            try:
                delattr(conn, attr)
            except Exception:
                pass
    return epoch


def _is_internal_barge_in_context(conn) -> bool:
    """Return True when abort is triggered by internal playback barge-in rather than client abort."""
    if _IN_INTERNAL_BARGE_IN.get():
        return True
    try:
        current = asyncio.current_task()
    except RuntimeError:
        current = None
    return current is not None and getattr(conn, "_passport_asr_task", None) is current


def patch_logging() -> None:
    """Install loguru + stdlib redaction and disable loguru diagnose=True traceback leaks."""
    import sys
    from loguru import logger
    import config.logger as cfg_logger
    from config.config_loader import load_config
    from config.settings import check_config_file
    from core.utils.cache.manager import CacheType, cache_manager

    install_stdlib_redaction()

    def safe_formatter(record):
        record["extra"].setdefault("tag", record["name"])
        record["extra"].setdefault("selected_module", "00000000000000")
        record["selected_module"] = record["extra"]["selected_module"]
        _redact_loguru_record(record)
        return record["message"]

    def safe_setup_logging(config=None):
        if config is None:
            check_config_file()
            config = cache_manager.get(CacheType.CONFIG, "main_config")
            if config is None:
                config = asyncio.run(load_config())
        register_secrets_from_config(config)
        log_config = config["log"]
        if not cfg_logger._logger_initialized:
            logger.configure(
                extra={
                    "selected_module": log_config.get(
                        "selected_module", "00000000000000"
                    ),
                },
                patcher=_redact_loguru_record,
            )

            log_format = log_config.get(
                "log_format",
                "<green>{time:YYMMDD HH:mm:ss}</green>[{version}_{extra[selected_module]}][<light-blue>{extra[tag]}</light-blue>]-<level>{level}</level>-<light-green>{message}</light-green>",
            ).replace("{version}", cfg_logger.SERVER_VERSION)
            log_format_file = log_config.get(
                "log_format_file",
                "{time:YYYY-MM-DD HH:mm:ss} - {version}_{extra[selected_module]} - {name} - {level} - {extra[tag]} - {message}",
            ).replace("{version}", cfg_logger.SERVER_VERSION)

            log_level = log_config.get("log_level", "INFO")
            log_dir = log_config.get("log_dir", "tmp")
            log_file = log_config.get("log_file", "server.log")
            data_dir = log_config.get("data_dir", "data")

            os.makedirs(log_dir, exist_ok=True)
            os.makedirs(data_dir, exist_ok=True)

            logger.remove()
            logger.add(
                sys.stdout,
                format=log_format,
                level=log_level,
                filter=safe_formatter,
                backtrace=False,
                diagnose=False,
            )
            log_file_path = os.path.join(log_dir, log_file)
            logger.add(
                log_file_path,
                format=log_format_file,
                level=log_level,
                filter=safe_formatter,
                rotation="10 MB",
                retention="30 days",
                compression=None,
                encoding="utf-8",
                enqueue=True,
                backtrace=False,
                diagnose=False,
            )
            cfg_logger._logger_initialized = True
        return logger

    cfg_logger.formatter = safe_formatter
    cfg_logger.setup_logging = safe_setup_logging
    cfg_logger.setup_logging()


def patch_openai_asr() -> None:
    """Replace upstream synchronous blocking OpenAI ASR provider with async httpx implementation."""
    import core.providers.asr.openai as openai_asr
    from passport_server.async_openai_asr import AsyncOpenAIASRProvider

    openai_asr.ASRProvider = AsyncOpenAIASRProvider


def patch_mcp_and_provider_logging() -> None:
    """Scrub Vision JWT from MCP DEBUG logs, TTS error bodies, and LLM URL userinfo."""
    import core.providers.llm.openai.openai as llm_openai
    import core.providers.tools.device_mcp as device_mcp
    import core.providers.tools.device_mcp.mcp_handler as mcp_handler
    import core.providers.tts.openai as tts_openai

    async def safe_send_mcp_message(conn, payload: dict):
        if not conn.features.get("mcp"):
            mcp_handler.logger.bind(tag=mcp_handler.TAG).warning(
                "客户端不支持MCP，无法发送MCP消息"
            )
            return
        message = json.dumps({"type": "mcp", "payload": payload})
        msg_kind = payload.get("method") if isinstance(payload, dict) else None
        if not msg_kind and isinstance(payload, dict):
            if "result" in payload:
                msg_kind = "result"
            elif "error" in payload:
                msg_kind = "error"
            else:
                msg_kind = "unknown"
        msg_id = payload.get("id") if isinstance(payload, dict) else None
        try:
            await conn.websocket.send(message)
            mcp_handler.logger.bind(tag=mcp_handler.TAG).debug(
                f"成功发送MCP消息: method={msg_kind}, id={msg_id}"
            )
        except Exception as exc:
            mcp_handler.logger.bind(tag=mcp_handler.TAG).error(
                f"发送MCP消息失败: method={msg_kind}, id={msg_id}, error_type={type(exc).__name__}"
            )

    async def safe_tts_text_to_speak(self, text, output_file):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        data = {
            "model": self.model,
            "input": text,
            "voice": self.voice,
            "response_format": self.audio_file_type,
            "speed": self.speed,
        }
        safe_endpoint = safe_endpoint_label(str(self.api_url or ""))
        try:
            response = requests.post(
                self.api_url, json=data, headers=headers, timeout=self.tts_timeout
            )
        except requests.RequestException as exc:
            raise RuntimeError(
                f"OpenAI TTS请求异常: endpoint={safe_endpoint}, error_type={type(exc).__name__}"
            ) from None
        if response.status_code == 200:
            if output_file:
                with open(output_file, "wb") as audio_file:
                    audio_file.write(response.content)
                return None
            return response.content
        raise Exception(
            f"OpenAI TTS请求失败: status={response.status_code}, "
            f"endpoint={safe_endpoint}, response_bytes={len(response.content)}"
        )

    def safe_apply_thinking_disabled(self, request_params: dict):
        parsed_url = urlsplit(str(self.base_url or ""))
        domain = parsed_url.hostname or ""
        for disabled_domain, params in llm_openai.THINKING_DISABLED_DOMAINS.items():
            if disabled_domain in domain:
                request_params.setdefault("extra_body", {}).update(params)
                llm_openai.logger.bind(tag=llm_openai.TAG).info(
                    f"为域名 {domain} 禁用思考模式，参数: {params}"
                )
                break

    mcp_handler.send_mcp_message = safe_send_mcp_message
    device_mcp.send_mcp_message = safe_send_mcp_message
    tts_openai.TTSProvider.text_to_speak = safe_tts_text_to_speak
    llm_openai.LLMProvider._apply_thinking_disabled = safe_apply_thinking_disabled


def patch_abort_and_listen_and_hello() -> None:
    """Patch abort cancellation, non-blocking manual/auto/realtime ASR dispatch, and hello readiness sync."""
    from core.providers.asr.dto.dto import InterfaceType
    import core.handle.abortHandle as abort_handle
    import core.handle.helloHandle as hello_handle
    import core.handle.receiveAudioHandle as receive_audio_handle
    import core.handle.textHandler.abortMessageHandler as abort_msg_handler
    import core.handle.textHandler.helloMessageHandler as hello_msg_handler
    import core.handle.textHandler.listenMessageHandler as listen_msg_handler
    import core.providers.asr.base as asr_base

    original_abort = abort_handle.handleAbortMessage
    original_hello = hello_handle.handleHelloMessage
    original_listen_handle = listen_msg_handler.ListenTextMessageHandler.handle
    original_enqueue_asr_report = asr_base.enqueue_asr_report
    original_start_to_chat = receive_audio_handle.startToChat
    original_handle_audio_message = receive_audio_handle.handleAudioMessage

    async def patched_internal_barge_in_abort(conn):
        _cancel_conn_asr_task(conn)
        conn.sentence_id = None
        await original_abort(conn)

    async def patched_client_abort(conn):
        _cancel_conn_asr_task(conn)
        _discard_conn_pending_audio(conn)
        conn.sentence_id = None
        await original_abort(conn)

    async def patched_abort(conn):
        if _is_internal_barge_in_context(conn):
            return await patched_internal_barge_in_abort(conn)
        return await patched_client_abort(conn)

    def patched_enqueue_asr_report(conn, text, opus_data):
        if _is_stale_conn_asr_task(conn):
            return None
        return original_enqueue_asr_report(conn, text, opus_data)

    async def patched_start_to_chat(conn, text):
        if _is_stale_conn_asr_task(conn):
            return None
        token = _IN_INTERNAL_BARGE_IN.set(True)
        try:
            return await original_start_to_chat(conn, text)
        finally:
            _IN_INTERNAL_BARGE_IN.reset(token)

    def _execute_listen_stop(conn, mode: Optional[str] = None) -> Optional[asyncio.Task]:
        stop_ev = getattr(conn, "stop_event", None)
        if stop_ev is not None and stop_ev.is_set():
            return None
        asr_obj = getattr(conn, "asr", None)
        if asr_obj is None or getattr(asr_obj, "interface_type", None) == InterfaceType.STREAM:
            return None
        if mode is not None:
            conn.client_listen_mode = mode
            conn_logger = getattr(conn, "logger", None)
            if conn_logger is not None:
                conn_logger.bind(tag=listen_msg_handler.TAG).debug(
                    f"客户端拾音模式：{conn.client_listen_mode}"
                )
        conn.client_voice_stop = True
        if len(conn.asr_audio) > 0:
            asr_audio_task = conn.asr_audio.copy()
            conn.reset_audio_states()
            if len(asr_audio_task) > 0:
                return _dispatch_conn_asr_task(conn, asr_obj, asr_audio_task)
        return None

    async def patched_handle_audio_message(conn, pcm_frame):
        stop_ev = getattr(conn, "stop_event", None)
        if stop_ev is not None and stop_ev.is_set():
            return None
        if isinstance(pcm_frame, _QueuedListenStop):
            if pcm_frame.epoch != int(getattr(conn, "_passport_audio_epoch", 0) or 0):
                return None
            _execute_listen_stop(conn, mode=pcm_frame.mode)
            return None
        if isinstance(pcm_frame, _EpochAudioFrame):
            if pcm_frame.epoch != int(getattr(conn, "_passport_audio_epoch", 0) or 0):
                return None
            frame_epoch = pcm_frame.epoch
            pcm_frame = pcm_frame.pcm_frame
        else:
            frame_epoch = int(getattr(conn, "_passport_audio_epoch", 0) or 0)
        token = _CURRENT_AUDIO_FRAME_EPOCH.set(frame_epoch)
        try:
            return await original_handle_audio_message(conn, pcm_frame)
        finally:
            _CURRENT_AUDIO_FRAME_EPOCH.reset(token)

    def patched_asr_text_priority_thread(self, conn):
        while not conn.stop_event.is_set():
            try:
                message = conn.asr_audio_queue.get(timeout=1)
                if conn.stop_event.is_set():
                    break
                if (
                    isinstance(message, (_EpochAudioFrame, _QueuedListenStop))
                    and message.epoch != int(getattr(conn, "_passport_audio_epoch", 0) or 0)
                ):
                    continue
                loop = getattr(conn, "loop", None)
                if loop is None or loop.is_closed():
                    break
                future = asyncio.run_coroutine_threadsafe(
                    asr_base.handleAudioMessage(conn, message),
                    loop,
                )
                future.result()
            except queue.Empty:
                continue
            except Exception as e:
                if conn.stop_event.is_set():
                    break
                asr_base.logger.bind(tag=asr_base.TAG).error(
                    f"处理ASR文本失败: {redact_text(str(e))}, 类型: {type(e).__name__}, 堆栈: {traceback.format_exc()}"
                )
                continue

    async def patched_hello(conn, msg_json):
        ready_event = getattr(conn, "_passport_ready_event", None)
        if ready_event is not None:
            try:
                await asyncio.wait_for(ready_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass

        # Wait briefly for run_coroutine_threadsafe open_audio_channels callbacks
        # scheduled at the end of _initialize_components to finish starting threads.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            vad_ready = getattr(conn, "vad", None) is not None
            asr_ready = getattr(conn, "asr", None) is not None and (
                getattr(conn, "asr_priority_thread", None) is not None
            )
            tts_obj = getattr(conn, "tts", None)
            tts_ready = tts_obj is not None and (
                getattr(tts_obj, "audio_play_priority_thread", None) is not None
            )
            if vad_ready and asr_ready and tts_ready:
                break
            await asyncio.sleep(0.01)

        await original_hello(conn, msg_json)

    async def patched_receive_audio(self, conn, pcm_frame, audio_have_voice):
        stop_ev = getattr(conn, "stop_event", None)
        if stop_ev is not None and stop_ev.is_set():
            return
        frame_epoch = _CURRENT_AUDIO_FRAME_EPOCH.get()
        if (
            frame_epoch is not None
            and frame_epoch != int(getattr(conn, "_passport_audio_epoch", 0) or 0)
        ):
            return

        if conn.client_listen_mode == "manual":
            conn.asr_audio.append(pcm_frame)
            return

        conn.asr_audio.append(pcm_frame)
        if not audio_have_voice and not conn.client_have_voice:
            conn.asr_audio = conn.asr_audio[-10:]
            return

        asr_obj = getattr(conn, "asr", None) or self
        if (
            getattr(asr_obj, "interface_type", None) != InterfaceType.STREAM
            and conn.client_voice_stop
        ):
            pcm_bytes = b"".join(conn.asr_audio)
            conn.reset_audio_states()
            if len(pcm_bytes) > 1920 * 15:
                _dispatch_conn_asr_task(conn, self, [pcm_bytes])

    async def patched_listen_handle(self, conn, msg_json):
        stop_ev = getattr(conn, "stop_event", None)
        if stop_ev is not None and stop_ev.is_set():
            return
        state = msg_json.get("state")
        if state in ("start", "detect"):
            _discard_conn_pending_audio(conn)
            await original_listen_handle(self, conn, msg_json)
            return
        if (
            state == "stop"
            and conn.asr is not None
            and conn.asr.interface_type != InterfaceType.STREAM
        ):
            stop_mode = msg_json["mode"] if "mode" in msg_json else None
            audio_q = getattr(conn, "asr_audio_queue", None)
            worker = getattr(conn, "asr_priority_thread", None)
            worker_alive = worker is not None and worker.is_alive()
            has_queued_audio = audio_q is not None and not audio_q.empty()
            if audio_q is not None and (worker_alive or has_queued_audio):
                epoch = int(getattr(conn, "_passport_audio_epoch", 0) or 0)
                audio_q.put(_QueuedListenStop(epoch=epoch, mode=stop_mode))
                return
            _execute_listen_stop(conn, mode=stop_mode)
            return
        await original_listen_handle(self, conn, msg_json)

    abort_handle.handleAbortMessage = patched_abort
    abort_msg_handler.handleAbortMessage = patched_client_abort
    receive_audio_handle.handleAbortMessage = patched_internal_barge_in_abort
    receive_audio_handle.handleAudioMessage = patched_handle_audio_message
    asr_base.handleAudioMessage = patched_handle_audio_message
    asr_base.ASRProviderBase.asr_text_priority_thread = patched_asr_text_priority_thread

    hello_handle.handleHelloMessage = patched_hello
    hello_msg_handler.handleHelloMessage = patched_hello

    asr_base.enqueue_asr_report = patched_enqueue_asr_report
    asr_base.startToChat = patched_start_to_chat
    receive_audio_handle.startToChat = patched_start_to_chat
    listen_msg_handler.startToChat = patched_start_to_chat
    asr_base.ASRProviderBase.receive_audio = patched_receive_audio
    listen_msg_handler.ListenTextMessageHandler.handle = patched_listen_handle


def patch_connection_handler() -> None:
    """Ensure ConnectionHandler strips sensitive headers, exposes readiness, and cancels ASR on close."""
    from core.connection import ConnectionHandler

    original_init = ConnectionHandler.__init__
    original_handle_connection = ConnectionHandler.handle_connection
    original_background_init = ConnectionHandler._background_initialize
    original_init_components = ConnectionHandler._initialize_components
    original_close = ConnectionHandler.close

    def patched_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._passport_ready_event = None
        self._passport_asr_task = None
        self._passport_asr_gen = 0
        self._passport_audio_epoch = 0
        self.asr_audio_queue = _PassportEpochAudioQueue(self)

    async def patched_handle_connection(self, ws):
        self._passport_ready_event = asyncio.Event()
        strip_sensitive_ws_headers(getattr(ws.request, "headers", None))
        req_path = getattr(ws.request, "path", "") or ""
        if "?" in req_path and "?from=mqtt_gateway" not in req_path:
            ws.request.path = req_path.split("?", 1)[0]
        await original_handle_connection(self, ws)

    async def patched_background_init(self):
        try:
            await original_background_init(self)
        finally:
            if not getattr(self, "executor", None) and self._passport_ready_event is not None:
                self._passport_ready_event.set()

    def patched_init_components(self):
        try:
            original_init_components(self)
        finally:
            ready = getattr(self, "_passport_ready_event", None)
            loop = getattr(self, "loop", None)
            if ready is not None:
                if loop is not None and not loop.is_closed():
                    try:
                        loop.call_soon_threadsafe(ready.set)
                    except RuntimeError:
                        pass
                else:
                    ready.set()

    async def patched_close(self, ws=None):
        stop_ev = getattr(self, "stop_event", None)
        if stop_ev is not None:
            stop_ev.set()
        _discard_conn_pending_audio(self)
        task = _cancel_conn_asr_task(self)
        if task is not None:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await original_close(self, ws)
        _discard_conn_pending_audio(self)
        lingering = _cancel_conn_asr_task(self)
        if lingering is not None:
            try:
                await lingering
            except (asyncio.CancelledError, Exception):
                pass

    def _get_asr_audio_queue(self):
        if "_passport_asr_audio_queue" in self.__dict__:
            return self.__dict__["_passport_asr_audio_queue"]
        return self.__dict__.get("asr_audio_queue")

    def _set_asr_audio_queue(self, audio_q):
        _install_epoch_queue_put(self, audio_q)
        self._passport_asr_audio_queue = audio_q

    ConnectionHandler.__init__ = patched_init
    ConnectionHandler.asr_audio_queue = property(_get_asr_audio_queue, _set_asr_audio_queue)
    ConnectionHandler.handle_connection = patched_handle_connection
    ConnectionHandler._background_initialize = patched_background_init
    ConnectionHandler._initialize_components = patched_init_components
    ConnectionHandler.close = patched_close


def patch_ota_and_http_server() -> None:
    """Enforce provisioned OTA auth, version: 1, no access log leaks, and close Vision backdoor."""
    from core.api.ota_handler import OTAHandler, _is_higher_version
    from core.api.vision_handler import VisionHandler
    from core.http_server import SimpleHttpServer
    from core.utils.util import get_local_ip, get_vision_url

    TAG = "passport.ota"
    original_ota_init = OTAHandler.__init__
    original_vision_init = VisionHandler.__init__

    def patched_ota_init(self, config: dict):
        validate_runtime_auth_config(config)
        original_ota_init(self, config)
        self.auth_enable = True
        self.device_auth = PassportDeviceAuth(config)
        if self.allowed_devices:
            self.logger.bind(tag=TAG).warning(
                "server.auth.allowed_devices is configured, but Passport enforces "
                "per-device provisioned secret and token verification for all devices."
            )

    def _extract_ota_secret(request) -> str:
        path_secret = (request.match_info.get("ota_secret") or "").strip()
        if path_secret:
            return path_secret
        header_secret = (request.headers.get("x-ota-secret") or "").strip()
        if header_secret:
            return header_secret
        auth_header = (request.headers.get("authorization") or "").strip()
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()
        return ""

    def _ota_error_response(self, status: int, message: str) -> web.Response:
        resp = web.Response(
            text=json.dumps({"success": False, "message": message}, separators=(",", ":")),
            content_type="application/json",
            status=status,
        )
        self._add_cors_headers(resp)
        return resp

    async def patched_ota_post(self, request):
        safe_path = sanitize_url_or_path(str(request.rel_url))
        try:
            if has_sensitive_query_params(str(request.rel_url)):
                self.logger.bind(tag=TAG).warning(
                    f"拒绝包含凭据查询参数的OTA请求: {safe_path}"
                )
                return _ota_error_response(
                    self, 400, "credentials in query string are not allowed"
                )

            data = await request.text()
            device_id = normalize_device_id(request.headers.get("device-id", ""))
            client_id = (request.headers.get("client-id") or "").strip()

            if not device_id or not client_id:
                self.logger.bind(tag=TAG).warning(
                    f"OTA请求缺少设备标识: path={safe_path}"
                )
                return _ota_error_response(
                    self, 400, "missing device-id or client-id"
                )

            ota_secret = _extract_ota_secret(request)
            ok, entry, reason = self.device_auth.authenticate_ota(
                device_id=device_id,
                client_id=client_id,
                ota_secret=ota_secret,
            )
            if not ok or entry is None:
                status = 401 if reason == "missing_credential" else 403
                self.logger.bind(tag=TAG).warning(
                    f"拒绝未授权OTA请求: device_id={device_id}, reason={reason}, path={safe_path}"
                )
                return _ota_error_response(
                    self, status, "device authentication failed"
                )

            data_json = {}
            try:
                data_json = json.loads(data) if data else {}
            except Exception:
                data_json = {}

            server_config = self.config["server"]
            websocket_port = int(server_config.get("port", 8000))
            local_ip = get_local_ip()

            device_model = ""
            for header_name in ("device-model", "device_model", "model"):
                if header_name in request.headers:
                    device_model = request.headers.get(header_name, "").strip()
                    break
            if not device_model:
                board = data_json.get("board")
                if isinstance(board, dict):
                    device_model = str(board.get("type", "") or "").strip()
                elif isinstance(data_json.get("model"), str):
                    device_model = data_json["model"].strip()
            if not device_model:
                device_model = "default"

            device_version = ""
            for header_name in (
                "device-version",
                "device_version",
                "firmware-version",
                "app-version",
                "application-version",
            ):
                if header_name in request.headers:
                    device_version = request.headers.get(header_name, "").strip()
                    break
            if not device_version:
                app_info = data_json.get("application")
                if isinstance(app_info, dict):
                    device_version = str(app_info.get("version", "") or "").strip()
            if not device_version:
                device_version = "0.0.0"

            return_json = {
                "server_time": {
                    "timestamp": int(round(time.time() * 1000)),
                    "timezone_offset": server_config.get("timezone_offset", 8) * 60,
                },
                "firmware": {
                    "version": device_version,
                    "url": "",
                },
            }

            mqtt_gateway_endpoint = server_config.get("mqtt_gateway")
            if mqtt_gateway_endpoint:
                group_id = f"GID_{device_model}".replace(":", "_").replace(" ", "_")
                mac_address_safe = device_id.replace(":", "_")
                mqtt_client_id = f"{group_id}@@@{mac_address_safe}@@@{mac_address_safe}"
                import base64

                username = base64.b64encode(
                    json.dumps({"ip": "unknown"}).encode("utf-8")
                ).decode("utf-8")
                signature_key = server_config.get("mqtt_signature_key", "")
                password = (
                    self.generate_password_signature(
                        mqtt_client_id + "|" + username, signature_key
                    )
                    if signature_key
                    else ""
                )
                return_json["mqtt"] = {
                    "endpoint": mqtt_gateway_endpoint,
                    "client_id": mqtt_client_id,
                    "username": username,
                    "password": password,
                    "publish_topic": "device-server",
                    "subscribe_topic": f"devices/p2p/{mac_address_safe}",
                }
            else:
                token = self.device_auth.generate_ws_token(
                    entry, client_id=client_id, device_id=device_id
                )
                ws_version = int(self.config.get("xiaozhi", {}).get("version", 1))
                return_json["websocket"] = {
                    "url": self._get_websocket_url(local_ip, websocket_port),
                    "token": token,
                    "version": ws_version,
                }
                self.logger.bind(tag=TAG).info(
                    f"已为已预配设备 {device_id} 下发WebSocket OTA配置 (version={ws_version})"
                )

            try:
                self._refresh_bin_cache_if_needed()
                files_by_model = self._bin_cache.get("files_by_model", {})
                candidates = files_by_model.get(device_model, [])
                for ver, fname in candidates:
                    if _is_higher_version(ver, device_version):
                        vision_url = get_vision_url(self.config)
                        return_json["firmware"]["version"] = ver
                        return_json["firmware"]["url"] = vision_url.replace(
                            "/mcp/vision/explain", f"/xiaozhi/ota/download/{fname}"
                        )
                        break
            except Exception as exc:
                self.logger.bind(tag=TAG).error(
                    f"检查固件版本时出错: {redact_text(str(exc))}"
                )

            response = web.Response(
                text=json.dumps(return_json, separators=(",", ":")),
                content_type="application/json",
            )
            self._add_cors_headers(response)
            return response
        except Exception as exc:
            self.logger.bind(tag=TAG).error(
                f"OTA POST处理异常: {redact_text(str(exc))}"
            )
            return _ota_error_response(self, 500, "request error.")

    async def patched_ota_get(self, request):
        resp = web.Response(text="Passport OTA service ready\n", content_type="text/plain")
        self._add_cors_headers(resp)
        return resp

    def patched_vision_init(self, config: dict):
        validate_runtime_auth_config(config)
        original_vision_init(self, config)
        self.device_auth = PassportDeviceAuth(config)

    def patched_vision_verify(self, request):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False, None
        token = auth_header[7:]
        is_valid, token_device_id = self.auth.verify_token(token)
        if not is_valid or not token_device_id:
            return False, None
        entry = self.device_auth.get_device(token_device_id)
        if entry is None or not entry.enabled:
            return False, None
        return True, token_device_id

    async def patched_http_start(self):
        server_config = self.config["server"]
        read_config_from_api = self.config.get("read_config_from_api", False)
        host = server_config.get("ip", "0.0.0.0")
        port = int(server_config.get("http_port", 8003))
        if not port:
            return

        app = web.Application()
        if not read_config_from_api:
            app.add_routes(
                [
                    web.get("/xiaozhi/ota/", self.ota_handler.handle_get),
                    web.post("/xiaozhi/ota/", self.ota_handler.handle_post),
                    web.options("/xiaozhi/ota/", self.ota_handler.handle_options),
                    web.post(
                        "/xiaozhi/ota/d/{ota_secret}",
                        self.ota_handler.handle_post,
                    ),
                    web.post(
                        "/xiaozhi/ota/d/{ota_secret}/",
                        self.ota_handler.handle_post,
                    ),
                    web.options(
                        "/xiaozhi/ota/d/{ota_secret}",
                        self.ota_handler.handle_options,
                    ),
                    web.options(
                        "/xiaozhi/ota/d/{ota_secret}/",
                        self.ota_handler.handle_options,
                    ),
                    web.get(
                        "/xiaozhi/ota/download/{filename}",
                        self.ota_handler.handle_download,
                    ),
                    web.options(
                        "/xiaozhi/ota/download/{filename}",
                        self.ota_handler.handle_options,
                    ),
                ]
            )
        app.add_routes(
            [
                web.get("/mcp/vision/explain", self.vision_handler.handle_get),
                web.post("/mcp/vision/explain", self.vision_handler.handle_post),
                web.options("/mcp/vision/explain", self.vision_handler.handle_options),
            ]
        )

        # Disable aiohttp's default access log so /xiaozhi/ota/d/<secret>/ paths never reach logs.
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            await runner.cleanup()

    OTAHandler.__init__ = patched_ota_init
    OTAHandler.handle_post = patched_ota_post
    OTAHandler.handle_get = patched_ota_get

    VisionHandler.__init__ = patched_vision_init
    VisionHandler._verify_auth_token = patched_vision_verify

    SimpleHttpServer.start = patched_http_start


def patch_websocket_server() -> None:
    """Enforce provisioned device + token auth on WebSockets and strip sensitive headers."""
    from core.auth import AuthenticationError
    from core.connection import ConnectionHandler
    from core.websocket_server import WebSocketServer

    TAG = "passport.ws"
    original_ws_init = WebSocketServer.__init__

    def patched_ws_init(self, config: dict):
        validate_runtime_auth_config(config)
        original_ws_init(self, config)
        self.auth_enable = True
        self.device_auth = PassportDeviceAuth(self.config)
        if self.allowed_devices:
            self.logger.bind(tag=TAG).warning(
                "server.auth.allowed_devices is configured, but Passport does NOT bypass "
                "token verification for allowlisted devices."
            )

    def _lowercase_headers(websocket) -> dict[str, str]:
        raw_hdrs = websocket.request.headers
        items = (
            list(raw_hdrs.raw_items())
            if hasattr(raw_hdrs, "raw_items")
            else list(raw_hdrs.items())
        )
        result: dict[str, str] = {}
        for k, v in items:
            lk = str(k).lower()
            if lk in result and lk in ("device-id", "client-id", "authorization"):
                raise AuthenticationError(f"Duplicate {lk} header")
            result[lk] = str(v)
        return result

    async def patched_handle_auth(self, websocket):
        headers = _lowercase_headers(websocket)
        device_id = normalize_device_id(headers.get("device-id", ""))
        client_id = headers.get("client-id", "").strip()
        auth_header = headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            self.logger.bind(tag=TAG).warning(
                f"拒绝WebSocket连接 (device_id={device_id or 'unknown'}, reason=missing_bearer_header)"
            )
            raise AuthenticationError("Missing or invalid Authorization header")

        token = auth_header[7:].strip()
        ok, reason = self.device_auth.authenticate_ws(
            device_id=device_id,
            client_id=client_id,
            token=token,
        )
        if not ok:
            self.logger.bind(tag=TAG).warning(
                f"拒绝WebSocket连接 (device_id={device_id or 'unknown'}, reason={reason})"
            )
            raise AuthenticationError(reason)

    async def patched_handle_connection(self, websocket):
        request_path = getattr(websocket.request, "path", "") or ""
        if has_sensitive_query_params(request_path):
            self.logger.bind(tag=TAG).warning(
                f"拒绝携带凭据查询参数的WebSocket连接: {sanitize_url_or_path(request_path)}"
            )
            try:
                await websocket.send("认证失败")
            except Exception:
                pass
            await websocket.close()
            return

        if "?" in request_path and not request_path.endswith("?from=mqtt_gateway"):
            websocket.request.path = request_path.split("?", 1)[0]

        try:
            headers = _lowercase_headers(websocket)
        except AuthenticationError as exc:
            self.logger.bind(tag=TAG).warning(f"拒绝WebSocket连接 (reason={exc})")
            try:
                await websocket.send("认证失败")
            except Exception:
                pass
            await websocket.close()
            return

        if not headers.get("device-id"):
            self.logger.bind(tag=TAG).warning("拒绝缺少Device-Id的WebSocket连接")
            try:
                await websocket.send("认证失败")
            except Exception:
                pass
            await websocket.close()
            return

        try:
            await self._handle_auth(websocket)
        except AuthenticationError:
            try:
                await websocket.send("认证失败")
            except Exception:
                pass
            await websocket.close()
            return

        # Strip Authorization and any sensitive headers before ConnectionHandler inspects/logs headers.
        strip_sensitive_ws_headers(websocket.request.headers)
        try:
            del websocket.request.headers["device-id"]
        except Exception:
            pass
        try:
            websocket.request.headers["device-id"] = normalize_device_id(
                headers["device-id"]
            )
        except Exception:
            pass

        handler = ConnectionHandler(
            self.config,
            self._vad,
            self._asr,
            self._llm,
            self._memory,
            self._intent,
            self,
        )
        try:
            await handler.handle_connection(websocket)
        except Exception as exc:
            self.logger.bind(tag=TAG).error(
                f"处理连接时出错: {redact_text(str(exc))}"
            )
        finally:
            try:
                if hasattr(websocket, "closed") and not websocket.closed:
                    await websocket.close()
                elif hasattr(websocket, "state") and websocket.state.name != "CLOSED":
                    await websocket.close()
                else:
                    await websocket.close()
            except Exception as close_error:
                self.logger.bind(tag=TAG).error(
                    f"服务器端强制关闭连接时出错: {redact_text(str(close_error))}"
                )

    WebSocketServer.__init__ = patched_ws_init
    WebSocketServer._handle_auth = patched_handle_auth
    WebSocketServer._handle_connection = patched_handle_connection


def apply_all_patches() -> None:
    """Install all Passport patches in strict module-import order."""
    global _PATCHES_APPLIED
    if _PATCHES_APPLIED:
        return
    patch_logging()
    patch_openai_asr()
    patch_mcp_and_provider_logging()
    patch_abort_and_listen_and_hello()
    patch_connection_handler()
    patch_ota_and_http_server()
    patch_websocket_server()
    _PATCHES_APPLIED = True
