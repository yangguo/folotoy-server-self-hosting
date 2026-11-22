"""Non-blocking, timeout-bounded, cancellable OpenAI-compatible ASR provider.

Replaces upstream ``core/providers/asr/openai.py`` which runs synchronous
``requests.post()`` without a timeout on the shared asyncio event loop, and
avoids blocking event-loop file I/O by uploading bounded in-memory WAV buffers.
"""

import asyncio
import math
import os
import shutil
import time
from pathlib import Path
from typing import List, Optional, Tuple

import httpx
from config.logger import setup_logging
from core.providers.asr.base import ASRProviderBase
from core.providers.asr.dto.dto import InterfaceType

from passport_server.redaction import (
    register_redacted_secret,
    register_url_secrets,
    safe_endpoint_label,
)

TAG = __name__
logger = setup_logging()

DEFAULT_MAX_AUDIO_BYTES = 16 * 1024 * 1024


def _positive_float(value, default: float, name: str) -> float:
    if value is None or value == "":
        return default
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"ASR {name} must be a positive finite number, got {value!r}")
    return parsed


def _positive_int(value, default: int, name: str) -> int:
    if value is None or value == "":
        return default
    parsed = int(value)
    if parsed <= 0:
        raise ValueError(f"ASR {name} must be a positive integer, got {value!r}")
    return parsed


class AsyncOpenAIASRProvider(ASRProviderBase):
    """Async httpx-based OpenAI Whisper ASR provider with explicit timeouts."""

    def __init__(self, config: dict, delete_audio_file: bool):
        self.interface_type = InterfaceType.NON_STREAM
        self.api_key = config.get("api_key", "")
        self.api_url = config.get("base_url")
        self.model = config.get("model_name")
        self.output_dir = config.get("output_dir", "tmp/")
        self.delete_audio_file = delete_audio_file
        self.max_audio_bytes = _positive_int(
            config.get("max_audio_bytes"),
            DEFAULT_MAX_AUDIO_BYTES,
            "max_audio_bytes",
        )
        register_redacted_secret(self.api_key)
        register_url_secrets(self.api_url)

        single_timeout = config.get("timeout")
        if single_timeout is not None and single_timeout != "":
            base_read = _positive_float(single_timeout, 15.0, "timeout")
            self.connect_timeout = _positive_float(
                config.get("connect_timeout"), min(5.0, base_read), "connect_timeout"
            )
            self.read_timeout = _positive_float(
                config.get("read_timeout"), base_read, "read_timeout"
            )
            self.write_timeout = _positive_float(
                config.get("write_timeout"), max(2.0, min(10.0, base_read)), "write_timeout"
            )
            self.pool_timeout = _positive_float(
                config.get("pool_timeout"), min(5.0, base_read), "pool_timeout"
            )
            self.total_timeout = _positive_float(
                config.get("total_timeout"), base_read + 1.0, "total_timeout"
            )
        else:
            self.connect_timeout = _positive_float(
                config.get("connect_timeout"), 5.0, "connect_timeout"
            )
            self.read_timeout = _positive_float(
                config.get("read_timeout"), 15.0, "read_timeout"
            )
            self.write_timeout = _positive_float(
                config.get("write_timeout"), 10.0, "write_timeout"
            )
            self.pool_timeout = _positive_float(
                config.get("pool_timeout"), 5.0, "pool_timeout"
            )
            self.total_timeout = _positive_float(
                config.get("total_timeout"), 20.0, "total_timeout"
            )

        if not self.delete_audio_file:
            os.makedirs(self.output_dir, exist_ok=True)

    def requires_file(self) -> bool:
        return False

    def _archive_pcm_sync(
        self, pcm_data: List[bytes], pcm_size: int, session_id: str
    ) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        free_space = shutil.disk_usage(self.output_dir).free
        if free_space < pcm_size * 2:
            raise OSError("磁盘空间不足")
        return self.save_audio_to_file(pcm_data, session_id)

    async def speech_to_text_wrapper(
        self, pcm_data: List[bytes], session_id: str
    ) -> Tuple[Optional[str], Optional[str]]:
        combined_pcm_data = b"".join(pcm_data)
        if not combined_pcm_data:
            return "", None

        if len(combined_pcm_data) > self.max_audio_bytes:
            logger.bind(tag=TAG).error(
                f"ASR音频超过最大限制: bytes={len(combined_pcm_data)}, limit={self.max_audio_bytes}"
            )
            return "", None

        file_path = None
        if not self.delete_audio_file:
            try:
                file_path = await asyncio.to_thread(
                    self._archive_pcm_sync,
                    pcm_data,
                    len(combined_pcm_data),
                    session_id,
                )
            except OSError as exc:
                logger.bind(tag=TAG).error(
                    f"ASR音频归档失败: error_type={type(exc).__name__}"
                )
                return "", None

        artifacts = ASRProviderBase.AudioArtifacts(
            pcm_frames=pcm_data,
            pcm_bytes=combined_pcm_data,
            file_path=file_path,
            temp_path=None,
        )
        text, _ = await self.speech_to_text(pcm_data, session_id, artifacts)
        return text, file_path

    async def speech_to_text(
        self,
        opus_data: List[bytes],
        session_id: str,
        artifacts=None,
    ) -> Tuple[Optional[str], Optional[str]]:
        if artifacts is None:
            return "", None

        file_path = getattr(artifacts, "file_path", None)
        pcm_bytes = getattr(artifacts, "pcm_bytes", None)
        if pcm_bytes:
            if len(pcm_bytes) > self.max_audio_bytes:
                logger.bind(tag=TAG).error(
                    f"ASR音频超过最大限制: bytes={len(pcm_bytes)}, limit={self.max_audio_bytes}"
                )
                return "", None
            audio_bytes = self._pcm_to_wav(pcm_bytes)
        elif file_path:
            audio_bytes = await asyncio.to_thread(Path(file_path).read_bytes)
        else:
            return "", None

        if not audio_bytes:
            return "", None

        safe_endpoint = safe_endpoint_label(str(self.api_url or ""))
        upload_name = (
            os.path.basename(file_path)
            if file_path
            else f"asr_{os.path.basename(str(session_id or 'session'))}.wav"
        )
        timeout = httpx.Timeout(
            connect=self.connect_timeout,
            read=self.read_timeout,
            write=self.write_timeout,
            pool=self.pool_timeout,
        )
        start_time = time.monotonic()

        try:
            async def _post_audio() -> httpx.Response:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    return await client.post(
                        self.api_url,
                        files={"file": (upload_name, audio_bytes, "audio/wav")},
                        data={"model": self.model},
                        headers={"Authorization": f"Bearer {self.api_key}"},
                    )

            response = await asyncio.wait_for(_post_audio(), timeout=self.total_timeout)
            elapsed = time.monotonic() - start_time
            logger.bind(tag=TAG).debug(
                f"异步ASR请求完成: {elapsed:.3f}s | status={response.status_code}"
            )
            if response.status_code == 200:
                text = response.json().get("text", "")
                return text, file_path

            logger.bind(tag=TAG).error(
                f"ASR API请求失败: status={response.status_code}, "
                f"endpoint={safe_endpoint}, response_bytes={len(response.content)}"
            )
            return "", None
        except asyncio.CancelledError:
            elapsed = time.monotonic() - start_time
            logger.bind(tag=TAG).info(
                f"ASR请求已取消 (session={session_id}, elapsed={elapsed:.3f}s)"
            )
            raise
        except (asyncio.TimeoutError, httpx.TimeoutException):
            elapsed = time.monotonic() - start_time
            logger.bind(tag=TAG).error(
                f"ASR请求超时: elapsed={elapsed:.3f}s, limit={self.total_timeout:.2f}s, "
                f"endpoint={safe_endpoint}"
            )
            return "", None
        except Exception as exc:
            logger.bind(tag=TAG).error(
                f"语音识别失败: endpoint={safe_endpoint}, error_type={type(exc).__name__}"
            )
            return "", None
