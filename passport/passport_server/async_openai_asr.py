"""Non-blocking, timeout-bounded, cancellable OpenAI-compatible ASR provider.

Replaces upstream ``core/providers/asr/openai.py`` which runs synchronous
``requests.post()`` without a timeout on the shared asyncio event loop.
"""

import asyncio
import math
import os
import time
from pathlib import Path
from typing import List, Optional, Tuple

import httpx
from config.logger import setup_logging
from core.providers.asr.base import ASRProviderBase
from core.providers.asr.dto.dto import InterfaceType

from passport_server.redaction import redact_text, sanitize_url_or_path

TAG = __name__
logger = setup_logging()


def _positive_float(value, default: float, name: str) -> float:
    if value is None or value == "":
        return default
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"ASR {name} must be a positive finite number, got {value!r}")
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

        os.makedirs(self.output_dir, exist_ok=True)

    def requires_file(self) -> bool:
        return True

    async def speech_to_text(
        self,
        opus_data: List[bytes],
        session_id: str,
        artifacts=None,
    ) -> Tuple[Optional[str], Optional[str]]:
        if artifacts is None or not getattr(artifacts, "file_path", None):
            return "", None

        file_path = artifacts.file_path
        safe_url = sanitize_url_or_path(str(self.api_url or ""))
        timeout = httpx.Timeout(
            connect=self.connect_timeout,
            read=self.read_timeout,
            write=self.write_timeout,
            pool=self.pool_timeout,
        )
        start_time = time.monotonic()

        try:
            audio_bytes = await asyncio.to_thread(Path(file_path).read_bytes)

            async def _post_audio() -> httpx.Response:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    return await client.post(
                        self.api_url,
                        files={"file": (os.path.basename(file_path), audio_bytes, "audio/wav")},
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

            body_preview = redact_text(response.text[:300])
            logger.bind(tag=TAG).error(
                f"ASR API请求失败: status={response.status_code}, url={safe_url}, body={body_preview}"
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
                f"ASR请求超时: elapsed={elapsed:.3f}s, limit={self.total_timeout:.2f}s, url={safe_url}"
            )
            return "", None
        except Exception as exc:
            logger.bind(tag=TAG).error(
                f"语音识别失败 ({safe_url}): {redact_text(str(exc))}"
            )
            return "", None
