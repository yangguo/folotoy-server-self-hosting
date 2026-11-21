"""Source-level and sink-level credential redaction helpers for Passport logs."""

import logging
import re
from typing import Iterable, Mapping, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-ota-secret",
        "x-api-key",
        "x-auth-token",
    }
)

SAFE_WS_LOG_HEADERS = (
    "device-id",
    "client-id",
    "protocol-version",
    "user-agent",
    "host",
    "x-real-ip",
    "x-forwarded-for",
)

SENSITIVE_QUERY_KEYS = frozenset(
    {
        "authorization",
        "token",
        "access_token",
        "secret",
        "ota_secret",
        "key",
        "api_key",
        "apikey",
        "password",
        "sig",
        "signature",
        "auth",
    }
)

_BEARER_RE = re.compile(
    r"(?i)(Bearer(?:\s+|%20|\+))(?!\[REDACTED\])([A-Za-z0-9._~+/=-]+)"
)
_OTA_SECRET_PATH_RE = re.compile(
    r"(/xiaozhi/ota/d/)(?!\[REDACTED\])([^/?#\s\"'<>]+)"
)
_QUERY_CRED_RE = re.compile(
    r"(?i)([?&](?:authorization|token|access_token|secret|ota_secret|key|api_key|apikey|password|sig|signature|auth)=)(?!\[REDACTED\])([^&\s\"'<>]+)"
)
_HEADER_KV_RE = re.compile(
    r"(?i)(['\"]?(?:authorization|proxy-authorization|x-ota-secret|x-api-key|x-auth-token|cookie|set-cookie|auth_key|api_key)['\"]?\s*[:=]\s*['\"]?)(?!\[REDACTED\]|Bearer\s+\[REDACTED\])([^'\",}\r\n]+)"
)

_STDLIB_LOGGERS_TO_FILTER = (
    "",
    "aiohttp",
    "aiohttp.access",
    "aiohttp.server",
    "aiohttp.web",
    "websockets",
    "websockets.server",
    "websockets.client",
    "httpx",
    "httpcore",
    "urllib3",
)


def redact_text(text: str) -> str:
    """Redact Bearer tokens, OTA secret paths, sensitive query values, and headers."""
    if not text:
        return text
    result = _BEARER_RE.sub(r"\1" + REDACTED, text)
    result = _OTA_SECRET_PATH_RE.sub(r"\1" + REDACTED, result)
    result = _QUERY_CRED_RE.sub(r"\1" + REDACTED, result)
    result = _HEADER_KV_RE.sub(r"\1" + REDACTED, result)
    return result


def has_sensitive_query_params(raw_path: str) -> bool:
    """Return True if *raw_path* carries any credential-like query parameter."""
    if not raw_path or "?" not in raw_path:
        return False
    parsed = urlsplit(raw_path)
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key.strip().lower() in SENSITIVE_QUERY_KEYS:
            return True
    return False


def sanitize_url_or_path(raw: str) -> str:
    """Redact secret OTA path segments and sensitive query parameters in a URL/path."""
    if not raw:
        return raw
    parsed = urlsplit(raw)
    clean_path = _OTA_SECRET_PATH_RE.sub(r"\1" + REDACTED, parsed.path)
    clean_query = ""
    if parsed.query:
        pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.strip().lower() in SENSITIVE_QUERY_KEYS:
                pairs.append((key, REDACTED))
            else:
                pairs.append((key, redact_text(value)))
        clean_query = urlencode(pairs, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, clean_path, clean_query, ""))


def sanitize_headers(
    headers: Mapping[str, str],
    allowlist: Optional[Iterable[str]] = None,
) -> dict[str, str]:
    """Return a copy of *headers* safe for diagnostic logging."""
    allowed = {k.lower() for k in allowlist} if allowlist is not None else None
    sanitized: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in SENSITIVE_HEADER_NAMES:
            if allowed is None:
                sanitized[lower] = REDACTED
            continue
        if allowed is not None and lower not in allowed:
            continue
        sanitized[lower] = redact_text(str(value))
    return sanitized


def strip_sensitive_ws_headers(headers) -> None:
    """Remove sensitive headers from a mutable websockets/HTTP header mapping in place."""
    if headers is None:
        return
    try:
        keys = list(headers.keys())
    except Exception:
        return
    for key in set(str(k) for k in keys):
        if key.lower() in SENSITIVE_HEADER_NAMES:
            try:
                del headers[key]
            except KeyError:
                pass
            except Exception:
                try:
                    if hasattr(headers, "pop"):
                        headers.pop(key, None)
                except Exception:
                    pass


class RedactingStdlibFilter(logging.Filter):
    """Stdlib logging filter that redacts credentials before records reach handlers."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
            redacted = redact_text(rendered)
            if redacted != rendered:
                record.msg = redacted
                record.args = ()
            elif isinstance(record.msg, str):
                record.msg = redact_text(record.msg)
        except Exception:
            record.msg = REDACTED
            record.args = ()
        return True


def install_stdlib_redaction() -> None:
    """Attach ``RedactingStdlibFilter`` to stdlib root and HTTP/WS library loggers."""
    filt = RedactingStdlibFilter()
    for logger_name in _STDLIB_LOGGERS_TO_FILTER:
        target = logging.getLogger(logger_name)
        if not any(isinstance(existing, RedactingStdlibFilter) for existing in target.filters):
            target.addFilter(filt)
