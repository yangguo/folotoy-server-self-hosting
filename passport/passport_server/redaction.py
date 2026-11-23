"""Source-level and sink-level credential redaction helpers for Passport logs."""

import logging
import re
import threading
from typing import Iterable, Mapping, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

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
        "refresh_token",
        "id_token",
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

_CONFIG_SECRET_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "auth_key",
        "secret",
        "secret_key",
        "app_secret",
        "client_secret",
        "ota_secret",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "mqtt_signature_key",
    }
)

_CONFIG_URL_KEYS = frozenset({"base_url", "api_url", "url", "endpoint", "ws_url"})

_REGISTERED_SECRETS: set[str] = set()
_REGISTRY_LOCK = threading.Lock()

_BEARER_RE = re.compile(
    r"(?i)(Bearer(?:\s+|%20|\+))(?!\[REDACTED\])([A-Za-z0-9._~+/=-]+)"
)
_OTA_SECRET_PATH_RE = re.compile(
    r"(/xiaozhi/ota/d/)(?!\[REDACTED\])([^/?#\s\"'<>]+)"
)
_URL_USERINFO_RE = re.compile(
    r"(?i)(\b(?:https?|wss?)://)(?!\[REDACTED\]@)([^/\s@\"'<>]+)@"
)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_QUERY_CRED_RE = re.compile(
    r"(?i)([?&](?:authorization|token|access_token|refresh_token|id_token|secret|ota_secret|key|api_key|apikey|password|sig|signature|auth)=)(?!\[REDACTED\])([^&\s\"'<>]+)"
)
_QUOTED_SECRET_KV_RE = re.compile(
    r"(?i)(['\"](?:authorization|proxy-authorization|x-ota-secret|x-api-key|x-auth-token|cookie|set-cookie|auth_key|api_key|apikey|token|access_token|refresh_token|id_token|ota_secret|client_secret|secret|secret_key|password|mqtt_signature_key)['\"]\s*[:=]\s*)(['\"])(?!\[REDACTED\]|Bearer\s+\[REDACTED\])([^'\"]+?)\2"
)
_UNQUOTED_SECRET_KV_RE = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|x-ota-secret|x-api-key|x-auth-token|cookie|set-cookie|auth_key|api_key|apikey|access_token|refresh_token|id_token|ota_secret|client_secret|secret_key|password|mqtt_signature_key)\b\s*[:=]\s*)(?!['\"]|\[REDACTED\]|Bearer\s+\[REDACTED\])([^\s,}\r\n]+)"
)

_STDLIB_LOGGERS_TO_FILTER = (
    "",
    "aiohttp",
    "aiohttp.access",
    "aiohttp.client",
    "aiohttp.internal",
    "aiohttp.server",
    "aiohttp.web",
    "websockets",
    "websockets.server",
    "websockets.client",
    "httpx",
    "httpcore",
    "httpcore.http11",
    "httpcore.connection",
    "openai",
    "openai._base_client",
    "urllib3",
    "urllib3.connectionpool",
)


def _is_ignorable_secret(value: str) -> bool:
    lower = value.lower()
    return (
        len(value) < 6
        or value == REDACTED
        or lower in {"lm-studio", "ollama"}
        or lower.startswith(("replace-with-", "your-", "<"))
        or "你" in value
    )


def register_redacted_secret(secret: Optional[str]) -> None:
    """Register a known secret value so sink redaction always scrubs it verbatim."""
    if not isinstance(secret, str):
        return
    val = secret.strip()
    if _is_ignorable_secret(val):
        return
    encoded = quote(val, safe="")
    with _REGISTRY_LOCK:
        _REGISTERED_SECRETS.add(val)
        if len(encoded) >= 6 and encoded != val:
            _REGISTERED_SECRETS.add(encoded)


def clear_registered_secrets() -> None:
    """Clear registered secret literals (intended for unit tests)."""
    with _REGISTRY_LOCK:
        _REGISTERED_SECRETS.clear()


def _register_secrets_from_url(raw_url: str) -> None:
    if not isinstance(raw_url, str) or not raw_url.strip():
        return
    try:
        parsed = urlsplit(raw_url.strip())
    except Exception:
        return
    if parsed.username:
        register_redacted_secret(parsed.username)
    if parsed.password:
        register_redacted_secret(parsed.password)
    if "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0]
        register_redacted_secret(userinfo)
    if parsed.query:
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.strip().lower() in SENSITIVE_QUERY_KEYS:
                register_redacted_secret(value)


def register_url_secrets(raw_url: Optional[str]) -> None:
    """Register URL userinfo and sensitive query parameter values for redaction."""
    if isinstance(raw_url, str):
        _register_secrets_from_url(raw_url)


def register_secrets_from_config(config: Optional[dict]) -> None:
    """Extract and register credentials/URL userinfo from runtime config."""
    if not isinstance(config, dict):
        return

    server_cfg = config.get("server")
    if isinstance(server_cfg, dict):
        register_redacted_secret(server_cfg.get("auth_key"))
        register_redacted_secret(server_cfg.get("mqtt_signature_key"))

    manager_cfg = config.get("manager-api")
    if isinstance(manager_cfg, dict):
        register_redacted_secret(manager_cfg.get("secret"))

    mcp_endpoint = config.get("mcp_endpoint")
    if isinstance(mcp_endpoint, str):
        _register_secrets_from_url(mcp_endpoint)

    for section_name in ("ASR", "LLM", "TTS", "VLLM", "Memory", "Intent"):
        section = config.get(section_name)
        if not isinstance(section, dict):
            continue
        for entry in section.values():
            if not isinstance(entry, dict):
                continue
            for key, value in entry.items():
                if not isinstance(value, str):
                    continue
                lower_key = str(key).strip().lower()
                if lower_key in _CONFIG_SECRET_KEYS:
                    register_redacted_secret(value)
                elif lower_key in _CONFIG_URL_KEYS:
                    _register_secrets_from_url(value)


def redact_text(text: str) -> str:
    """Redact Bearer tokens, URL userinfo, JWTs, OTA secret paths, query creds, and headers."""
    if not text:
        return text
    result = _BEARER_RE.sub(r"\1" + REDACTED, text)
    result = _URL_USERINFO_RE.sub(r"\1" + REDACTED + "@", result)
    result = _OTA_SECRET_PATH_RE.sub(r"\1" + REDACTED, result)
    result = _JWT_RE.sub(REDACTED, result)
    result = _QUERY_CRED_RE.sub(r"\1" + REDACTED, result)
    result = _QUOTED_SECRET_KV_RE.sub(r"\1\2" + REDACTED + r"\2", result)
    result = _UNQUOTED_SECRET_KV_RE.sub(r"\1" + REDACTED, result)

    with _REGISTRY_LOCK:
        registered = sorted(_REGISTERED_SECRETS, key=len, reverse=True)
    for secret in registered:
        if secret in result:
            result = result.replace(secret, REDACTED)
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


def _extract_host_port(parsed, include_redacted_userinfo: bool) -> str:
    netloc = parsed.netloc or ""
    if not netloc:
        return ""
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host_part = f"[{host}]"
    else:
        host_part = host
    try:
        port = parsed.port
    except ValueError:
        port = None
    if host_part:
        host_port = f"{host_part}:{port}" if port is not None else host_part
    else:
        host_port = netloc.rsplit("@", 1)[-1]
    if include_redacted_userinfo and (
        parsed.username is not None or parsed.password is not None or "@" in netloc
    ):
        return f"{REDACTED}@{host_port}"
    return host_port


def sanitize_url_or_path(raw: str) -> str:
    """Redact userinfo, secret OTA path segments, and sensitive query params in a URL/path."""
    if not raw:
        return raw
    try:
        parsed = urlsplit(raw)
    except Exception:
        return "[invalid-url]"
    clean_netloc = _extract_host_port(parsed, include_redacted_userinfo=True)
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
    return urlunsplit((parsed.scheme, clean_netloc, clean_path, clean_query, ""))


def safe_endpoint_label(raw: str) -> str:
    """Return scheme://host[:port]/safe_path without userinfo, query string, or fragment."""
    if not raw or not str(raw).strip():
        return ""
    try:
        parsed = urlsplit(str(raw).strip())
        host_port = _extract_host_port(parsed, include_redacted_userinfo=False)
        clean_path = _OTA_SECRET_PATH_RE.sub(r"\1" + REDACTED, parsed.path)
        return urlunsplit((parsed.scheme, host_port, clean_path, "", ""))
    except Exception:
        return "[invalid-url]"


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
            if isinstance(getattr(record, "exc_text", None), str) and record.exc_text:
                record.exc_text = redact_text(record.exc_text)
        except Exception:
            record.msg = REDACTED
            record.args = ()
        return True


_STDLIB_FILTER = RedactingStdlibFilter()
_ADD_HANDLER_WRAPPED = False
_ORIGINAL_ADD_HANDLER = logging.Logger.addHandler


def _attach_filter_to_handler(handler: logging.Handler) -> None:
    if not any(isinstance(existing, RedactingStdlibFilter) for existing in handler.filters):
        handler.addFilter(_STDLIB_FILTER)


def install_stdlib_redaction() -> None:
    """Attach ``RedactingStdlibFilter`` to stdlib loggers, handlers, and future handlers."""
    global _ADD_HANDLER_WRAPPED
    for logger_name in _STDLIB_LOGGERS_TO_FILTER:
        target = logging.getLogger(logger_name)
        if not any(isinstance(existing, RedactingStdlibFilter) for existing in target.filters):
            target.addFilter(_STDLIB_FILTER)
        for handler in list(target.handlers):
            _attach_filter_to_handler(handler)

    if not _ADD_HANDLER_WRAPPED:
        def _wrapped_add_handler(self, hdlr):
            _attach_filter_to_handler(hdlr)
            return _ORIGINAL_ADD_HANDLER(self, hdlr)

        logging.Logger.addHandler = _wrapped_add_handler
        _ADD_HANDLER_WRAPPED = True
