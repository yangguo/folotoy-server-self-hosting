"""Atomic file helpers for sensitive configuration and secret files."""

import os
import tempfile
from pathlib import Path


def atomic_write_private(path: Path, content: str, mode: int = 0o600) -> None:
    """Atomically write *content* to *path* with restrictive permissions from birth.

    Uses ``tempfile.mkstemp`` in the target directory so the file is created by
    the kernel with 0600 permissions before any secret data is written, avoiding
    any umask race window.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
