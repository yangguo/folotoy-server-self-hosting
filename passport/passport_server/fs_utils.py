"""Atomic file helpers and cross-process file locking for sensitive files."""

import fcntl
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator


@contextmanager
def locked_file(path: Path, mode: int = 0o600) -> Iterator[None]:
    """Acquire an exclusive cross-process advisory lock via a sidecar lock file.

    Locks ``.<name>.lock`` rather than *path* itself so callers can safely perform
    ``os.replace`` on *path* without invalidating the locked inode.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.parent / f".{target.name}.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, mode)
    try:
        os.fchmod(fd, mode)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


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


def ensure_private_secret_file(
    path: Path,
    generator: Callable[[], str],
    validator: Callable[[str], bool],
    mode: int = 0o600,
) -> str:
    """Create or read a private secret file under a cross-process lock."""
    target = Path(path)
    with locked_file(target, mode=mode):
        if target.is_file():
            existing = target.read_text(encoding="utf-8").strip()
            if not validator(existing):
                raise ValueError(f"Existing secret file {target} failed validation")
            return existing
        generated = generator().strip()
        if not validator(generated):
            raise ValueError(f"Generated secret for {target} failed validation")
        atomic_write_private(target, generated + "\n", mode=mode)
        return generated
