"""Atomic file helpers and cross-process file locking for sensitive files."""

import fcntl
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator


@contextmanager
def locked_file(path: Path, mode: int = 0o600) -> Iterator[None]:
    """Acquire an exclusive cross-process advisory lock via a sidecar lock file.

    Locks ``.<name>.lock`` rather than *path* itself so callers can safely perform
    ``os.replace`` on *path* without invalidating the locked inode. Refuses
    symlinks and multi-hard-link lock files before any ``fchmod`` or ``flock``
    so a planted link cannot be altered via the sidecar lock.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.parent / f".{target.name}.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    fd = os.open(lock_path, flags, mode)
    locked = False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"Refusing non-regular lock file: {lock_path}")
        if st.st_uid != os.geteuid():
            raise PermissionError(f"Refusing lock file owned by another user: {lock_path}")
        if st.st_nlink != 1:
            raise PermissionError(
                f"Refusing lock file with multiple hard links (nlink={st.st_nlink}): {lock_path}"
            )
        lst = os.lstat(lock_path)
        if stat.S_ISLNK(lst.st_mode) or (lst.st_dev, lst.st_ino) != (st.st_dev, st.st_ino):
            raise PermissionError(f"Refusing replaced or symlinked lock file: {lock_path}")
        fcntl.flock(fd, fcntl.LOCK_EX)
        locked = True
        st_locked = os.fstat(fd)
        if (
            not stat.S_ISREG(st_locked.st_mode)
            or st_locked.st_uid != os.geteuid()
            or st_locked.st_nlink != 1
        ):
            raise PermissionError(
                f"Refusing lock file whose metadata changed (nlink={st_locked.st_nlink}): {lock_path}"
            )
        if stat.S_IMODE(st_locked.st_mode) != mode:
            os.fchmod(fd, mode)
        yield
    finally:
        if locked:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
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
