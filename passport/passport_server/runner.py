#!/usr/bin/env python3
"""Unified entrypoint for xiaozhi-server wrapped with Passport security/runtime fixes."""

import asyncio
import os
import sys
from pathlib import Path


def main() -> None:
    passport_root = Path(__file__).resolve().parents[1]
    xiaozhi_home = Path(os.environ.get("XIAOZHI_HOME", os.getcwd())).resolve()

    if not (xiaozhi_home / "app.py").is_file():
        sys.exit(f"XIAOZHI_HOME does not contain app.py: {xiaozhi_home}")

    os.chdir(xiaozhi_home)
    for entry in (str(passport_root), str(xiaozhi_home)):
        if entry not in sys.path:
            sys.path.insert(0, entry)

    from passport_server.patches import apply_all_patches

    apply_all_patches()

    import app

    try:
        asyncio.run(app.main())
    except KeyboardInterrupt:
        print("手动中断，程序终止。")


if __name__ == "__main__":
    main()
