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

    from config.config_loader import load_config
    from config.settings import check_config_file
    from core.utils.cache.manager import CacheType, cache_manager
    from loguru import logger
    from passport_server.device_auth import validate_runtime_auth_config
    from passport_server.redaction import register_secrets_from_config

    try:
        check_config_file()
        main_config = cache_manager.get(CacheType.CONFIG, "main_config")
        if main_config is None:
            main_config = asyncio.run(load_config())
        validate_runtime_auth_config(main_config)
        register_secrets_from_config(main_config)
    except Exception as exc:
        logger.complete()
        sys.exit(f"Passport configuration validation failed: {exc}")

    import app

    try:
        asyncio.run(app.main())
    except KeyboardInterrupt:
        print("手动中断，程序终止。")
    finally:
        logger.complete()


if __name__ == "__main__":
    main()
