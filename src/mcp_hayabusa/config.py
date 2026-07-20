"""Locates the hayabusa binary this server shells out to."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


class HayabusaNotFoundError(RuntimeError):
    pass


def resolve_hayabusa_binary() -> str:
    env_path = os.environ.get("HAYABUSA_BIN")
    if env_path:
        if not Path(env_path).is_file():
            raise HayabusaNotFoundError(
                f"HAYABUSA_BIN is set to '{env_path}' but no file exists there"
            )
        return env_path

    found = shutil.which("hayabusa") or shutil.which("hayabusa.exe")
    if found:
        return found

    raise HayabusaNotFoundError(
        "Could not locate the hayabusa binary. Set the HAYABUSA_BIN environment "
        "variable to its full path, or add it to your PATH."
    )
