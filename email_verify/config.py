from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    data = json.loads(config_path.read_text())
    if not isinstance(data, dict):
        raise ValueError("Config file must contain a JSON object")
    return data
