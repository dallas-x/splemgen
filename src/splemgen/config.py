import json
from dataclasses import asdict
from pathlib import Path

from platformdirs import user_config_dir

from .models import UserConfig

APP_NAME = "splunk-event-mgmt"
APP_AUTHOR = "dallas-baker"


def get_config_path() -> Path:
    config_dir = Path(user_config_dir(APP_NAME, APP_AUTHOR))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.json"


def save_config(config: UserConfig) -> Path:
    path = get_config_path()
    with path.open("w", encoding="utf-8") as f:
        json.dump(asdict(config), f, indent=2)
    return path


def load_config() -> UserConfig:
    path = get_config_path()
    if not path.exists():
        raise FileNotFoundError(f"Config not found at {path}. Run `event-mgmt init` first.")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    return UserConfig(**data)
