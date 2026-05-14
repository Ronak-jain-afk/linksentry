import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib


DEFAULT_CONFIG = {
    "model": {
        "path": None,
        "default_full": False,
        "confidence_threshold": 0.0,
    },
    "watch": {
        "interval": 300,
    },
    "api_keys": {
        "virustotal": "",
        "google_safe_browsing": "",
    },
}


def get_config_dir() -> Path:
    if os.name == 'nt':
        base = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming'))
    else:
        base = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config'))
    return base / 'linksentry'


def get_config_path() -> Path:
    return get_config_dir() / 'config.toml'


def load_config() -> dict:
    config_path = get_config_path()
    config = {}
    if config_path.exists():
        with open(config_path, 'rb') as f:
            config = tomllib.load(f)

    merged = {}
    for section, values in DEFAULT_CONFIG.items():
        merged[section] = dict(values)
        if section in config:
            merged[section].update({k: v for k, v in config[section].items() if v is not None})

    merged['_path'] = str(config_path)
    return merged


def init_config() -> Path:
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = get_config_path()

    if config_path.exists():
        return config_path

    lines = [
        "[model]",
        "# path = \"~/.linksentry/models\"",
        "# default_full = false",
        "# confidence_threshold = 0.0",
        "",
        "[watch]",
        "# interval = 300",
        "",
        "[api_keys]",
        '# virustotal = "your-api-key"',
        '# google_safe_browsing = "your-api-key"',
        "",
    ]
    config_path.write_text('\n'.join(lines))
    return config_path
