import functools
import hashlib
import json
import os
import time
from pathlib import Path


def _get_cache_dir() -> Path:
    if os.name == 'nt':
        base = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local'))
    else:
        base = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache'))
    return base / 'linksentry'


def _make_key(prefix: str, args, kwargs) -> str:
    raw = f'{prefix}:{args}:{sorted(kwargs.items())}'
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _cache_path(cache_dir: Path, key: str) -> Path:
    sub = key[:2]
    (cache_dir / sub).mkdir(parents=True, exist_ok=True)
    return cache_dir / sub / f'{key}.json'


def _read_cache(cache_dir: Path, key: str, ttl: int):
    path = _cache_path(cache_dir, key)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if time.time() - data['_ts'] < ttl:
            return data['value']
        path.unlink(missing_ok=True)
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _write_cache(cache_dir: Path, key: str, value):
    path = _cache_path(cache_dir, key)
    data = {'_ts': time.time(), 'value': value}
    path.write_text(json.dumps(data))


CACHE_DIR = _get_cache_dir()


def cached(prefix: str, ttl: int):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = _make_key(prefix, args, kwargs)
            cached = _read_cache(CACHE_DIR, key, ttl)
            if cached is not None:
                return cached
            result = func(*args, **kwargs)
            _write_cache(CACHE_DIR, key, result)
            return result
        return wrapper
    return decorator


def clear_cache():
    import shutil
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
