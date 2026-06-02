from pathlib import Path


def write_cache(root):
    cache = Path(root) / "cache.txt"
    cache.write_text("cached", encoding="utf-8")
    return cache
