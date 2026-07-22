import time

from app.core.cache import TTLCache


def test_cache_set_get():
    c = TTLCache(ttl_seconds=60)
    c.set("k", {"a": 1})
    assert c.get("k") == {"a": 1}


def test_cache_miss():
    c = TTLCache(ttl_seconds=60)
    assert c.get("missing") is None


def test_cache_expiry():
    c = TTLCache(ttl_seconds=0.05)
    c.set("k", "v")
    time.sleep(0.07)
    assert c.get("k") is None
