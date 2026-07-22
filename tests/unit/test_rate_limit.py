import time

from app.core.rate_limit import RateLimiter


def test_allows_up_to_limit():
    lim = RateLimiter(max_requests=3, window_seconds=60)
    assert lim.hit("1.1.1.1").allowed is True
    assert lim.hit("1.1.1.1").allowed is True
    r = lim.hit("1.1.1.1")
    assert r.allowed is True
    assert r.remaining == 0
    assert r.limit == 3


def test_blocks_over_limit():
    lim = RateLimiter(max_requests=2, window_seconds=60)
    lim.hit("8.8.8.8")
    lim.hit("8.8.8.8")
    r = lim.hit("8.8.8.8")
    assert r.allowed is False
    assert r.remaining == 0
    assert r.retry_after > 0


def test_keys_are_independent():
    lim = RateLimiter(max_requests=1, window_seconds=60)
    assert lim.hit("a").allowed is True
    assert lim.hit("b").allowed is True
    assert lim.hit("a").allowed is False
    assert lim.hit("b").allowed is False


def test_window_expiry_allows_again():
    lim = RateLimiter(max_requests=1, window_seconds=0.05)
    assert lim.hit("x").allowed is True
    assert lim.hit("x").allowed is False
    time.sleep(0.07)
    assert lim.hit("x").allowed is True


def test_disabled_when_max_requests_zero():
    lim = RateLimiter(max_requests=0, window_seconds=60)
    for _ in range(20):
        r = lim.hit("1.2.3.4")
        assert r.allowed is True
