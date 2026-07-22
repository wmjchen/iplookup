from app.core.client_ip import resolve_client_ip


def test_prefers_cf_connecting_ip():
    ip = resolve_client_ip(
        headers={
            "cf-connecting-ip": "8.8.8.8",
            "x-real-ip": "1.1.1.1",
            "x-forwarded-for": "9.9.9.9, 10.0.0.1",
        },
        peer="10.0.0.2",
        trust_proxy=True,
    )
    assert ip == "8.8.8.8"


def test_falls_back_to_x_real_ip():
    ip = resolve_client_ip(
        headers={"x-real-ip": "1.1.1.1"},
        peer="10.0.0.2",
        trust_proxy=True,
    )
    assert ip == "1.1.1.1"


def test_x_forwarded_for_first_public():
    ip = resolve_client_ip(
        headers={"x-forwarded-for": "10.0.0.8, 9.9.9.9, 10.0.0.9"},
        peer="10.0.0.2",
        trust_proxy=True,
    )
    assert ip == "9.9.9.9"


def test_untrusted_proxy_uses_peer():
    ip = resolve_client_ip(
        headers={"x-forwarded-for": "8.8.8.8"},
        peer="1.1.1.1",
        trust_proxy=False,
    )
    assert ip == "1.1.1.1"


def test_peer_fallback():
    ip = resolve_client_ip(headers={}, peer="1.0.0.1", trust_proxy=True)
    assert ip == "1.0.0.1"
