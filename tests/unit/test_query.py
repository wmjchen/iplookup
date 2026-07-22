import pytest

from app.core.query import classify_query, is_hostname, normalize_hostname


def test_classify_ip():
    kind, value = classify_query("8.8.8.8")
    assert kind == "ip"
    assert value == "8.8.8.8"


def test_classify_domain():
    kind, value = classify_query("Google.com")
    assert kind == "domain"
    assert value == "google.com"


def test_classify_domain_trailing_dot():
    kind, value = classify_query("spartanhost.com.")
    assert kind == "domain"
    assert value == "spartanhost.com"


def test_invalid():
    with pytest.raises(ValueError):
        classify_query("not a host")
    with pytest.raises(ValueError):
        classify_query("")


def test_is_hostname():
    assert is_hostname("example.com")
    assert is_hostname("sub.example.co.uk")
    assert not is_hostname("8.8.8.8")
    assert not is_hostname("no spaces.com")


def test_normalize():
    assert normalize_hostname("Ex.COM.") == "ex.com"
