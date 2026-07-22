import pytest

from app.core.iputil import classify_address, ip_version, is_public_ip, parse_ip, validate_query_ip


def test_parse_ipv4():
    ip = parse_ip("8.8.8.8")
    assert str(ip) == "8.8.8.8"
    assert ip_version(ip) == 4


def test_parse_ipv6():
    ip = parse_ip("2001:4860:4860::8888")
    assert ip_version(ip) == 6


def test_parse_invalid_raises():
    with pytest.raises(ValueError):
        parse_ip("not-an-ip")


def test_public_and_private():
    assert is_public_ip(parse_ip("8.8.8.8")) is True
    assert is_public_ip(parse_ip("10.0.0.1")) is False
    assert is_public_ip(parse_ip("127.0.0.1")) is False
    assert is_public_ip(parse_ip("192.168.1.1")) is False


def test_classify_address():
    assert classify_address(parse_ip("8.8.8.8")) == "public"
    assert classify_address(parse_ip("10.0.0.1")) == "private"
    assert classify_address(parse_ip("127.0.0.1")) == "loopback"
    assert classify_address(parse_ip("169.254.1.1")) == "link_local"


def test_validate_query_ip_ok():
    assert validate_query_ip("1.1.1.1") == "1.1.1.1"


def test_validate_query_ip_invalid():
    with pytest.raises(ValueError):
        validate_query_ip("999.1.1.1")
