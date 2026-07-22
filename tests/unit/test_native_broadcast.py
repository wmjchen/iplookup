from app.core.native_broadcast import classify_native_broadcast


def test_matching_countries_native():
    assert (
        classify_native_broadcast(
            usage_country_code="US",
            registration_country_code="US",
        )
        == "native"
    )


def test_mismatch_broadcast():
    assert (
        classify_native_broadcast(
            usage_country_code="CN",
            registration_country_code="NL",
        )
        == "broadcast"
    )


def test_missing_data_unknown():
    assert (
        classify_native_broadcast(
            usage_country_code=None,
            registration_country_code="US",
        )
        == "unknown"
    )
    assert (
        classify_native_broadcast(
            usage_country_code="US",
            registration_country_code=None,
        )
        == "unknown"
    )


def test_case_insensitive():
    assert (
        classify_native_broadcast(
            usage_country_code="us",
            registration_country_code="US",
        )
        == "native"
    )
