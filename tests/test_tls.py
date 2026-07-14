from datetime import datetime, timezone

import pytest

from cert_sentinel.tls import get_certificate_expiry


def _fake_fetcher(not_after: str):
    def fetcher(domain: str, port: int, timeout: float) -> dict:
        return {"notAfter": not_after, "subject": ((("commonName", domain),),)}

    return fetcher


def test_parses_cert_expiry_to_utc():
    expiry = get_certificate_expiry(
        "example.com", fetcher=_fake_fetcher("Jun  3 12:00:00 2027 GMT")
    )
    assert expiry == datetime(2027, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


def test_missing_not_after_raises():
    def fetcher(domain: str, port: int, timeout: float) -> dict:
        return {}

    with pytest.raises(ValueError, match="notAfter"):
        get_certificate_expiry("example.com", fetcher=fetcher)


def test_fetcher_receives_domain_port_timeout():
    seen = {}

    def fetcher(domain: str, port: int, timeout: float) -> dict:
        seen["args"] = (domain, port, timeout)
        return {"notAfter": "Jan  1 00:00:00 2030 GMT"}

    get_certificate_expiry("example.com", port=8443, timeout=5.0, fetcher=fetcher)
    assert seen["args"] == ("example.com", 8443, 5.0)
