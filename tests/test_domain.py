from datetime import datetime, timezone

from cert_sentinel.domain import get_domain_expiry


def _fake_fetcher(record: dict):
    def fetcher(domain: str, timeout: float) -> dict:
        return record

    return fetcher


def test_parses_expiration_event():
    record = {
        "events": [
            {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-06-03T04:00:00Z"},
        ]
    }
    expiry = get_domain_expiry("example.com", fetcher=_fake_fetcher(record))
    assert expiry == datetime(2027, 6, 3, 4, 0, 0, tzinfo=timezone.utc)


def test_no_expiration_event_returns_none():
    record = {"events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}]}
    assert get_domain_expiry("example.com", fetcher=_fake_fetcher(record)) is None


def test_no_events_key_returns_none():
    assert get_domain_expiry("example.com", fetcher=_fake_fetcher({})) is None


def test_handles_numeric_offset_and_fractional_seconds():
    record = {
        "events": [
            {"eventAction": "expiration", "eventDate": "2027-06-03T04:00:00.123+00:00"}
        ]
    }
    expiry = get_domain_expiry("example.com", fetcher=_fake_fetcher(record))
    assert expiry.year == 2027 and expiry.tzinfo is not None
