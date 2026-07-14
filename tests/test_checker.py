from datetime import datetime, timedelta, timezone

from cert_sentinel.checker import Status, check_domain, run_checks
from cert_sentinel.config import Config

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _cert_fetcher_in(days: int):
    def fetcher(domain: str, port: int, timeout: float) -> dict:
        expiry = NOW + timedelta(days=days)
        return {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")}

    return fetcher


def _rdap_fetcher_in(days: int):
    def fetcher(domain: str, timeout: float) -> dict:
        expiry = NOW + timedelta(days=days)
        return {"events": [{"eventAction": "expiration", "eventDate": expiry.isoformat()}]}

    return fetcher


def test_all_ok_when_far_from_expiry():
    config = Config(domains=("example.com",), warn_days=30, critical_days=7)
    result = check_domain(
        "example.com",
        config,
        now=NOW,
        cert_fetcher=_cert_fetcher_in(365),
        rdap_fetcher=_rdap_fetcher_in(365),
    )
    assert result.status == Status.OK


def test_warn_when_within_warn_window():
    config = Config(domains=("example.com",), warn_days=30, critical_days=7)
    result = check_domain(
        "example.com",
        config,
        now=NOW,
        cert_fetcher=_cert_fetcher_in(20),
        rdap_fetcher=_rdap_fetcher_in(365),
    )
    assert result.status == Status.WARN
    assert result.cert_status == Status.WARN
    assert result.domain_status == Status.OK


def test_critical_when_within_critical_window():
    config = Config(domains=("example.com",), warn_days=30, critical_days=7)
    result = check_domain(
        "example.com",
        config,
        now=NOW,
        cert_fetcher=_cert_fetcher_in(3),
        rdap_fetcher=_rdap_fetcher_in(365),
    )
    assert result.status == Status.CRITICAL


def test_critical_when_already_expired():
    config = Config(domains=("example.com",), warn_days=30, critical_days=7)
    result = check_domain(
        "example.com",
        config,
        now=NOW,
        cert_fetcher=_cert_fetcher_in(-1),
        rdap_fetcher=_rdap_fetcher_in(365),
    )
    assert result.status == Status.CRITICAL


def test_error_when_fetcher_raises():
    config = Config(domains=("example.com",), warn_days=30, critical_days=7)

    def failing_fetcher(domain: str, port: int, timeout: float) -> dict:
        raise TimeoutError("connection timed out")

    result = check_domain(
        "example.com",
        config,
        now=NOW,
        cert_fetcher=failing_fetcher,
        rdap_fetcher=_rdap_fetcher_in(365),
    )
    assert result.cert_status == Status.ERROR
    assert any("tls:" in e for e in result.errors)


def test_run_checks_outcome_success_when_all_clear():
    config = Config(domains=("a.com", "b.com"), warn_days=30, critical_days=7)
    result = run_checks(
        config, now=NOW, cert_fetcher=_cert_fetcher_in(365), rdap_fetcher=_rdap_fetcher_in(365)
    )
    assert result.all_clear
    assert result.outcome == "success"


def test_run_checks_outcome_escalated_when_only_warnings():
    config = Config(domains=("a.com",), warn_days=30, critical_days=7)
    result = run_checks(
        config, now=NOW, cert_fetcher=_cert_fetcher_in(20), rdap_fetcher=_rdap_fetcher_in(365)
    )
    assert not result.all_clear
    assert not result.has_critical_or_error
    assert result.outcome == "escalated"


def test_run_checks_outcome_failure_when_critical_present():
    config = Config(domains=("a.com",), warn_days=30, critical_days=7)
    result = run_checks(
        config, now=NOW, cert_fetcher=_cert_fetcher_in(-5), rdap_fetcher=_rdap_fetcher_in(365)
    )
    assert result.has_critical_or_error
    assert result.outcome == "failure"
