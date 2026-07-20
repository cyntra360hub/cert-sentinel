from cert_sentinel.checker import CheckResult, DomainResult, Status
from cert_sentinel.config import Config
from cert_sentinel.reporting import ReportingError, report_run


def _result(status: Status) -> CheckResult:
    domain = DomainResult(
        domain="example.com",
        cert_status=status,
        cert_expiry=None,
        cert_days_left=None,
        domain_status=Status.OK,
        domain_expiry=None,
        domain_days_left=None,
    )
    return CheckResult(domains=(domain,))


class _FakePoster:
    def __init__(self):
        self.calls: list[tuple[str, bytes, dict]] = []

    def __call__(self, url, body, headers):
        self.calls.append((url, body, headers))
        return {"id": "evt_123"}


def test_report_disabled_returns_none():
    poster = _FakePoster()
    config = Config(report_enabled=False)
    assert report_run(config, _result(Status.OK), poster=poster) is None
    assert poster.calls == []


def test_report_enabled_sends_started_then_completed():
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    response = report_run(config, _result(Status.OK), poster=poster)
    assert response == {"id": "evt_123"}
    assert len(poster.calls) == 2

    import json

    first_body = json.loads(poster.calls[0][1])
    second_body = json.loads(poster.calls[1][1])
    assert first_body["event_type"] == "task_started"
    assert second_body["event_type"] == "task_completed"
    assert second_body["outcome"] == "success"
    assert second_body["task_id"] == first_body["task_id"]


def test_report_uses_success_outcome_with_details_and_external_ref():
    # A detected critical finding (e.g. expired cert) is still a
    # successful run -- the finding goes in `details` (human-readable,
    # what the platform's pulse renders) and `external_ref` (fuller
    # technical detail), not in outcome.
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.CRITICAL), poster=poster)

    import json

    second_body = json.loads(poster.calls[1][1])
    assert second_body["outcome"] == "success"
    assert second_body["details"] == "found 1 expiring issue across 1 domain -- e.g. example.com"
    assert second_body["external_ref"] == "example.com"


def test_report_uses_failure_outcome_on_check_error():
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.ERROR), poster=poster)

    import json

    second_body = json.loads(poster.calls[1][1])
    assert second_body["outcome"] == "failure"
    assert "external_ref" not in second_body
    assert "details" not in second_body


def test_report_omits_details_and_external_ref_when_all_clear():
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.OK), poster=poster)

    import json

    second_body = json.loads(poster.calls[1][1])
    assert "external_ref" not in second_body
    assert "details" not in second_body


def test_requests_are_signed_with_correct_headers():
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.OK), poster=poster)
    for url, body, headers in poster.calls:
        assert url.endswith("/api/v1/events")
        assert headers["X-Agent-Key-Id"] == "ak_test"
        assert "X-Agent-Signature" in headers
        assert "X-Agent-Timestamp" in headers


def test_duration_ms_is_never_zero_even_for_instant_runs():
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.OK), poster=poster)

    import json

    second_body = json.loads(poster.calls[1][1])
    assert isinstance(second_body["duration_ms"], int)
    assert second_body["duration_ms"] >= 1


def test_duration_ms_reflects_real_elapsed_run_time():
    import time

    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    run_started = time.monotonic() - 2.5  # simulate a check phase that took 2.5s
    report_run(config, _result(Status.OK), poster=poster, run_started=run_started)

    import json

    second_body = json.loads(poster.calls[1][1])
    assert second_body["duration_ms"] >= 2500


def test_reporting_error_carries_status_and_detail():
    err = ReportingError(422, '{"detail": "bad request"}')
    assert err.status_code == 422
    assert "bad request" in err.detail
