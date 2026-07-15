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


def test_report_uses_failure_outcome_on_critical():
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.CRITICAL), poster=poster)

    import json

    second_body = json.loads(poster.calls[1][1])
    assert second_body["outcome"] == "failure"


def test_requests_are_signed_with_correct_headers():
    poster = _FakePoster()
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.OK), poster=poster)
    for url, body, headers in poster.calls:
        assert url.endswith("/api/v1/events")
        assert headers["X-Agent-Key-Id"] == "ak_test"
        assert "X-Agent-Signature" in headers
        assert "X-Agent-Timestamp" in headers


def test_reporting_error_carries_status_and_detail():
    err = ReportingError(422, '{"detail": "bad request"}')
    assert err.status_code == 422
    assert "bad request" in err.detail
