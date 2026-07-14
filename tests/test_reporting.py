import sys
import types

from cert_sentinel.checker import CheckResult, DomainResult, Status
from cert_sentinel.config import Config
from cert_sentinel.reporting import report_run


def _result(outcome_status: Status) -> CheckResult:
    domain = DomainResult(
        domain="example.com",
        cert_status=outcome_status,
        cert_expiry=None,
        cert_days_left=None,
        domain_status=Status.OK,
        domain_expiry=None,
        domain_days_left=None,
    )
    return CheckResult(domains=(domain,))


class _FakeClient:
    calls: list[tuple[str, dict]] = []

    def __init__(self, *, agent_key_id, agent_secret, base_url):
        self.agent_key_id = agent_key_id
        self.agent_secret = agent_secret
        self.base_url = base_url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def task_started(self, *, task_id):
        _FakeClient.calls.append(("task_started", {"task_id": task_id}))
        return {}

    def task_completed(self, *, task_id, outcome, duration_ms, category=None, external_ref=None):
        _FakeClient.calls.append(
            ("task_completed", {"task_id": task_id, "outcome": outcome, "category": category})
        )
        return {"ok": True}


def _install_fake_sdk(monkeypatch):
    fake_module = types.ModuleType("aiops_enabler")
    fake_module.AiOpsClient = _FakeClient
    monkeypatch.setitem(sys.modules, "aiops_enabler", fake_module)
    _FakeClient.calls = []


def test_report_disabled_returns_none(monkeypatch):
    _install_fake_sdk(monkeypatch)
    config = Config(report_enabled=False)
    assert report_run(config, _result(Status.OK)) is None
    assert _FakeClient.calls == []


def test_report_enabled_sends_started_then_completed(monkeypatch):
    _install_fake_sdk(monkeypatch)
    config = Config(
        report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret"
    )
    response = report_run(config, _result(Status.OK))
    assert response == {"ok": True}
    kinds = [c[0] for c in _FakeClient.calls]
    assert kinds == ["task_started", "task_completed"]
    assert _FakeClient.calls[1][1]["outcome"] == "success"


def test_report_uses_failure_outcome_on_critical(monkeypatch):
    _install_fake_sdk(monkeypatch)
    config = Config(report_enabled=True, agent_key_id="ak_test", agent_secret="s3cret")
    report_run(config, _result(Status.CRITICAL))
    assert _FakeClient.calls[1][1]["outcome"] == "failure"
