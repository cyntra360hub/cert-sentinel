"""Orchestrates TLS + domain-registration expiry checks across a domain
list and reduces them to a single run-level status."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from cert_sentinel.config import Config
from cert_sentinel.domain import RdapFetcher, fetch_rdap_record, get_domain_expiry
from cert_sentinel.tls import CertFetcher, fetch_peer_cert, get_certificate_expiry


class Status(str, Enum):
    OK = "ok"
    WARN = "warn"
    CRITICAL = "critical"
    ERROR = "error"


@dataclass(frozen=True)
class DomainResult:
    domain: str
    cert_status: Status
    cert_expiry: datetime | None
    cert_days_left: int | None
    domain_status: Status
    domain_expiry: datetime | None
    domain_days_left: int | None
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> Status:
        order = [Status.OK, Status.WARN, Status.CRITICAL, Status.ERROR]
        return max((self.cert_status, self.domain_status), key=order.index)


@dataclass(frozen=True)
class CheckResult:
    domains: tuple[DomainResult, ...]

    @property
    def all_clear(self) -> bool:
        return all(d.status == Status.OK for d in self.domains)

    @property
    def has_critical_or_error(self) -> bool:
        return any(d.status in (Status.CRITICAL, Status.ERROR) for d in self.domains)

    @property
    def outcome(self) -> str:
        """Maps to the AiOps Enabler `task_completed` outcome enum
        (success | failure | escalated)."""
        if self.all_clear:
            return "success"
        if self.has_critical_or_error:
            return "failure"
        return "escalated"


def _days_left(expiry: datetime, now: datetime) -> int:
    return int((expiry - now).total_seconds() // 86400)


def _classify(days_left: int, warn_days: int, critical_days: int) -> Status:
    if days_left < 0:
        return Status.CRITICAL
    if days_left <= critical_days:
        return Status.CRITICAL
    if days_left <= warn_days:
        return Status.WARN
    return Status.OK


def check_domain(
    domain: str,
    config: Config,
    now: datetime | None = None,
    cert_fetcher: CertFetcher = fetch_peer_cert,
    rdap_fetcher: RdapFetcher = fetch_rdap_record,
) -> DomainResult:
    now = now or datetime.now(timezone.utc)
    errors: list[str] = []

    cert_status = Status.ERROR
    cert_expiry: datetime | None = None
    cert_days_left: int | None = None
    try:
        cert_expiry = get_certificate_expiry(
            domain, timeout=config.timeout_seconds, fetcher=cert_fetcher
        )
        cert_days_left = _days_left(cert_expiry, now)
        cert_status = _classify(cert_days_left, config.warn_days, config.critical_days)
    except Exception as exc:  # noqa: BLE001 - any failure means the check itself failed
        errors.append(f"tls: {exc}")

    domain_status = Status.ERROR
    domain_expiry: datetime | None = None
    domain_days_left: int | None = None
    try:
        domain_expiry = get_domain_expiry(
            domain, timeout=config.timeout_seconds, fetcher=rdap_fetcher
        )
        if domain_expiry is None:
            domain_status = Status.OK
            errors.append("rdap: no expiration event in record (registry omits it)")
        else:
            domain_days_left = _days_left(domain_expiry, now)
            domain_status = _classify(
                domain_days_left, config.warn_days, config.critical_days
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"rdap: {exc}")

    return DomainResult(
        domain=domain,
        cert_status=cert_status,
        cert_expiry=cert_expiry,
        cert_days_left=cert_days_left,
        domain_status=domain_status,
        domain_expiry=domain_expiry,
        domain_days_left=domain_days_left,
        errors=tuple(errors),
    )


def run_checks(
    config: Config,
    now: datetime | None = None,
    cert_fetcher: CertFetcher = fetch_peer_cert,
    rdap_fetcher: RdapFetcher = fetch_rdap_record,
) -> CheckResult:
    results = tuple(
        check_domain(
            domain, config, now=now, cert_fetcher=cert_fetcher, rdap_fetcher=rdap_fetcher
        )
        for domain in config.domains
    )
    return CheckResult(domains=results)
