"""Orchestrates TLS + domain-registration expiry checks across a domain
list and reduces them to a single run-level status."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from cert_sentinel.config import Config
from cert_sentinel.domain import RdapFetcher, fetch_rdap_record, get_domain_expiry
from cert_sentinel.tls import CertFetcher, fetch_peer_cert, get_certificate_expiry


def _pluralize(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


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
        """Used for this CLI's own exit code (a real monitoring signal
        for cron/CI use) -- distinct from `outcome` below, which reports
        to AiOps Enabler and treats CRITICAL as a successful detection,
        not a tool failure."""
        return any(d.status in (Status.CRITICAL, Status.ERROR) for d in self.domains)

    @property
    def has_errors(self) -> bool:
        """True only when a check itself couldn't run (network failure,
        unreachable host, etc.) -- as opposed to WARN/CRITICAL, which
        mean the check ran fine and found a real expiring/expired
        cert or domain. This is the only condition that should ever
        report `outcome=failure` to AiOps Enabler; a detected expiry is
        the agent doing its job, not the agent failing."""
        return any(
            d.cert_status == Status.ERROR or d.domain_status == Status.ERROR
            for d in self.domains
        )

    @property
    def _flagged(self) -> list["DomainResult"]:
        return [d for d in self.domains if d.status in (Status.WARN, Status.CRITICAL)]

    @property
    def findings_summary(self) -> str | None:
        """A short, human-readable findings summary for the AiOps
        Enabler event's `details` field -- what actually renders on the
        agent's public pulse/profile activity (see api-guide.md §4).
        Deduplicated to a single named example plus a count rather than
        an exhaustive per-domain list; carries no technical identifiers.
        None when there's nothing to report."""
        flagged = self._flagged
        if not flagged:
            return None
        example = flagged[0]
        days = (
            example.cert_days_left
            if example.cert_status in (Status.WARN, Status.CRITICAL)
            else example.domain_days_left
        )
        example_text = f"{example.domain} ({_pluralize(days, 'day')})" if days is not None else example.domain
        issue_word = _pluralize(len(flagged), "expiring issue")
        domain_word = _pluralize(len(self.domains), "domain")
        return f"found {issue_word} across {domain_word} -- e.g. {example_text}"[:500]

    @property
    def technical_summary(self) -> str | None:
        """The fuller, per-domain technical detail (every flagged
        domain, with day counts) for the event's legacy `external_ref`
        field -- kept separate from `findings_summary` so the
        human-facing summary never has to carry this level of detail."""
        flagged = self._flagged
        if not flagged:
            return None
        parts = []
        for d in flagged:
            bits = []
            if d.cert_status in (Status.WARN, Status.CRITICAL) and d.cert_days_left is not None:
                bits.append(f"cert {d.cert_days_left}d")
            if d.domain_status in (Status.WARN, Status.CRITICAL) and d.domain_days_left is not None:
                bits.append(f"domain {d.domain_days_left}d")
            parts.append(f"{d.domain} ({', '.join(bits)})" if bits else d.domain)
        return "; ".join(parts)[:255]

    @property
    def outcome(self) -> str:
        """Maps to the AiOps Enabler `task_completed` outcome enum
        (success | failure | escalated). `failure` is reserved for the
        check itself erroring out (see `has_errors`); a completed run
        that *found* expiring/expired certs or domains is `success` --
        detection is this agent doing its job, and the findings are
        reported via `external_ref` (see `findings_summary`), not via a
        non-success outcome."""
        return "failure" if self.has_errors else "success"


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
