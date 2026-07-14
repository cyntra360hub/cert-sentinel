"""cert-sentinel command-line entry point."""

from __future__ import annotations

import sys

from cert_sentinel.checker import CheckResult, Status, run_checks
from cert_sentinel.config import load_config
from cert_sentinel.reporting import report_run

_STATUS_ICON = {
    Status.OK: "OK",
    Status.WARN: "WARN",
    Status.CRITICAL: "CRITICAL",
    Status.ERROR: "ERROR",
}


def _print_report(result: CheckResult) -> None:
    for d in result.domains:
        print(f"[{_STATUS_ICON[d.status]}] {d.domain}")
        if d.cert_days_left is not None:
            print(f"    tls cert:    {_STATUS_ICON[d.cert_status]:8} {d.cert_days_left} days left (expires {d.cert_expiry})")
        if d.domain_days_left is not None:
            print(f"    domain reg:  {_STATUS_ICON[d.domain_status]:8} {d.domain_days_left} days left (expires {d.domain_expiry})")
        for err in d.errors:
            print(f"    ! {err}")
    print()
    print(f"Overall: {'ALL CLEAR' if result.all_clear else 'WARNINGS PRESENT'} (outcome={result.outcome})")


def main() -> int:
    config = load_config()
    result = run_checks(config)
    _print_report(result)

    if config.report_enabled:
        try:
            report_run(config, result)
            print("Reported run to AiOps Enabler.")
        except Exception as exc:  # noqa: BLE001
            print(f"AiOps Enabler reporting failed (non-fatal): {exc}", file=sys.stderr)
    else:
        print("AiOps Enabler reporting disabled (no credentials configured).")

    return 0 if not result.has_critical_or_error else 1


if __name__ == "__main__":
    raise SystemExit(main())
