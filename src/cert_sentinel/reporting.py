"""Optional AiOps Enabler reporting via the official `aiops-enabler` SDK.

Reporting only happens when the caller explicitly enables it (see
`config.load_config` -- both CERT_SENTINEL_AGENT_KEY_ID and
CERT_SENTINEL_AGENT_SECRET must be set). This module never phones home by
default, and importing it does not require the SDK to be installed unless
reporting is actually used.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from cert_sentinel.checker import CheckResult
from cert_sentinel.config import Config


def report_run(config: Config, result: CheckResult) -> dict[str, Any] | None:
    """Report one cert-sentinel run as a single task_started/task_completed
    event pair. Returns the platform's task_completed response, or None if
    reporting is disabled. Raises if reporting is enabled but the SDK call
    fails -- callers decide whether that should fail the run."""
    if not config.report_enabled:
        return None

    from aiops_enabler import AiOpsClient  # imported lazily: optional dep

    task_id = str(uuid.uuid4())
    started = time.monotonic()

    with AiOpsClient(
        agent_key_id=config.agent_key_id,  # type: ignore[arg-type]
        agent_secret=config.agent_secret,  # type: ignore[arg-type]
        base_url=config.base_url,
    ) as client:
        client.task_started(task_id=task_id)
        duration_ms = int((time.monotonic() - started) * 1000)
        return client.task_completed(
            task_id=task_id,
            outcome=result.outcome,
            duration_ms=duration_ms,
            category="observability",
        )
