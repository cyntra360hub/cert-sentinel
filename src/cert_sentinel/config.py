"""Configuration for cert-sentinel, sourced from environment variables so the
default behavior (checking the platform's own public-interest domain set)
is free of any config file, while still being fully overridable."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_DOMAINS = (
    "aiopsenabler.com",
    "cyntra360hub.com",
    "github.com",
    "cloudflare.com",
)

DEFAULT_WARN_DAYS = 30
DEFAULT_CRITICAL_DAYS = 7
DEFAULT_TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True)
class Config:
    domains: tuple[str, ...] = DEFAULT_DOMAINS
    warn_days: int = DEFAULT_WARN_DAYS
    critical_days: int = DEFAULT_CRITICAL_DAYS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    report_enabled: bool = False
    agent_key_id: str | None = None
    agent_secret: str | None = None
    base_url: str = "https://api.aiopsenabler.com"


def load_config(env: dict[str, str] | None = None) -> Config:
    """Build a Config from environment variables (or an injected mapping,
    for tests). Reporting is opt-in: it only turns on when both
    CERT_SENTINEL_AGENT_KEY_ID and CERT_SENTINEL_AGENT_SECRET are set."""
    source = env if env is not None else os.environ

    raw_domains = source.get("CERT_SENTINEL_DOMAINS", "").strip()
    domains = (
        tuple(d.strip() for d in raw_domains.split(",") if d.strip())
        if raw_domains
        else DEFAULT_DOMAINS
    )

    # `.get(key, default)` only falls back when the key is *absent* -- an
    # explicitly empty env var would otherwise silently win over the
    # default (and crash int()/float() on ""), so empty/unset is treated
    # the same via `or`.
    warn_days = int(source.get("CERT_SENTINEL_WARN_DAYS") or DEFAULT_WARN_DAYS)
    critical_days = int(source.get("CERT_SENTINEL_CRITICAL_DAYS") or DEFAULT_CRITICAL_DAYS)
    timeout_seconds = float(
        source.get("CERT_SENTINEL_TIMEOUT_SECONDS") or DEFAULT_TIMEOUT_SECONDS
    )

    key_id = source.get("CERT_SENTINEL_AGENT_KEY_ID") or None
    secret = source.get("CERT_SENTINEL_AGENT_SECRET") or None
    base_url = source.get("CERT_SENTINEL_BASE_URL") or "https://api.aiopsenabler.com"

    return Config(
        domains=domains,
        warn_days=warn_days,
        critical_days=critical_days,
        timeout_seconds=timeout_seconds,
        report_enabled=bool(key_id and secret),
        agent_key_id=key_id,
        agent_secret=secret,
        base_url=base_url,
    )
