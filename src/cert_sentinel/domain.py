"""Domain registration expiry lookups via RDAP (the IANA-standardized,
free, no-API-key successor to WHOIS -- RFC 9083).

`rdap.org` is a public bootstrap redirector that resolves any domain to
its authoritative registry RDAP server, so a single fixed URL pattern
works for arbitrary TLDs without us maintaining a registry map.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone

RdapFetcher = Callable[[str, float], dict]

RDAP_URL_TEMPLATE = "https://rdap.org/domain/{domain}"

# rdap.org's bootstrap redirect (resolving a domain to its authoritative
# registry RDAP server) has been observed taking >10s for some TLDs
# before succeeding -- one retry after a short pause absorbs that without
# masking a genuinely dead endpoint (still raises after both attempts).
_RETRY_ATTEMPTS = 2
_RETRY_DELAY_SECONDS = 2.0


def fetch_rdap_record(domain: str, timeout: float = 10.0) -> dict:
    """Fetch the real RDAP record for `domain` from rdap.org."""
    url = RDAP_URL_TEMPLATE.format(domain=domain)
    request = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
    last_error: Exception | None = None
    for attempt in range(_RETRY_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (TimeoutError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt < _RETRY_ATTEMPTS - 1:
                time.sleep(_RETRY_DELAY_SECONDS)
    assert last_error is not None
    raise last_error


def get_domain_expiry(
    domain: str,
    timeout: float = 10.0,
    fetcher: RdapFetcher = fetch_rdap_record,
) -> datetime | None:
    """Return the UTC registration-expiry datetime for `domain`, or None
    if the RDAP record has no expiration event (some registries omit it)."""
    record = fetcher(domain, timeout)
    for event in record.get("events", []):
        if event.get("eventAction") == "expiration":
            raw_date = event["eventDate"]
            return _parse_rdap_datetime(raw_date)
    return None


def _parse_rdap_datetime(raw: str) -> datetime:
    # RDAP dates are RFC 3339, e.g. "2027-06-03T04:00:00Z" or with a
    # numeric UTC offset. datetime.fromisoformat handles both once "Z" is
    # normalized to an explicit offset (Python's fromisoformat only
    # accepts "Z" directly from 3.11+, but we normalize anyway for
    # clarity and to tolerate fractional seconds with a trailing "Z").
    normalized = raw.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
