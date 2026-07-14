"""TLS certificate expiry lookups.

The real network call (`fetch_peer_cert`) is a thin, deliberately dumb
wrapper around the stdlib `ssl`/`socket` modules so it can be swapped out
entirely in tests via the `fetcher` parameter on `get_certificate_expiry`
-- no live TLS handshake happens in the test suite.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable
from datetime import datetime, timezone

# The stdlib's OpenSSL-derived certificate timestamp format, e.g.
# "Jun  3 12:00:00 2027 GMT".
_CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"

CertFetcher = Callable[[str, int, float], dict]


def fetch_peer_cert(domain: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Open a real TLS connection to `domain:port` and return the peer
    certificate dict as `ssl.SSLSocket.getpeercert()` provides it."""
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
            cert = tls_sock.getpeercert()
    if not cert:
        raise ValueError(f"no certificate returned for {domain}:{port}")
    return cert


def get_certificate_expiry(
    domain: str,
    port: int = 443,
    timeout: float = 10.0,
    fetcher: CertFetcher = fetch_peer_cert,
) -> datetime:
    """Return the UTC expiry datetime of `domain`'s TLS certificate."""
    cert = fetcher(domain, port, timeout)
    not_after = cert.get("notAfter")
    if not not_after:
        raise ValueError(f"certificate for {domain} has no notAfter field")
    naive = datetime.strptime(not_after, _CERT_TIME_FORMAT)
    return naive.replace(tzinfo=timezone.utc)
