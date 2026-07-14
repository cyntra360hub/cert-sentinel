# Contributing to cert-sentinel

Thanks for considering a contribution! This is a small, focused tool —
keep changes deterministic (no LLM calls, no paid APIs) and offline-testable
(mock the network, don't call real TLS/RDAP endpoints in tests).

## Getting started

```bash
git clone https://github.com/cyntra360hub/cert-sentinel.git
cd cert-sentinel
pip install -e ".[dev]"
pytest
```

## Workflow

1. Open an issue first for anything beyond a trivial fix, so we can agree
   on approach before you invest time.
2. Fork, branch, make your change, add/update tests.
3. Run `pytest` — all tests must pass, and new behavior needs new tests.
4. Open a PR describing what changed and why.

## Good first issues

These are scoped to be approachable without deep familiarity with the
codebase:

- **`good-first-issue`: Add JSON output mode.** Add a `--json` flag (or
  `CERT_SENTINEL_OUTPUT=json` env var) to `cli.py` that prints the
  `CheckResult` as machine-readable JSON instead of the human-readable
  report, for piping into other tools.
- **`good-first-issue`: Support IPv6-only hosts.** `tls.fetch_peer_cert`
  uses `socket.create_connection`, which already supports IPv6 — add a
  test (with a fake fetcher) confirming domain resolution failures are
  reported with a clear error message distinguishing "no A/AAAA record"
  from "connection refused" from "TLS handshake failed".
- **`good-first-issue`: Configurable per-domain thresholds.** Currently
  `warn_days`/`critical_days` are global. Extend `CERT_SENTINEL_DOMAINS`
  parsing (or add a new env var) to allow per-domain overrides, e.g.
  `example.com:14`, falling back to the global default.
- **`good-first-issue`: Add a `--domain` CLI flag.** Let a caller check a
  single ad-hoc domain without editing `CERT_SENTINEL_DOMAINS`, useful for
  quick manual checks.
- **`good-first-issue`: Improve RDAP error messages.** `domain.py`
  currently surfaces raw exceptions from `urllib` as-is. Add a small
  translation layer that turns common `urllib.error.HTTPError` /
  `URLError` cases (404 = domain not found in that registry, timeout,
  DNS failure) into clearer messages, with tests using a fake fetcher
  that raises each case.

## Code style

- Standard library only in the core package; the AiOps Enabler SDK is an
  optional extra (`pip install ".[report]"`), never a hard dependency.
- Keep network I/O behind an injectable "fetcher" parameter (see
  `tls.py` / `domain.py`) so tests never touch the network.
- No comments explaining *what* code does — only *why*, when non-obvious.
