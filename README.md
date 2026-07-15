# cert-sentinel

A small, deterministic Python agent that checks a configurable list of
domains for **TLS certificate expiry** and **domain registration
expiry**, and reports one clear all-clear-or-warnings summary per run.

No LLM calls, no paid APIs, no server to run — it's a script you run on
a schedule (cron, GitHub Actions, etc.) or by hand.

## What it does

For each configured domain, cert-sentinel:

1. Opens a real TLS connection and reads the certificate's `notAfter`
   date (stdlib `ssl`/`socket`, no third-party TLS library).
2. Looks up the domain's registration expiry via [RDAP](https://rdap.org)
   (the free, keyless, standardized successor to WHOIS — RFC 9083).
3. Classifies each into `ok` / `warn` / `critical` / `error` against
   configurable thresholds (default: warn at 30 days, critical at 7
   days or already expired).
4. Prints a report and exits non-zero if anything is `critical` or
   `error`, so it's usable directly as a CI/cron failure signal.

Default domain list: `aiopsenabler.com`, `cyntra360hub.com`,
`github.com`, `cloudflare.com`.

## Install

Requires Python 3.12+.

```bash
pip install .
```

## Usage

```bash
cert-sentinel
```

Or run it as a module:

```bash
python -m cert_sentinel.cli
```

### Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `CERT_SENTINEL_DOMAINS` | the four defaults above | comma-separated domain list |
| `CERT_SENTINEL_WARN_DAYS` | `30` | days-left threshold for `warn` |
| `CERT_SENTINEL_CRITICAL_DAYS` | `7` | days-left threshold for `critical` |
| `CERT_SENTINEL_TIMEOUT_SECONDS` | `10` | network timeout per check |

Copy `.env.example` to `.env` to set these locally; `.env` is
gitignored and never committed.

## Optional: AiOps Enabler integration

cert-sentinel can optionally report each run as a signed task event to
[AiOps Enabler](https://aiopsenabler.com), a public-interest registry of
verified AI agent performance. **This is opt-in and off by default** —
the agent never phones home unless you explicitly configure credentials.

Reporting is implemented as **raw HMAC-signed REST** (`src/cert_sentinel/signing.py`
+ `reporting.py`), built directly from the platform's own published spec
([skill.md](https://aiopsenabler.com/skill.md) §3,
[api-guide.md](https://aiopsenabler.com/api-guide.md) §2) using only the
standard library — no extra dependency to install. This is a deliberate
substitution for the officially-documented Python SDK
(`aiops-enabler`): as of this writing, the SDK's install command points
at `github.com/cyntra360hub/aiops-enabler`, which is a **private**
repository and not installable by the public despite being the
documented path for external integrators. Raw signed REST sidesteps that
and is functionally equivalent — same headers, same canonical signing
scheme, same test vector (see `tests/test_signing.py`).

To enable reporting, set two environment variables (in `.env` locally,
or as GitHub Actions secrets in CI — see `.github/workflows/scheduled.yml`):

```
CERT_SENTINEL_AGENT_KEY_ID=ak_...
CERT_SENTINEL_AGENT_SECRET=...
```

These are the API key pair issued when this agent registered on AiOps
Enabler. Never commit them.

With both set, each run sends a signed `task_started` / `task_completed`
event pair to `POST /api/v1/events`. `outcome` is `success` whenever the
checks actually ran — **including** when they find an expiring or
expired cert/domain, since detecting that is this agent doing its job,
not a failure. `outcome` is `failure` only when a check itself couldn't
run (network error, unreachable host). Any WARN/CRITICAL findings are
summarized in the event's `external_ref` field (the events API's only
freeform field) so the finding is still visible on your AiOps Enabler
profile, e.g. `"critical: example.com; warn: other.com"`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

All tests run fully offline — TLS and RDAP calls are replaced with
injected fake fetchers, so the suite never touches the network.

## License

MIT — see [LICENSE](LICENSE).
