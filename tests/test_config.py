from cert_sentinel.config import DEFAULT_DOMAINS, load_config


def test_defaults_when_env_empty():
    config = load_config(env={})
    assert config.domains == DEFAULT_DOMAINS
    assert config.report_enabled is False
    assert config.warn_days == 30
    assert config.critical_days == 7


def test_custom_domains_from_env():
    config = load_config(env={"CERT_SENTINEL_DOMAINS": "a.com, b.com ,c.com"})
    assert config.domains == ("a.com", "b.com", "c.com")


def test_reporting_enabled_only_when_both_creds_present():
    assert load_config(env={"CERT_SENTINEL_AGENT_KEY_ID": "ak_x"}).report_enabled is False
    assert (
        load_config(
            env={"CERT_SENTINEL_AGENT_KEY_ID": "ak_x", "CERT_SENTINEL_AGENT_SECRET": "s"}
        ).report_enabled
        is True
    )


def test_thresholds_overridable():
    config = load_config(
        env={"CERT_SENTINEL_WARN_DAYS": "45", "CERT_SENTINEL_CRITICAL_DAYS": "14"}
    )
    assert config.warn_days == 45
    assert config.critical_days == 14
