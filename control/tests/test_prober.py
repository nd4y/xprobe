"""Document parsing with the very code that runs on points (prober.Config)."""

import prober
import pytest

DOC = {
    "version": 5,
    "point": "yaroslavl",
    "labels": {"point": "yaroslavl", "vantage": "home", "country": "RU"},
    "subscriptions": {"check": "https://sub/check", "load": "https://sub/load"},
    "probes": {
        "tcp": {"enabled": True, "interval": 120, "subscription": "check"},
        "status": {"enabled": True, "interval": 900, "subscription": "check"},
        "download": {"enabled": False, "interval": 1800, "subscription": "load"},
    },
    "exit_expectations": {"WARP": "104.28.,172.6"},
    "push": {"url": "https://vmauth/api/v1/import/prometheus", "interval": 60},
}


def test_enabled_modes_become_probes():
    cfg = prober.Config.from_document(DOC, point="yaroslavl", push_password="tok")
    kinds = {p.kind for p in cfg.probes}
    assert kinds == {"tcp", "status"}          # download is disabled
    assert cfg.version == 5


def test_each_mode_reads_its_own_subscription():
    cfg = prober.Config.from_document(DOC, point="yaroslavl", push_password="tok")
    status = next(p for p in cfg.probes if p.kind == "status")
    assert status.subscription_url == "https://sub/check"


def test_push_credentials_are_point_name_and_secret():
    # One secret per point: the document-fetch token doubles as the push
    # password.
    cfg = prober.Config.from_document(DOC, point="yaroslavl", push_password="tok")
    assert cfg.push.username == "yaroslavl"
    assert cfg.push.password == "tok"


def test_exit_expectations_parse_into_regexes():
    cfg = prober.Config.from_document(DOC, point="p", push_password="t")
    pattern, prefixes = cfg.expectations[0]
    assert pattern.search("🌀 WARP ← DE")
    assert prefixes == ("104.28.", "172.6")


def test_enabled_mode_without_subscription_is_an_error():
    bad = dict(DOC, subscriptions={"check": "https://sub/check"},
               probes={"download": {"enabled": True, "subscription": "load"}})
    with pytest.raises(ValueError, match="download"):
        prober.Config.from_document(bad, point="p", push_password="t")


def test_no_enabled_modes_is_an_error():
    bad = dict(DOC, probes={"tcp": {"enabled": False}})
    with pytest.raises(ValueError, match="no enabled modes"):
        prober.Config.from_document(bad, point="p", push_password="t")
