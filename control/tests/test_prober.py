"""Document parsing with the very code that runs on points (prober.Config)."""

import prober
import pytest

BASE = "https://xprobe.example/api/points/yaroslavl/configs"
DOC = {
    "version": 5,
    "point": "yaroslavl",
    "labels": {"point": "yaroslavl", "vantage": "home", "country": "RU"},
    "probes": {
        "tcp": {"enabled": True, "interval": 120, "configs_url": f"{BASE}/tcp"},
        "status": {"enabled": True, "interval": 900, "configs_url": f"{BASE}/status"},
        "download": {"enabled": False, "interval": 1800, "configs_url": f"{BASE}/download"},
    },
    "exit_expectations": {"WARP": "104.28.,172.6"},
    "push": {"url": "https://vmauth/api/v1/import/prometheus", "interval": 60},
}


def test_enabled_modes_become_probes():
    cfg = prober.Config.from_document(DOC, point="yaroslavl", push_password="tok")
    kinds = {p.kind for p in cfg.probes}
    assert kinds == {"tcp", "status"}          # download is disabled
    assert cfg.version == 5


def test_each_mode_reads_its_own_config_endpoint():
    cfg = prober.Config.from_document(DOC, point="yaroslavl", push_password="tok")
    status = next(p for p in cfg.probes if p.kind == "status")
    assert status.subscription_url == f"{BASE}/status"
    # And carries the point's credentials — the endpoint is authenticated.
    assert status.auth == ("yaroslavl", "tok")


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


def test_enabled_mode_without_a_config_source_is_an_error():
    bad = dict(DOC, probes={"download": {"enabled": True}})
    with pytest.raises(ValueError, match="download"):
        prober.Config.from_document(bad, point="p", push_password="t")


def test_node_id_prefers_the_environment(monkeypatch, tmp_path):
    # The only identity that survives storage which does not: without it a
    # rescheduled pod enrolls as a new point.
    monkeypatch.setenv("NODE_ID", "pinned-by-the-orchestrator")
    monkeypatch.setattr(prober, "NODE_ID_PATH", str(tmp_path / "node-id"))
    assert prober.node_id() == "pinned-by-the-orchestrator"
    # And nothing is written: the environment is the source of truth here.
    assert not (tmp_path / "node-id").exists()


def test_node_id_falls_back_to_the_volume(monkeypatch, tmp_path):
    monkeypatch.delenv("NODE_ID", raising=False)
    monkeypatch.setattr(prober, "NODE_ID_PATH", str(tmp_path / "node-id"))
    first = prober.node_id()
    assert first and prober.node_id() == first     # stable across calls


def test_timing_camouflage_reaches_the_probes():
    # Without jitter and spread a round is a burst of handshakes on the dot,
    # in a fixed order — the clearest machine signature the probe emits.
    doc = dict(DOC, jitter=0.3, spread=0.4)
    cfg = prober.Config.from_document(doc, point="p", push_password="t")
    assert all(p.jitter == 0.3 and p.spread == 0.4 for p in cfg.probes)
    # Absent from the document — sane defaults, never zero.
    plain = prober.Config.from_document(DOC, point="p", push_password="t")
    assert all(p.jitter > 0 and p.spread > 0 for p in plain.probes)


def test_volume_settings_are_read_from_the_document():
    doc = dict(DOC, probes=dict(DOC["probes"],
                                download={"enabled": True, "configs_url": f"{BASE}/download",
                                          "url": "https://host/10Mb.dat",
                                          "min_bytes": 10 * 1024**2}))
    cfg = prober.Config.from_document(doc, point="p", push_password="t")
    dl = next(p for p in cfg.probes if p.kind == "download")
    assert dl.url == "https://host/10Mb.dat" and dl.min_bytes == 10 * 1024**2


def test_no_enabled_modes_is_an_error():
    bad = dict(DOC, probes={"tcp": {"enabled": False}})
    with pytest.raises(ValueError, match="no enabled modes"):
        prober.Config.from_document(bad, point="p", push_password="t")
