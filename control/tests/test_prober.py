"""Document parsing with the very code that runs on points (prober.Config)."""

import json

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


def test_core_version_reaches_each_probe():
    doc = dict(DOC, probes=dict(
        DOC["probes"],
        status={"enabled": True, "configs_url": f"{BASE}/status", "xray_version": "v26.7.28"},
        tcp={"enabled": True, "configs_url": f"{BASE}/tcp"}))
    cfg = prober.Config.from_document(doc, point="p", push_password="t")
    by_kind = {p.kind: p for p in cfg.probes}
    assert by_kind["status"].xray_version == "v26.7.28"
    assert by_kind["tcp"].xray_version == ""       # tcp runs no core


def test_an_unknown_core_is_refused_not_substituted(monkeypatch, tmp_path):
    # Probing with a different core than the one asked for produces a
    # confident answer to a question nobody asked.
    (tmp_path / "v26.7.28").mkdir()
    binary = tmp_path / "v26.7.28" / "xray"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setattr(prober, "XRAY_DIR", str(tmp_path))

    assert prober.xray_binary("v26.7.28") == str(binary)
    with pytest.raises(LookupError, match="v26.3.27"):
        prober.xray_binary("v26.3.27")


def test_a_check_with_a_missing_core_reports_instead_of_running(monkeypatch, tmp_path):
    monkeypatch.setattr(prober, "XRAY_DIR", str(tmp_path))          # no cores at all
    probe = prober.Probe(kind="status", subscription_url="", interval=300, start_port=20000,
                         timeout=5, url="http://example", xray_version="v26.3.27")
    res = prober.probe_one({"remarks": "x", "outbounds": [{}]}, 20000, probe,
                           prober.Config(probes=(probe,)))
    assert res.up is False
    assert "v26.3.27" in res.error


def test_a_fetched_core_must_match_its_checksum(monkeypatch, tmp_path):
    # The checksum is what makes fetching a binary acceptable; failing it has
    # to discard the download, not warn about it.
    monkeypatch.setattr(prober, "CORE_CACHE", str(tmp_path / "cores"))
    monkeypatch.setattr(prober, "urllib", prober.urllib)

    class FakeResponse:
        def __init__(self, blob):
            self._blob = blob

        def read(self):
            return self._blob

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(prober.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(b"not a real release"))
    with pytest.raises(ValueError, match="checksum mismatch"):
        prober.fetch_core("v26.7.28", "d" * 64)
    assert not (tmp_path / "cores" / "v26.7.28" / "xray").exists()


def test_a_core_without_a_checksum_is_never_fetched(monkeypatch, tmp_path):
    monkeypatch.setattr(prober, "CORE_CACHE", str(tmp_path / "cores"))
    with pytest.raises(ValueError, match="no checksum"):
        prober.fetch_core("v26.7.28", "")


def test_a_version_that_is_not_a_plain_name_is_refused(monkeypatch, tmp_path):
    # The version becomes a path under the cache; with relaying enabled the
    # control plane supplies both bytes and checksum, so "../.." would let it
    # choose where the file lands. Refused before any network access.
    monkeypatch.setattr(prober, "CORE_CACHE", str(tmp_path / "cores"))

    def no_network(*a, **k):
        raise AssertionError("must be refused before any fetch")

    monkeypatch.setattr(prober.urllib.request, "urlopen", no_network)
    for bad in ("../evil", "v1/..", "a\\b", ".hidden"):
        with pytest.raises(ValueError, match="plain release tag"):
            prober.fetch_core(bad, "a" * 64)
    assert not (tmp_path / "cores").exists()


def test_unused_cores_are_removed_but_the_image_is_left_alone(monkeypatch, tmp_path):
    # Cached cores are tens of megabytes each; one that nothing asks for any
    # more should not sit on someone else's disk forever. What the image
    # carries is not ours to delete.
    cache, baked = tmp_path / "cores", tmp_path / "image"
    for root, version in ((cache, "v26.3.27"), (cache, "v26.7.28"), (baked, "v26.0.0")):
        (root / version).mkdir(parents=True)
        binary = root / version / "xray"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
    monkeypatch.setattr(prober, "CORE_CACHE", str(cache))
    monkeypatch.setattr(prober, "XRAY_DIR", str(baked))

    prober.ensure_cores({}, {"v26.7.28"})
    assert (cache / "v26.7.28").exists()
    assert not (cache / "v26.3.27").exists()      # nothing wants it now
    assert (baked / "v26.0.0").exists()           # the image keeps its own


def test_a_disabled_document_builds_nothing(monkeypatch, tmp_path):
    # The probe must stand down rather than keep its old configuration: this
    # is what makes disabling a point in the UI actually stop the node.
    monkeypatch.setattr(prober, "CACHE_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(prober, "fetch_document",
                        lambda *a, **k: dict(DOC, enabled=False))
    monkeypatch.setattr(prober, "resolve_identity", lambda url: ("yar", "sec"))
    cfg, point, secret = prober.build_config("https://control")
    assert cfg is None and point == "yar"


def test_a_disabled_cache_does_not_resume_on_an_outage(monkeypatch, tmp_path):
    # The control plane being unreachable must not look like permission to
    # start probing again.
    cache = tmp_path / "config.json"
    cache.write_text(json.dumps(dict(DOC, enabled=False)), encoding="utf-8")
    monkeypatch.setattr(prober, "CACHE_PATH", str(cache))
    monkeypatch.setattr(prober, "resolve_identity", lambda url: ("yar", "sec"))

    def boom(*a, **k):
        raise OSError("control plane down")

    monkeypatch.setattr(prober, "fetch_document", boom)
    cfg, _, _ = prober.build_config("https://control")
    assert cfg is None


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
