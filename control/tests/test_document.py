import json

from control.config import Defaults
from control.db import Point
from control.document import build_document

DEF = Defaults()


SITE = "https://xprobe.example"


def point(**kw) -> Point:
    base = dict(
        name="yaroslavl", vantage="home", country="RU", city="Yaroslavl",
        check_sub_url="https://sub/check", version=7,
    )
    base.update(kw)
    return Point(**base)


def test_labels_without_pin_are_name_and_role_only():
    # Geo is not pinned — the probe sets country/city/ISP itself from its
    # address; they are not placed in the document at all.
    doc = build_document(point(), DEF)
    assert doc["version"] == 7
    assert doc["labels"] == {"point": "yaroslavl", "vantage": "home"}


def test_document_carries_no_subscription_links():
    # The probe reads configs from the control plane, so a subscription link
    # — which is a credential — never reaches the node.
    doc = build_document(point(), DEF, base_url=SITE)
    assert "subscriptions" not in doc
    assert "sub" not in json.dumps(doc).replace("subscription_interval", "")


def test_pinned_geo_goes_into_the_document():
    # The administrator pinned it — this label wins over self-detection.
    doc = build_document(point(pin_geo=True), DEF)
    assert doc["labels"] == {"point": "yaroslavl", "vantage": "home",
                             "country": "RU", "city": "Yaroslavl"}


def test_push_goes_to_the_control_plane_relay():
    doc = build_document(point(), DEF, base_url="https://xprobe.example")
    assert doc["push"]["url"] == "https://xprobe.example/api/points/yaroslavl/metrics"


def test_disabled_mode_is_served_disabled():
    doc = build_document(point(modes={"tcp": True, "status": True, "download": False}), DEF)
    assert doc["probes"]["download"]["enabled"] is False
    assert doc["probes"]["tcp"]["enabled"] is True


def test_each_check_points_at_its_own_config_endpoint():
    doc = build_document(point(), DEF, base_url=SITE)
    for kind in ("tcp", "status", "download"):
        assert doc["probes"][kind]["configs_url"] == \
            f"{SITE}/api/points/yaroslavl/configs/{kind}"


def test_interval_override_lands_in_the_document():
    doc = build_document(point(intervals={"status": 300}), DEF)
    assert doc["probes"]["status"]["interval"] == 300
    # While an untouched mode keeps the default.
    assert doc["probes"]["tcp"]["interval"] == DEF.tcp_interval


def test_push_is_absent_when_pushing_is_disabled():
    assert "push" not in build_document(point(push_enabled=False), DEF,
                                        base_url="https://xprobe.example")


def test_push_is_absent_without_any_target():
    # No base URL and no fallback push_url: omitting push beats handing the
    # probe an empty URL to fail against.
    assert "push" not in build_document(point(push_enabled=True), DEF)


def test_volume_test_settings_are_per_point():
    # The download check proves how much a tunnel lets through before DPI
    # cuts it, so the volume and its source belong to the point's network.
    doc = build_document(point(download_url="https://host/10Mb.dat",
                               download_min_bytes=10 * 1024**2), DEF)
    assert doc["probes"]["download"]["url"] == "https://host/10Mb.dat"
    assert doc["probes"]["download"]["min_bytes"] == 10 * 1024**2
    # Unset — the fleet default.
    plain = build_document(point(), DEF)
    assert plain["probes"]["download"]["min_bytes"] == DEF.download_min_bytes


def test_each_check_carries_its_own_core_version():
    # A config that works on one core can fail silently on another — that is
    # the whole reason this tool exists, so the version is per check.
    doc = build_document(point(cores={"status": "v26.7.28", "download": "v26.3.27"}), DEF)
    assert doc["probes"]["status"]["xray_version"] == "v26.7.28"
    assert doc["probes"]["download"]["xray_version"] == "v26.3.27"
    # Unset means the image default, not a guess.
    assert doc["probes"]["tcp"]["xray_version"] == ""


def test_document_says_whether_the_point_is_enabled():
    # This flag is what stops a probe: it cannot be inferred from silence.
    assert build_document(point(), DEF)["enabled"] is True
    assert build_document(point(enabled=False), DEF)["enabled"] is False


def test_document_carries_timing_camouflage():
    doc = build_document(point(), DEF)
    assert doc["jitter"] == DEF.jitter and doc["spread"] == DEF.spread


def test_own_exit_expectations_win_over_defaults():
    doc = build_document(point(exit_expectations={"WARP": "1.2.3."}), DEF)
    assert doc["exit_expectations"] == {"WARP": "1.2.3."}
    # Without own ones — the defaults.
    assert build_document(point(), DEF)["exit_expectations"] == DEF.exit_expectations
