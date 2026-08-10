from control.config import Defaults
from control.db import Point
from control.document import build_document

DEF = Defaults()


def point(**kw) -> Point:
    base = dict(
        name="yaroslavl", vantage="home", country="RU", city="Yaroslavl",
        check_sub_url="https://sub/check", load_sub_url="https://sub/load",
        version=7,
    )
    base.update(kw)
    return Point(**base)


def test_labels_without_pin_are_name_and_role_only():
    # Geo is not pinned — the probe sets country/city/ISP itself from its
    # address; they are not placed in the document at all.
    doc = build_document(point(), DEF)
    assert doc["version"] == 7
    assert doc["labels"] == {"point": "yaroslavl", "vantage": "home"}
    assert doc["subscriptions"] == {"check": "https://sub/check", "load": "https://sub/load"}


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


def test_each_check_reads_its_own_subscription():
    doc = build_document(point(tcp_sub_url="https://sub/tcp"), DEF)
    assert doc["probes"]["download"]["subscription"] == "load"
    assert doc["probes"]["status"]["subscription"] == "check"
    assert doc["probes"]["tcp"]["subscription"] == "tcp"
    assert doc["subscriptions"]["tcp"] == "https://sub/tcp"


def test_tcp_falls_back_to_the_http_subscription_when_unset():
    # A point provisioned before the tcp set existed has no tcp subscription;
    # tcp then reads the http (check) set rather than nothing.
    doc = build_document(point(), DEF)
    assert "tcp" not in doc["subscriptions"]
    assert doc["probes"]["tcp"]["subscription"] == "check"


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


def test_document_carries_timing_camouflage():
    doc = build_document(point(), DEF)
    assert doc["jitter"] == DEF.jitter and doc["spread"] == DEF.spread


def test_own_exit_expectations_win_over_defaults():
    doc = build_document(point(exit_expectations={"WARP": "1.2.3."}), DEF)
    assert doc["exit_expectations"] == {"WARP": "1.2.3."}
    # Without own ones — the defaults.
    assert build_document(point(), DEF)["exit_expectations"] == DEF.exit_expectations
