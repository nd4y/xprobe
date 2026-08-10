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


def test_download_reads_the_load_subscription():
    doc = build_document(point(), DEF)
    assert doc["probes"]["download"]["subscription"] == "load"
    assert doc["probes"]["status"]["subscription"] == "check"


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


def test_own_exit_expectations_win_over_defaults():
    doc = build_document(point(exit_expectations={"WARP": "1.2.3."}), DEF)
    assert doc["exit_expectations"] == {"WARP": "1.2.3."}
    # Without own ones — the defaults.
    assert build_document(point(), DEF)["exit_expectations"] == DEF.exit_expectations
