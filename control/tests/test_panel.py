"""The panel client's boundaries.

Target sets used to be applied by editing squad membership and patching live
host objects. That is gone: the control plane filters configs instead, so the
client must not be able to modify a host at all — `PATCH /api/hosts` silently
resets every field absent from the body, and no monitoring feature is worth
that risk.
"""

from control.panel import Host, Panel


def test_the_client_cannot_modify_hosts_or_squad_membership():
    for forbidden in ("patch_host", "set_squad_inbounds", "delete_host"):
        assert not hasattr(Panel, forbidden), f"{forbidden} must stay removed"


def test_the_client_still_provisions_accounts():
    for needed in ("create_squad", "create_user", "hosts", "squads", "subscription"):
        assert hasattr(Panel, needed)


def test_host_exclusions_are_still_readable_for_migration():
    # A point whose sets predate the switch has them in squad membership, so
    # the exclusion list must remain visible — read-only.
    h = Host(uuid="h1", remark="RU · TLS", inbound_uuid="i-tls", excluded=["sq"])
    assert h.excluded == ["sq"]
