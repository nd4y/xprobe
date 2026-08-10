from control.panel import Host, plan_squad_membership

# Three hosts, two sharing one inbound (like RU-XHTTP in a real panel: the
# same inbound serves both the direct entry and the CDN entry).
HOSTS = [
    Host(uuid="h1", remark="RU · TLS", inbound_uuid="i-tls"),
    Host(uuid="h2", remark="RU · XHTTP", inbound_uuid="i-xhttp"),
    Host(uuid="h3", remark="RU ← CF · XHTTP", inbound_uuid="i-xhttp"),
]


def test_squad_inbounds_are_the_union_of_selected():
    inbounds, _ = plan_squad_membership("sq", HOSTS, {"RU · TLS", "RU · XHTTP"})
    assert set(inbounds) == {"i-tls", "i-xhttp"}


def test_inbound_neighbor_is_hidden_by_exclusion():
    # Only one of the two hosts on the shared inbound is selected — the other
    # must be excluded, or it would show up in the squad along for the ride.
    _, changed = plan_squad_membership("sq", HOSTS, {"RU · XHTTP"})
    assert changed == {"h3": ["sq"]}


def test_stale_exclusion_is_removed():
    hosts = [Host(uuid="h2", remark="RU · XHTTP", inbound_uuid="i-xhttp", excluded=["sq"])]
    _, changed = plan_squad_membership("sq", hosts, {"RU · XHTTP"})
    assert changed == {"h2": []}


def test_matching_set_changes_nothing():
    hosts = [
        Host(uuid="h2", remark="RU · XHTTP", inbound_uuid="i-xhttp"),
        Host(uuid="h3", remark="RU ← CF · XHTTP", inbound_uuid="i-xhttp", excluded=["sq"]),
    ]
    _, changed = plan_squad_membership("sq", hosts, {"RU · XHTTP"})
    assert changed == {}
