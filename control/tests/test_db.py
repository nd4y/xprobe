import threading

from control import db


def test_secret_is_stored_hashed():
    h = db.hash_secret("s3cret")
    assert "s3cret" not in h          # no cleartext secret in the database
    assert db.check_secret("s3cret", h)
    assert not db.check_secret("wrong", h)


def test_create_and_read_point():
    conn = db.connect(":memory:")
    db.create_point(conn, db.Point(name="yar", city="Yaroslavl"), "sec")
    p = db.get_point(conn, "yar")
    assert p is not None and p.city == "Yaroslavl" and p.version == 1
    assert db.check_secret("sec", db.get_secret_hash(conn, "yar"))


def test_edit_bumps_version():
    conn = db.connect(":memory:")
    db.create_point(conn, db.Point(name="yar"), "sec")
    v = db.update_point(conn, "yar", {"city": "Tolyatti", "modes": {"tcp": True}})
    assert v == 2
    assert db.get_point(conn, "yar").city == "Tolyatti"


def test_secret_rotation_bumps_version_too():
    # Otherwise a probe with the old secret would silently keep running on the
    # old document, never learning it was cut off.
    conn = db.connect(":memory:")
    db.create_point(conn, db.Point(name="yar"), "old")
    db.rotate_secret(conn, "yar", "new")
    p = db.get_point(conn, "yar")
    assert p.version == 2
    assert db.check_secret("new", db.get_secret_hash(conn, "yar"))
    assert not db.check_secret("old", db.get_secret_hash(conn, "yar"))


def test_reads_and_writes_survive_concurrent_threads():
    """The connection is shared and handlers run in a thread pool.

    Caught in production: every config poll writes `last_seen_at`, so reads
    and writes now collide constantly, and sqlite3 answers a racing pair with
    `InterfaceError: bad parameter or other API misuse` — on a plain SELECT,
    which reads like a broken query rather than a threading problem.
    """
    conn = db.connect(":memory:")
    for n in range(4):
        db.create_point(conn, db.Point(name=f"p{n}"), "sec")
    errors: list[Exception] = []
    stop = threading.Event()

    def hammer(fn):
        def run():
            while not stop.is_set():
                try:
                    fn()
                except Exception as exc:  # noqa: BLE001 — the point of the test
                    errors.append(exc)
                    return
        return run

    workers = [
        threading.Thread(target=hammer(lambda: db.get_secret_hash(conn, "p1"))),
        threading.Thread(target=hammer(lambda: db.list_points(conn))),
        threading.Thread(target=hammer(lambda: db.touch_point(conn, "p2"))),
        threading.Thread(target=hammer(lambda: db.touch_point(conn, "p3", metrics=True))),
    ]
    for w in workers:
        w.start()
    stop.wait(1.5)
    stop.set()
    for w in workers:
        w.join(timeout=10)
    assert not errors, f"concurrent access raised: {errors[0]!r}"


def test_unknown_field_is_not_written():
    conn = db.connect(":memory:")
    db.create_point(conn, db.Point(name="yar"), "sec")
    # secret_hash is not in EDITABLE — update_point must not overwrite it.
    db.update_point(conn, "yar", {"secret_hash": "forged"})
    assert db.check_secret("sec", db.get_secret_hash(conn, "yar"))
