from taintgate.state import SessionState, StateStore


def test_state_roundtrip(tmp_path):
    s = StateStore(tmp_path)
    st = SessionState("a", tainted=True, taint_sources=["WebFetch"], untrusted_entities={"x@y.com"})
    s.save(st)
    assert s.load("a") == st


def test_sessions_isolated(tmp_path):
    s = StateStore(tmp_path)
    s.save(SessionState("a", tainted=True))
    assert s.load("b").tainted is False


def test_corrupt_state_file_gives_fresh_state(tmp_path):
    s = StateStore(tmp_path)
    s.save(SessionState("a", tainted=True))
    (tmp_path / "a.json").write_text("{not json")
    assert s.load("a").tainted is False


def test_session_id_path_traversal_is_sanitized(tmp_path):
    root = tmp_path / "root"
    s = StateStore(root)
    s.save(SessionState("../../x", tainted=True))
    assert not (tmp_path / "x.json").exists()
    assert all(p.parent == root for p in root.glob("*.json"))
    assert s.load("../../x").tainted is True
