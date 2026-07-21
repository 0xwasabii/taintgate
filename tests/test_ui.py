import json

from taintgate import ui
from taintgate.cli import main


def make_results(d):
    rec = [{"kind": "attack", "defense": "none", "task": "t", "goal": "g", "attack_success": True,
            "task_success_attacked": True, "blocked_calls": 0, "rounds_used": 1},
           {"kind": "clean", "defense": "none", "task": "t", "task_success": True}]
    (d / "results-static.json").write_text(json.dumps(rec))
    return rec


def test_viewer_embeds_data_and_leaves_no_placeholder(tmp_path):
    make_results(tmp_path)
    out = ui.build_viewer(tmp_path / "v.html", tmp_path)
    html = out.read_text(encoding="utf-8")
    assert "/*__DATA__*/null" not in html and '"attack_success": true' in html
    assert json.loads(html.split('type="application/json">')[1].split("</script>")[0])["policy"]


def test_script_close_tag_in_data_cannot_break_page(tmp_path):
    rec = make_results(tmp_path)
    rec[0]["goal"] = "</script><script>alert(1)</script>"
    (tmp_path / "results-static.json").write_text(json.dumps(rec))
    html = ui.build_viewer(tmp_path / "v.html", tmp_path).read_text(encoding="utf-8")
    assert html.count("</script>") == 2  # data block + app block only


def test_audit_and_missing_files_are_optional(tmp_path):
    audit = tmp_path / "a.jsonl"
    audit.write_text('{"ts": 1, "session": "s", "tool": "Bash", "decision": "ask", "reason": "r", "rule": "Bash"}\nnot json\n')
    data = ui.build_data(tmp_path, audit, None)
    assert len(data["audit"]) == 1 and data["results"]["adaptive"] == []


def test_cli_ui_writes_file(tmp_path):
    make_results(tmp_path)
    assert main(["ui", "--results", str(tmp_path), "--out", str(tmp_path / "v.html"), "--audit", str(tmp_path / "none.jsonl")]) == 0
    assert (tmp_path / "v.html").exists()
