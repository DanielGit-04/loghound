import json
import os

import pytest
from click.testing import CliRunner

from conftest import RULES_PATH, SAMPLE_LOGS
from loghound.cli import cli
from loghound.report import build_timeline, mitre_url


def run(args):
    return CliRunner().invoke(cli, args)


def analyze_args(out, *extra):
    return ["analyze", "--logs", SAMPLE_LOGS, "--rules", RULES_PATH, "--examiner", "Tester", "--case-id", "T-1",
            "--output", str(out), *extra]


def test_end_to_end_signed_flow(tmp_path):
    keys = tmp_path / "keys"
    assert run(["keygen", "--out-dir", str(keys)]).exit_code == 0
    out = tmp_path / "out" / "report.html"
    res = run(analyze_args(out, "--sign-key", str(keys / "examiner_private.pem")))
    assert res.exit_code == 0, res.output
    assert out.exists() and (tmp_path / "out" / "chain_of_custody.json").exists()

    ver = run(["verify", "--manifest", str(tmp_path / "out" / "chain_of_custody.json"),
               "--public-key", str(keys / "examiner_public.pem"),
               "--evidence-dir", os.path.dirname(SAMPLE_LOGS), "--require-signature"])
    assert ver.exit_code == 0, ver.output

    out.write_text(out.read_text() + "<!-- manipulado -->")
    ver = run(["verify", "--manifest", str(tmp_path / "out" / "chain_of_custody.json"),
               "--public-key", str(keys / "examiner_public.pem")])
    assert ver.exit_code == 1


def test_output_without_folder_works(tmp_path, monkeypatch):
    """Fallaba en v0.1 con --output report.html (sin carpeta)."""
    monkeypatch.chdir(tmp_path)
    res = run(analyze_args("report.html"))
    assert res.exit_code == 0, res.output
    assert (tmp_path / "report.html").exists() and (tmp_path / "chain_of_custody.json").exists()


def test_unsigned_run_warns(tmp_path):
    res = run(analyze_args(tmp_path / "r.html"))
    assert res.exit_code == 0 and "SIN firma" in res.output.replace("\n", " ")


def test_multiple_log_files(tmp_path):
    a = tmp_path / "a.json"
    a.write_text(json.dumps([{"timestamp": "2026-08-10T10:00:00Z", "event_id": 1102, "computer": "X", "user": "u"}]))
    out = tmp_path / "o" / "r.html"
    res = run(["analyze", "--logs", str(a), "--logs", SAMPLE_LOGS, "--rules", RULES_PATH,
               "--examiner", "T", "--case-id", "C", "--output", str(out)])
    assert res.exit_code == 0, res.output
    manifest = json.load(open(tmp_path / "o" / "chain_of_custody.json"))
    assert [e["filename"] for e in manifest["evidence"]] == ["a.json", "sample_logs.json", "detection_rules.yaml"]


def test_bad_logs_and_bad_rules_exit_cleanly(tmp_path):
    bad_logs = tmp_path / "bad.json"
    bad_logs.write_text('{"no": "lista"}')
    res = run(["analyze", "--logs", str(bad_logs), "--rules", RULES_PATH, "--examiner", "T", "--case-id", "C",
               "--output", str(tmp_path / "r.html")])
    assert res.exit_code == 1 and "Error al parsear" in res.output

    bad_rules = tmp_path / "bad.yaml"
    bad_rules.write_text("rules: [{id: A, name: x, type: magia, match: {event_id: 1}}]")
    res = run(["analyze", "--logs", SAMPLE_LOGS, "--rules", str(bad_rules), "--examiner", "T", "--case-id", "C",
               "--output", str(tmp_path / "r.html")])
    assert res.exit_code == 1 and "Error en las reglas" in res.output


def test_keygen_refuses_to_overwrite(tmp_path):
    assert run(["keygen", "--out-dir", str(tmp_path)]).exit_code == 0
    assert run(["keygen", "--out-dir", str(tmp_path)]).exit_code == 1


def test_version_flag():
    from loghound import __version__
    res = run(["--version"])
    assert res.exit_code == 0 and __version__ in res.output


# ---------------- Informe ----------------

def test_report_contents(tmp_path):
    out = tmp_path / "r.html"
    assert run(analyze_args(out)).exit_code == 0
    html = out.read_text(encoding="utf-8")
    assert "Línea de tiempo" in html and "Recomendación:" in html
    assert "https://attack.mitre.org/techniques/T1003/001/" in html
    assert "sample_logs.json" in html and "detection_rules.yaml" in html


def test_report_escapes_hostile_log_content(tmp_path):
    """Un log con HTML/JS no debe poder ejecutarse al abrir el informe."""
    payload = '<script>alert(1)</script>'
    logs = tmp_path / "h.json"
    logs.write_text(json.dumps([{"timestamp": "2026-08-10T10:00:00Z", "event_id": 1, "computer": payload,
                                 "user": payload, "command_line":
                                 f"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA {payload}"}]))
    out = tmp_path / "r.html"
    res = run(["analyze", "--logs", str(logs), "--rules", RULES_PATH, "--examiner", payload, "--case-id", "C",
               "--output", str(out)])
    assert res.exit_code == 0, res.output
    html = out.read_text(encoding="utf-8")
    assert "<script" not in html.lower()   # ni en el HTML ni dentro del JSON de evidencia
    assert "&lt;script&gt;" in html or "\\u003cscript\\u003e" in html


def test_timeline_is_chronological_and_deduplicated(tmp_path):
    from loghound.parser import load_logs
    from loghound.rules_engine import load_rules, run_rules
    dets = run_rules(load_rules(RULES_PATH), load_logs(SAMPLE_LOGS))
    tl = build_timeline(dets)
    assert tl == sorted(tl, key=lambda t: t["time"])
    assert len(tl) == sum(len(d["evidence"]) for d in dets)   # cada evento aparece una vez


def test_mitre_url():
    assert mitre_url("T1110") == "https://attack.mitre.org/techniques/T1110/"
    assert mitre_url("T1558.003") == "https://attack.mitre.org/techniques/T1558/003/"
    assert mitre_url('x"><script>') == "" and mitre_url(None) == ""
