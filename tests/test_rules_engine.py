import copy

import pytest

from conftest import RULES_PATH, SAMPLE_LOGS
from loghound.parser import load_logs
from loghound.rules_engine import (
    RuleError, _event_matches, load_rules, run_rules, validate_rule,
)


@pytest.fixture(scope="module")
def sample_detections():
    return run_rules(load_rules(RULES_PATH), load_logs(SAMPLE_LOGS))


def by_rule(detections, rid):
    return [d for d in detections if d["rule_id"] == rid]


# ---------------- Datos de ejemplo: aciertos y ausencia de falsos positivos ----------------

def test_each_attack_in_sample_is_detected_exactly_once(sample_detections):
    counts = {rid: len(by_rule(sample_detections, rid)) for rid in ("R001", "R002", "R003", "R004", "R005", "R006")}
    assert counts == {"R001": 1, "R002": 1, "R003": 1, "R004": 1, "R005": 1, "R006": 1}


def test_benign_noise_in_sample_does_not_alert(sample_detections):
    """El ejemplo incluye actividad legítima parecida a un ataque; no debe disparar nada."""
    evidence_ips_users = {(d["rule_id"], d["entity"]) for d in sample_detections}
    assert ("R001", "legacyapp") not in evidence_ips_users      # RC4 siempre al mismo servicio
    assert ("R005", "10.0.0.9") not in evidence_ips_users       # backups a un único equipo
    assert ("R002", "10.0.0.31") not in evidence_ips_users      # solo 3 fallos
    r003 = by_rule(sample_detections, "R003")[0]
    assert "-Encoding" not in r003["evidence"][0]["command_line"]
    r004 = by_rule(sample_detections, "R004")[0]
    assert r004["evidence"][0]["source_image"].endswith("procdump.exe")


def test_detection_metadata(sample_detections):
    d = by_rule(sample_detections, "R001")[0]
    assert d["mitre"] == "T1558.003"
    assert d["entity"] == "attacker_svc"
    assert d["distinct_field"] == "target_user" and len(d["distinct_values"]) == 5
    assert d["recommendation"]
    assert by_rule(sample_detections, "R004")[0]["severity"] == "critical"


def test_detections_sorted_by_severity(sample_detections):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranks = [order[d["severity"]] for d in sample_detections]
    assert ranks == sorted(ranks)


# ---------------- Condiciones sueltas ----------------

R003 = {"event_id": 1, "field_regex_all": {"command_line": [
    r'(?:^|[\\/\s"\'])(?:powershell|pwsh)(?:\.exe)?(?:["\'\s]|$)',
    r'\s-(?:e|ec|en\w*)\s+[A-Za-z0-9+/=]{16,}|frombase64string|\s-nop\w*\s.*-w\w*\s+hidden',
]}}


@pytest.mark.parametrize("cmd,expected", [
    ("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", True),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", True),
    ("pwsh -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", True),
    ("powershell -c [Convert]::FromBase64String('aGVsbG8=')", True),
    ("powershell.exe -NoProfile -WindowStyle Hidden -File x.ps1", True),
    ("powershell.exe -Command Get-Content a | Out-File b -Encoding utf8", False),   # falso positivo del v0.1
    ("cmd.exe /c echo hola -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", False),  # no es PowerShell
    ("powershell.exe -File backup.ps1", False),
])
def test_r003_patterns(cmd, expected):
    assert _event_matches({"event_id": 1, "command_line": cmd}, R003) is expected


def test_r004_uses_full_path_and_access_mask(rules):
    m = rules["R004"]["match"]
    base = {"event_id": 10, "target_image": "C:\\Windows\\System32\\lsass.exe",
            "source_image": "C:\\Temp\\x.exe", "granted_access": "0x1FFFFF"}
    assert _event_matches(base, m)                                           # ruta completa + máscara en mayúsculas
    assert _event_matches({**base, "target_image": "lsass.exe"}, m)           # nombre suelto
    assert not _event_matches({**base, "target_image": "C:\\x\\notlsass.exe"}, m)
    assert not _event_matches({**base, "granted_access": "0x1000"}, m)        # permisos mínimos
    assert not _event_matches({**base, "source_image": "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe"}, m)
    assert not _event_matches({k: v for k, v in base.items() if k != "granted_access"}, m)


def test_operators():
    ev = {"event_id": 4624, "user": "Admin$", "ip": "10.0.0.1", "cmd": "Hello World"}
    assert _event_matches(ev, {"event_id": [4624, 4625]})
    assert not _event_matches(ev, {"event_id": [1, 2]})
    assert _event_matches(ev, {"field_endswith": {"user": ["$"]}})
    assert _event_matches(ev, {"field_in": {"ip": ["10.0.0.1", "10.0.0.2"]}})
    assert _event_matches(ev, {"field_contains": {"cmd": ["WORLD"]}})          # sin distinguir mayúsculas
    assert not _event_matches(ev, {"field_equals": {"missing_field": "x"}})
    assert not _event_matches(ev, {"field_equals": {"user": "admin$"}, "exclude": {"field_endswith": {"user": ["$"]}}})
    assert not _event_matches(ev, {"event_id": 4624, "exclude": [{"field_equals": {"ip": "x"}}, {"field_equals": {"ip": "10.0.0.1"}}]})


# ---------------- Reglas threshold ----------------

def _events(parser_events, tmp_path):
    from loghound.parser import load_logs
    import json
    p = tmp_path / "ev.json"
    p.write_text(json.dumps(parser_events))
    return load_logs(str(p))


def test_threshold_requires_events_inside_window(rules, tmp_path):
    # 8 fallos, pero espaciados 60 s -> nunca 8 dentro de 120 s
    evs = [{"timestamp": f"2026-08-10T09:{i:02d}:00Z", "event_id": 4625, "source_ip": "1.2.3.4"} for i in range(8)]
    assert run_rules([rules["R002"]], _events(evs, tmp_path)) == []
    # 8 fallos en 35 s -> alerta
    evs = [{"timestamp": f"2026-08-10T09:00:{i * 5:02d}Z", "event_id": 4625, "source_ip": "1.2.3.4"} for i in range(8)]
    assert len(run_rules([rules["R002"]], _events(evs, tmp_path))) == 1


def test_threshold_window_boundary_is_inclusive(rules, tmp_path):
    evs = [{"timestamp": "2026-08-10T09:00:00Z", "event_id": 4625, "source_ip": "9.9.9.9"}]
    evs += [{"timestamp": "2026-08-10T09:00:10Z", "event_id": 4625, "source_ip": "9.9.9.9"} for _ in range(6)]
    evs += [{"timestamp": "2026-08-10T09:02:00Z", "event_id": 4625, "source_ip": "9.9.9.9"}]  # justo a 120 s
    assert len(run_rules([rules["R002"]], _events(evs, tmp_path))) == 1


def test_threshold_groups_are_independent_and_missing_group_is_ignored(rules, tmp_path):
    evs = [{"timestamp": f"2026-08-10T09:00:{i:02d}Z", "event_id": 4625, "source_ip": f"1.1.1.{i % 2}"} for i in range(12)]
    assert run_rules([rules["R002"]], _events(evs, tmp_path)) == []   # 6 por IP < 8
    evs = [{"timestamp": f"2026-08-10T09:00:{i:02d}Z", "event_id": 4625} for i in range(12)]  # sin source_ip
    assert run_rules([rules["R002"]], _events(evs, tmp_path)) == []
    evs = [{"timestamp": f"2026-08-10T09:00:{i:02d}Z", "event_id": 4625, "source_ip": "-"} for i in range(12)]  # logon local
    assert run_rules([rules["R002"]], _events(evs, tmp_path)) == []


def test_r005_needs_distinct_computers(rules, tmp_path):
    mk = lambda i, c: {"timestamp": f"2026-08-10T10:0{i}:00Z", "event_id": 4624, "logon_type": 3,
                       "computer": c, "user": "u", "source_ip": "10.0.0.9"}
    same = [mk(i, "SRV1") for i in range(6)]
    assert run_rules([rules["R005"]], _events(same, tmp_path)) == []
    diff = [mk(i, f"SRV{i}") for i in range(5)]
    d = run_rules([rules["R005"]], _events(diff, tmp_path))
    assert len(d) == 1 and len(d[0]["distinct_values"]) == 5


def test_r005_ignores_machine_accounts_and_anonymous(rules, tmp_path):
    mk = lambda i, u: {"timestamp": f"2026-08-10T10:0{i}:00Z", "event_id": 4624, "logon_type": 3,
                       "computer": f"SRV{i}", "user": u, "source_ip": "10.0.0.9"}
    assert run_rules([rules["R005"]], _events([mk(i, "DC01$") for i in range(5)], tmp_path)) == []
    assert run_rules([rules["R005"]], _events([mk(i, "ANONYMOUS LOGON") for i in range(5)], tmp_path)) == []


def test_r001_ignores_machine_accounts(rules, tmp_path):
    mk = lambda i: {"timestamp": f"2026-08-10T10:00:{i:02d}Z", "event_id": 4769, "user": "u",
                    "target_user": f"SRV{i}$", "encryption_type": "0x17"}
    assert run_rules([rules["R001"]], _events([mk(i) for i in range(8)], tmp_path)) == []


def test_r006_log_cleared(rules, tmp_path):
    evs = [{"timestamp": "2026-08-10T10:00:00Z", "event_id": 1102, "user": "x"},
           {"timestamp": "2026-08-10T10:01:00Z", "event_id": 104, "user": "x"}]
    assert len(run_rules([rules["R006"]], _events(evs, tmp_path))) == 2


def test_overlapping_bursts_produce_separate_alerts(rules, tmp_path):
    mk = lambda h: [{"timestamp": f"2026-08-10T{h}:00:{i:02d}Z", "event_id": 4625, "source_ip": "5.5.5.5"} for i in range(8)]
    assert len(run_rules([rules["R002"]], _events(mk("09") + mk("15"), tmp_path))) == 2


# ---------------- Validación de reglas ----------------

def good_rule():
    return {"id": "X1", "name": "n", "type": "threshold", "group_by": "user", "match": {"event_id": 1}}


@pytest.mark.parametrize("mutate,message", [
    (lambda r: r.pop("id"), "id"),
    (lambda r: r.update(type="magia"), "tipo desconocido"),
    (lambda r: r.update(severity="enorme"), "severidad"),
    (lambda r: r.pop("group_by"), "group_by"),
    (lambda r: r.update(threshold=0), "threshold"),
    (lambda r: r.update(window_seconds="5"), "window_seconds"),
    (lambda r: r.update(distinct_field="x"), "distinct_threshold"),
    (lambda r: r.update(match={"event_id": "abc"}), "event_id"),
    (lambda r: r.update(match={"field_equal": {"a": 1}}), "desconocidas"),
    (lambda r: r.update(match={"field_regex": {"a": ["(sin cerrar"]}}), "regex inválida"),
    (lambda r: r.update(match={"field_in": {"a": "no-lista"}}), "lista"),
    (lambda r: r.update(match={"event_id": 1, "exclude": {}}), "no vacío"),
])
def test_invalid_rules_are_rejected(mutate, message):
    rule = copy.deepcopy(good_rule())
    mutate(rule)
    with pytest.raises(RuleError, match=message):
        validate_rule(rule)


def test_load_rules_errors(tmp_path):
    bad = tmp_path / "r.yaml"
    bad.write_text("rules: [ {id: A, name: x, match: {event_id: 1}}, {id: A, name: y, match: {event_id: 2}} ]")
    with pytest.raises(RuleError, match="duplicado"):
        load_rules(str(bad))
    bad.write_text("no: es una regla")
    with pytest.raises(RuleError, match="rules"):
        load_rules(str(bad))
    bad.write_text("rules: [unclosed")
    with pytest.raises(RuleError, match="YAML"):
        load_rules(str(bad))


def test_shipped_rules_are_valid_and_complete():
    ids = {r["id"] for r in load_rules(RULES_PATH)}
    assert ids == {"R001", "R002", "R003", "R004", "R005", "R006"}
    assert all(r.get("mitre") and r.get("recommendation") for r in load_rules(RULES_PATH))
