import base64
import json

import pytest

from loghound.hashing import (
    ChainOfCustody, canonical_bytes, generate_keypair, sha256_of_bytes, sha256_of_file, verify_manifest,
)


@pytest.fixture
def case(tmp_path):
    """Un caso completo: log + reglas + informe, con claves, manifiesto firmado."""
    (tmp_path / "evidence").mkdir()
    log = tmp_path / "evidence" / "log.json"
    log.write_text('[{"a": 1}]')
    rules = tmp_path / "evidence" / "rules.yaml"
    rules.write_text("rules: []")
    out = tmp_path / "out"
    out.mkdir()
    report = out / "report.html"
    report.write_text("<html>informe</html>")
    priv, pub = generate_keypair(str(tmp_path / "keys"), "ex")

    coc = ChainOfCustody("CASE-1", "Examinador")
    coc.add_evidence(str(log))
    coc.add_evidence(str(rules), role="rules")
    coc.add_artifact(str(report))
    manifest_path = str(out / "chain_of_custody.json")
    coc.finalize(manifest_path, private_key_path=priv)
    return {"dir": tmp_path, "log": log, "report": report, "manifest": manifest_path, "priv": priv, "pub": pub,
            "evidence_dir": str(tmp_path / "evidence"), "out": out}


def statuses(report):
    return {c.name.split(":")[0]: c.status for c in report.checks}


def rewrite_manifest(path, mutate, rehash=False):
    m = json.load(open(path))
    mutate(m)
    if rehash:  # el atacante recalcula el hash del manifiesto tras modificarlo
        body = {k: v for k, v in m.items() if k != "integrity"}
        m["integrity"]["manifest_sha256"] = sha256_of_bytes(canonical_bytes(body))
    json.dump(m, open(path, "w"))


def test_sha256_helpers(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    assert sha256_of_file(str(p)) == sha256_of_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_manifest_content_has_no_absolute_paths(case):
    m = json.load(open(case["manifest"]))
    assert m["schema_version"] == 2
    assert {e["filename"] for e in m["evidence"]} == {"log.json", "rules.yaml"}
    assert [a["filename"] for a in m["artifacts"]] == ["report.html"]
    assert str(case["dir"]) not in json.dumps(m)
    assert all("path" not in e for e in m["evidence"])


def test_valid_signed_manifest_passes_with_trusted_key(case):
    r = verify_manifest(case["manifest"], public_key_path=case["pub"], evidence_dir=case["evidence_dir"], require_signature=True)
    assert r.ok
    s = statuses(r)
    assert s["Hash del manifiesto"] == s["Firma digital"] == s["Informe"] == "ok"
    assert [c.status for c in r.checks if c.name.startswith("Evidencia")] == ["ok", "ok"]


def test_without_trusted_key_signature_only_warns(case):
    r = verify_manifest(case["manifest"])
    assert r.ok and statuses(r)["Firma digital"] == "warn"


def test_tampering_without_rehash_is_detected(case):
    rewrite_manifest(case["manifest"], lambda m: m.update(examiner="Otro"))
    r = verify_manifest(case["manifest"], public_key_path=case["pub"])
    assert not r.ok and statuses(r)["Hash del manifiesto"] == "fail"


def test_forgery_with_recalculated_hash_is_caught_by_signature(case):
    """El fallo de la v0.1: cambiar el contenido y recalcular el hash pasaba la verificación."""
    rewrite_manifest(case["manifest"], lambda m: m.update(examiner="Otro"), rehash=True)
    r = verify_manifest(case["manifest"], public_key_path=case["pub"])
    s = statuses(r)
    assert s["Hash del manifiesto"] == "ok" and s["Firma digital"] == "fail"
    assert not r.ok


def test_forgery_re_signed_with_attacker_key_is_caught_by_trusted_key(case, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    atk = ed25519.Ed25519PrivateKey.generate()
    raw_pub = atk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def forge(m):
        m["examiner"] = "Otro"
        body = {k: v for k, v in m.items() if k != "integrity"}
        data = canonical_bytes(body)
        m["integrity"] = {"manifest_sha256": sha256_of_bytes(data), "signature": {
            "algorithm": "ed25519", "public_key": base64.b64encode(raw_pub).decode(),
            "value": base64.b64encode(atk.sign(data)).decode()}}
    rewrite_manifest(case["manifest"], forge)

    assert verify_manifest(case["manifest"]).ok                      # sin clave de confianza solo avisa...
    r = verify_manifest(case["manifest"], public_key_path=case["pub"])  # ...con la clave de confianza falla
    assert not r.ok and statuses(r)["Firma digital"] == "fail"


def test_modified_report_is_detected(case):
    case["report"].write_text("<html>informe MANIPULADO</html>")
    r = verify_manifest(case["manifest"], public_key_path=case["pub"])
    assert not r.ok and statuses(r)["Informe"] == "fail"


def test_modified_evidence_is_detected(case):
    case["log"].write_text('[{"a": 2}]')
    r = verify_manifest(case["manifest"], public_key_path=case["pub"], evidence_dir=case["evidence_dir"])
    assert not r.ok
    assert any(c.status == "fail" and c.name == "Evidencia: log.json" for c in r.checks)


def test_missing_files_are_skipped_not_failed(case):
    case["report"].unlink()
    r = verify_manifest(case["manifest"], public_key_path=case["pub"])
    assert r.ok and statuses(r)["Informe"] == "skip"


def test_unsigned_manifest(tmp_path):
    f = tmp_path / "l.json"
    f.write_text("[]")
    coc = ChainOfCustody("C", "E")
    coc.add_evidence(str(f))
    path = str(tmp_path / "m.json")
    coc.finalize(path)
    assert verify_manifest(path).ok
    assert statuses(verify_manifest(path))["Firma digital"] == "warn"
    r = verify_manifest(path, require_signature=True)
    assert not r.ok


def test_garbage_and_wrong_version_manifests(tmp_path):
    p = tmp_path / "m.json"
    p.write_text("no soy json")
    assert not verify_manifest(str(p)).ok
    p.write_text(json.dumps({"self_hash": "x", "case_id": "viejo"}))   # formato de la v0.1
    r = verify_manifest(str(p))
    assert not r.ok and r.checks[-1].name == "Formato"


def test_keygen_does_not_overwrite_and_private_key_is_protected(tmp_path):
    priv, pub = generate_keypair(str(tmp_path), "k")
    with pytest.raises(FileExistsError):
        generate_keypair(str(tmp_path), "k")
    import os, stat
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(priv).st_mode) == 0o600


def test_missing_evidence_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ChainOfCustody("C", "E").add_evidence(str(tmp_path / "no_existe.json"))
