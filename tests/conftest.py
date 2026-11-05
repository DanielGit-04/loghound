"""Utilidades compartidas por los tests."""

import json
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE_LOGS = os.path.join(ROOT, "sample_data", "sample_logs.json")
RULES_PATH = os.path.join(ROOT, "rules", "detection_rules.yaml")


@pytest.fixture
def write_logs(tmp_path):
    """Escribe una lista de eventos en un JSON temporal y devuelve su ruta."""
    def _write(events, name="logs.json"):
        path = tmp_path / name
        path.write_text(json.dumps(events), encoding="utf-8")
        return str(path)
    return _write


@pytest.fixture
def rules():
    from loghound.rules_engine import load_rules
    return {r["id"]: r for r in load_rules(RULES_PATH)}


def make_events(parser_module, events, tmp_path):
    path = tmp_path / "e.json"
    path.write_text(json.dumps(events), encoding="utf-8")
    return parser_module.load_logs(str(path))
