"""
Motor de reglas de detección.

Tipos de regla
--------------
- ``simple``: dispara con un único evento que cumple las condiciones.
- ``threshold``: agrupa los eventos que cumplen las condiciones por un campo
  (``group_by``) y dispara si en una ventana de ``window_seconds`` se acumulan
  al menos ``threshold`` eventos para el mismo valor. Opcionalmente exige
  además ``distinct_threshold`` valores *distintos* de ``distinct_field``
  (por ejemplo, "logons en 3 equipos diferentes", no "4 logons al mismo equipo").

Condiciones (bloque ``match``)
------------------------------
Todas las condiciones de un bloque se combinan con AND. Las comparaciones de
texto no distinguen mayúsculas de minúsculas.

- ``event_id``: número o lista de números.
- ``field_equals``: ``{campo: valor}`` igualdad exacta.
- ``field_in``: ``{campo: [valores]}`` el valor está en la lista.
- ``field_contains``: ``{campo: [textos]}`` contiene alguno de los textos.
- ``field_endswith``: ``{campo: [sufijos]}`` termina con alguno.
- ``field_regex``: ``{campo: [patrones]}`` casa con alguno (regex).
- ``field_regex_all``: ``{campo: [patrones]}`` casa con todos (regex).
- ``exclude``: bloque (o lista de bloques) con las mismas condiciones. Si el
  evento cumple alguno, se descarta. Sirve para quitar falsos positivos.

Cada detección incluye: regla, técnica MITRE, severidad, recomendación,
entidad implicada, eventos de evidencia y timestamps de inicio/fin.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from functools import lru_cache
from typing import Any, Dict, List

import yaml

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RULE_TYPES = {"simple", "threshold"}
MATCH_KEYS = {
    "event_id",
    "field_equals",
    "field_in",
    "field_contains",
    "field_endswith",
    "field_regex",
    "field_regex_all",
    "exclude",
}
_FIELD_DICT_KEYS = ("field_equals", "field_in", "field_contains", "field_endswith", "field_regex", "field_regex_all")


class RuleError(Exception):
    """Una regla de detección no es válida."""


# --------------------------------------------------------------------------
# Carga y validación
# --------------------------------------------------------------------------

def _as_list(value: Any) -> list:
    return list(value) if isinstance(value, (list, tuple)) else [value]


@lru_cache(maxsize=None)
def _regex(pattern: str):
    return re.compile(pattern, re.IGNORECASE)


def _validate_match(match: Any, where: str, allow_exclude: bool = True) -> None:
    if not isinstance(match, dict) or not match:
        raise RuleError(f"{where}: el bloque de condiciones debe ser un diccionario no vacío.")

    unknown = set(match) - MATCH_KEYS
    if unknown:
        raise RuleError(f"{where}: condiciones desconocidas {sorted(unknown)}. Válidas: {sorted(MATCH_KEYS)}.")

    if "event_id" in match:
        try:
            [int(x) for x in _as_list(match["event_id"])]
        except (TypeError, ValueError):
            raise RuleError(f"{where}: event_id debe ser un número o una lista de números.")

    for key in _FIELD_DICT_KEYS:
        if key not in match:
            continue
        if not isinstance(match[key], dict):
            raise RuleError(f"{where}: '{key}' debe ser un diccionario {{campo: ...}}.")
        for field, values in match[key].items():
            if key in ("field_in", "field_contains", "field_endswith", "field_regex", "field_regex_all"):
                if not isinstance(values, list) or not values:
                    raise RuleError(f"{where}: '{key}.{field}' debe ser una lista no vacía.")
            if key in ("field_regex", "field_regex_all"):
                for pattern in values:
                    try:
                        _regex(str(pattern))
                    except re.error as e:
                        raise RuleError(f"{where}: regex inválida en '{key}.{field}' ({pattern!r}): {e}")

    if "exclude" in match:
        if not allow_exclude:
            raise RuleError(f"{where}: 'exclude' no se puede anidar dentro de otro 'exclude'.")
        for n, ex in enumerate(_as_list(match["exclude"])):
            _validate_match(ex, f"{where}.exclude[{n}]", allow_exclude=False)


def validate_rule(rule: Any) -> None:
    if not isinstance(rule, dict):
        raise RuleError("Cada regla debe ser un diccionario.")
    rid = rule.get("id", "?")

    for key in ("id", "name", "match"):
        if key not in rule:
            raise RuleError(f"Regla {rid}: falta el campo obligatorio '{key}'.")

    rtype = rule.get("type", "simple")
    if rtype not in RULE_TYPES:
        raise RuleError(f"Regla {rid}: tipo desconocido '{rtype}'. Válidos: {sorted(RULE_TYPES)}.")

    severity = rule.get("severity", "medium")
    if severity not in SEVERITY_ORDER:
        raise RuleError(f"Regla {rid}: severidad '{severity}' no válida. Válidas: {sorted(SEVERITY_ORDER)}.")

    _validate_match(rule["match"], f"Regla {rid}.match")

    if rtype == "threshold":
        if not rule.get("group_by"):
            raise RuleError(f"Regla {rid}: las reglas 'threshold' necesitan 'group_by'.")
        for key, default in (("window_seconds", 300), ("threshold", 5)):
            value = rule.get(key, default)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise RuleError(f"Regla {rid}: '{key}' debe ser un entero >= 1.")
        if "distinct_field" in rule:
            value = rule.get("distinct_threshold")
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise RuleError(f"Regla {rid}: con 'distinct_field' hay que indicar 'distinct_threshold' (entero >= 1).")


def load_rules(rules_path: str) -> List[Dict[str, Any]]:
    with open(rules_path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise RuleError(f"YAML inválido en {rules_path}: {e}") from e

    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleError("El fichero de reglas debe tener la forma 'rules: [ ... ]'.")

    rules = data["rules"]
    seen = set()
    for rule in rules:
        validate_rule(rule)
        if rule["id"] in seen:
            raise RuleError(f"ID de regla duplicado: {rule['id']}.")
        seen.add(rule["id"])
    return rules


# --------------------------------------------------------------------------
# Evaluación de condiciones
# --------------------------------------------------------------------------

def _text(event: Dict[str, Any], field: str):
    value = event.get(field)
    return None if value is None else str(value)


def _event_matches(event: Dict[str, Any], match: Dict[str, Any]) -> bool:
    if "event_id" in match:
        allowed = {int(x) for x in _as_list(match["event_id"])}
        if event.get("event_id") not in allowed:
            return False

    for field, expected in match.get("field_equals", {}).items():
        actual = _text(event, field)
        if actual is None or actual.lower() != str(expected).lower():
            return False

    for field, values in match.get("field_in", {}).items():
        actual = _text(event, field)
        if actual is None or actual.lower() not in {str(v).lower() for v in values}:
            return False

    for field, needles in match.get("field_contains", {}).items():
        actual = _text(event, field)
        if actual is None or not any(str(n).lower() in actual.lower() for n in needles):
            return False

    for field, suffixes in match.get("field_endswith", {}).items():
        actual = _text(event, field)
        if actual is None or not any(actual.lower().endswith(str(s).lower()) for s in suffixes):
            return False

    for field, patterns in match.get("field_regex", {}).items():
        actual = _text(event, field)
        if actual is None or not any(_regex(str(p)).search(actual) for p in patterns):
            return False

    for field, patterns in match.get("field_regex_all", {}).items():
        actual = _text(event, field)
        if actual is None or not all(_regex(str(p)).search(actual) for p in patterns):
            return False

    if "exclude" in match:
        for ex in _as_list(match["exclude"]):
            if _event_matches(event, ex):
                return False

    return True


# --------------------------------------------------------------------------
# Ejecución de reglas
# --------------------------------------------------------------------------

def _base_detection(rule: Dict[str, Any], entity: str, evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "rule_id": rule["id"],
        "name": rule["name"],
        "mitre": rule.get("mitre"),
        "severity": rule.get("severity", "medium"),
        "description": " ".join(str(rule.get("description", "")).split()),
        "recommendation": " ".join(str(rule.get("recommendation", "")).split()),
        "entity": entity,
        "start_time": evidence[0]["timestamp"],
        "end_time": evidence[-1]["timestamp"],
        "evidence": evidence,
    }


def _run_simple_rule(rule: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    detections = []
    for event in events:
        if _event_matches(event, rule["match"]):
            entity = event.get("user") or event.get("computer") or "desconocido"
            detections.append(_base_detection(rule, str(entity), [event]))
    return detections


def _run_threshold_rule(rule: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    group_by = rule["group_by"]
    window = timedelta(seconds=rule.get("window_seconds", 300))
    threshold = rule.get("threshold", 5)
    distinct_field = rule.get("distinct_field")
    distinct_threshold = rule.get("distinct_threshold", 1)

    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if not _event_matches(e, rule["match"]):
            continue
        key = e.get(group_by)
        if key is None or str(key).strip() == "":
            continue  # sin valor de agrupación no se puede atribuir a una entidad
        buckets[str(key)].append(e)

    detections = []
    for key, group_events in buckets.items():
        group_events.sort(key=lambda e: e["_dt"])
        n = len(group_events)
        i = 0
        while i < n:
            start = group_events[i]["_dt"]
            j = i + 1
            while j < n and group_events[j]["_dt"] - start <= window:
                j += 1
            window_events = group_events[i:j]

            distinct_values = None
            ok = len(window_events) >= threshold
            if ok and distinct_field:
                distinct_values = sorted({
                    str(e.get(distinct_field)) for e in window_events if e.get(distinct_field) not in (None, "")
                })
                ok = len(distinct_values) >= distinct_threshold

            if ok:
                detection = _base_detection(rule, key, window_events)
                if distinct_values is not None:
                    detection["distinct_field"] = distinct_field
                    detection["distinct_values"] = distinct_values
                detections.append(detection)
                i = j  # evita solapamientos: saltamos al final de la ventana disparada
            else:
                i += 1

    return detections


def run_rules(rules: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_detections: List[Dict[str, Any]] = []
    for rule in rules:
        validate_rule(rule)
        if rule.get("type", "simple") == "simple":
            all_detections.extend(_run_simple_rule(rule, events))
        else:
            all_detections.extend(_run_threshold_rule(rule, events))

    # Se ordena por la fecha real (UTC), no por el texto del timestamp, que puede venir en formatos distintos
    all_detections.sort(
        key=lambda d: (SEVERITY_ORDER.get(d["severity"], 9), d["evidence"][0]["_dt"], d["rule_id"])
    )
    return all_detections
