"""
Parser de logs.

Carga logs en formato JSON (una lista de objetos) o JSON Lines (un objeto por
línea) y los normaliza a un esquema interno común para que el motor de reglas
no tenga que preocuparse del origen exacto (Security log vs Sysmon).

Normalización que se aplica a cada evento:
- ``_dt``: fecha/hora como ``datetime`` **con zona horaria, siempre en UTC**.
  Si el log trae un offset (``+02:00``) se convierte a UTC. Si no trae ninguna
  zona (ni ``Z`` ni offset) se asume UTC.
- ``event_id``: entero.
- ``_source``: nombre del fichero del que procede el evento.

Si en el futuro se quiere soportar .evtx directamente, este es el único módulo
que habría que tocar: añadir una función ``load_evtx()`` que devuelva la misma
estructura que ``load_logs()``.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

REQUIRED_FIELDS = ["timestamp", "event_id"]

_FRACTION_RE = re.compile(r"\.(\d+)")


class LogParseError(Exception):
    """El fichero de logs no tiene un formato válido."""


def parse_timestamp(ts: Any) -> datetime:
    """
    Convierte un timestamp ISO 8601 a ``datetime`` en UTC.

    Acepta sufijo ``Z``, offsets (``+02:00``), ausencia de zona (se asume UTC)
    y fracciones de segundo de cualquier longitud (Windows exporta 7 dígitos).
    """
    if not isinstance(ts, str) or not ts.strip():
        raise ValueError(f"timestamp no válido: {ts!r}")

    text = ts.strip()
    if text[-1] in ("Z", "z"):
        text = text[:-1] + "+00:00"

    # Normaliza la fracción de segundo a exactamente 6 dígitos: las versiones
    # antiguas de Python (3.9/3.10) solo aceptan 3 o 6.
    text = _FRACTION_RE.sub(lambda m: "." + m.group(1).ljust(6, "0")[:6], text, count=1)

    dt = datetime.fromisoformat(text)  # puede lanzar ValueError
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _read_raw_events(filepath: str) -> List[Any]:
    with open(filepath, "r", encoding="utf-8-sig") as f:
        text = f.read()

    stripped = text.lstrip()
    if not stripped:
        return []

    if stripped.startswith("["):
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as e:
            raise LogParseError(f"JSON inválido en {os.path.basename(filepath)}: {e}") from e
        if not isinstance(raw, list):
            raise LogParseError("El fichero de logs debe contener una lista de eventos JSON.")
        return raw

    # JSON Lines: un objeto JSON por línea
    events = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise LogParseError(
                f"Línea {lineno} de {os.path.basename(filepath)} no es JSON válido: {e}"
            ) from e
    return events


def load_logs(filepath: str) -> List[Dict[str, Any]]:
    """Carga un fichero JSON / JSON Lines y devuelve los eventos normalizados y ordenados."""
    raw = _read_raw_events(filepath)
    source = os.path.basename(filepath)

    normalized = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise LogParseError(f"Evento en posición {i} no es un objeto JSON.")

        for field in REQUIRED_FIELDS:
            if field not in entry:
                raise LogParseError(f"Evento en posición {i} no tiene el campo obligatorio '{field}'.")

        record = dict(entry)  # copia: no tocamos el original
        try:
            record["_dt"] = parse_timestamp(record["timestamp"])
        except ValueError as e:
            raise LogParseError(f"Evento en posición {i}: {e}") from e

        try:
            record["event_id"] = int(record["event_id"])
        except (TypeError, ValueError) as e:
            raise LogParseError(
                f"Evento en posición {i}: event_id no es un número ({record['event_id']!r})."
            ) from e

        record["_source"] = source
        normalized.append(record)

    # Orden cronológico: importante para la ventana temporal del motor de reglas
    normalized.sort(key=lambda r: r["_dt"])
    return normalized


def load_many(filepaths: List[str]) -> List[Dict[str, Any]]:
    """Carga varios ficheros y devuelve todos los eventos fusionados en orden cronológico."""
    events: List[Dict[str, Any]] = []
    for path in filepaths:
        events.extend(load_logs(path))
    events.sort(key=lambda r: r["_dt"])
    return events


# Alias de compatibilidad con la versión 0.1
load_json_logs = load_logs
