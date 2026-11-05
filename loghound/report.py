"""
Generación del informe HTML a partir de las detecciones y del manifiesto de
cadena de custodia. Usa Jinja2 sobre ``templates/report_template.html``.

Seguridad: los logs analizados pueden contener texto hostil (por ejemplo, una
línea de comandos con ``<script>``). La plantilla usa autoescape y el JSON de
evidencia se serializa con ``tojson``, que escapa ``<``, ``>`` y ``&``, para
que el informe nunca ejecute contenido procedente de los logs.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from loghound import __version__

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_DETAIL_FIELDS = ("command_line", "target_image", "target_user", "status", "process")


def mitre_url(technique: Any) -> str:
    """Enlace a la técnica en attack.mitre.org (solo si el ID tiene el formato esperado)."""
    if not isinstance(technique, str) or not _MITRE_RE.match(technique):
        return ""
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def _clean_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Quita los campos internos (``_dt``...) para poder serializar a JSON; conserva el fichero de origen."""
    cleaned = {k: v for k, v in event.items() if not k.startswith("_")}
    if "_source" in event:
        cleaned["source_file"] = event["_source"]
    return cleaned


def build_timeline(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Línea de tiempo cronológica con todos los eventos de evidencia, sin duplicados."""
    by_identity: Dict[int, Dict[str, Any]] = {}
    for d in detections:
        for ev in d["evidence"]:
            item = by_identity.setdefault(id(ev), {"event": ev, "rules": []})
            if d["rule_id"] not in item["rules"]:
                item["rules"].append(d["rule_id"])

    timeline = []
    for item in sorted(by_identity.values(), key=lambda i: i["event"]["_dt"]):
        ev = item["event"]
        detail = next((str(ev[f]) for f in _DETAIL_FIELDS if ev.get(f)), "")
        timeline.append({
            "time": ev.get("timestamp", ""),
            "computer": ev.get("computer", ""),
            "user": ev.get("user", ""),
            "event_id": ev.get("event_id", ""),
            "rules": item["rules"],
            "detail": detail if len(detail) <= 140 else detail[:137] + "...",
        })
    return timeline


def render_report(
    case_id: str,
    examiner: str,
    generated_at: str,
    detections: List[Dict[str, Any]],
    manifest: Dict[str, Any],
    total_events: int,
    output_path: str,
) -> None:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report_template.html")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in detections:
        sev = d.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    timeline = build_timeline(detections)

    # Copias limpias (sin campos internos) para no tocar los objetos originales
    shown = [
        {**d, "mitre_url": mitre_url(d.get("mitre")), "evidence": [_clean_event(ev) for ev in d["evidence"]]}
        for d in detections
    ]

    html = template.render(
        case_id=case_id,
        examiner=examiner,
        generated_at=generated_at,
        version=__version__,
        detections=shown,
        timeline=timeline,
        manifest=manifest,
        total_events=total_events,
        total_detections=len(detections),
        severity_counts=severity_counts,
    )

    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
