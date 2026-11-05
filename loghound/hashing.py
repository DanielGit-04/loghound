"""
Cadena de custodia.

Qué hace este módulo
--------------------
- Calcula el SHA-256 de cada fichero de evidencia (logs, reglas) y del informe.
- Registra quién, cuándo y qué se hizo (log de acciones).
- Genera un manifiesto (``chain_of_custody.json``) con un hash de todo su
  contenido y, opcionalmente, una **firma digital Ed25519**.
- Permite verificar el manifiesto, el informe y (si se aportan) las evidencias.

Qué garantiza cada capa (importante para no sobrevender la herramienta)
-----------------------------------------------------------------------
1. Hash del manifiesto (``manifest_sha256``): detecta cambios *accidentales*.
   Cualquiera que modifique el manifiesto puede recalcular el hash, así que
   por sí solo NO prueba que nadie lo haya manipulado a propósito.
2. Firma Ed25519: solo quien tiene la clave privada puede producirla. Si el
   verificador dispone de la clave pública *de confianza* del examinador
   (obtenida por un canal independiente), una firma válida demuestra que el
   manifiesto lo generó esa persona y que no se ha modificado desde entonces.
3. Hash del informe y de las evidencias dentro del manifiesto firmado: si el
   informe o un log cambian, ``verify`` lo detecta.

Estructura del manifiesto (schema_version 2)
--------------------------------------------
    {
      "schema_version": 2, "tool": "LogHound", "tool_version": "...",
      "case_id": "...", "examiner": "...", "created_at": "...",
      "evidence":  [ {filename, role, sha256, size_bytes, hashed_at}, ... ],
      "artifacts": [ {filename, role, sha256, size_bytes, hashed_at}, ... ],
      "actions":   [ {timestamp, description}, ... ],
      "integrity": { "manifest_sha256": "...", "signature": {...} | null }
    }

El hash y la firma se calculan sobre el JSON canónico (claves ordenadas,
sin espacios) de todo el manifiesto *excepto* el bloque ``integrity``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from loghound import __version__

SCHEMA_VERSION = 2


# --------------------------------------------------------------------------
# Hashes y utilidades
# --------------------------------------------------------------------------

def sha256_of_file(filepath: str) -> str:
    """SHA-256 de un fichero, leído en bloques (apto para ficheros grandes)."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_bytes(body: Dict[str, Any]) -> bytes:
    """Serialización canónica (siempre idéntica para el mismo contenido)."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------
# Claves Ed25519
# --------------------------------------------------------------------------

def generate_keypair(out_dir: str, name: str = "examiner") -> tuple:
    """
    Genera un par de claves Ed25519 y las guarda como ``<name>_private.pem`` y
    ``<name>_public.pem``. Devuelve las dos rutas.

    La clave PRIVADA no debe compartirse ni subirse a ningún repositorio.
    """
    os.makedirs(out_dir, exist_ok=True)
    private_path = os.path.join(out_dir, f"{name}_private.pem")
    public_path = os.path.join(out_dir, f"{name}_public.pem")
    for path in (private_path, public_path):
        if os.path.exists(path):
            raise FileExistsError(f"Ya existe {path}; no se sobrescribe para no perder una clave.")

    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # La clave privada se crea con permisos 600 (solo el propietario puede leerla)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)
    return private_path, public_path


def _load_private_key(path: str) -> ed25519.Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("La clave privada no es de tipo Ed25519.")
    return key


def _load_public_key(path: str) -> ed25519.Ed25519PublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("La clave pública no es de tipo Ed25519.")
    return key


def _raw_public_bytes(key: ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def public_key_fingerprint(raw_public: bytes) -> str:
    """Huella corta de una clave pública (SHA-256, 16 primeros hex) para compararla a simple vista."""
    return sha256_of_bytes(raw_public)[:16]


# --------------------------------------------------------------------------
# Construcción del manifiesto
# --------------------------------------------------------------------------

def _file_entry(filepath: str, role: str) -> Dict[str, Any]:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"No se encuentra el fichero: {filepath}")
    return {
        "filename": os.path.basename(filepath),  # solo el nombre: no se filtran rutas del equipo del examinador
        "role": role,
        "sha256": sha256_of_file(filepath),
        "size_bytes": os.path.getsize(filepath),
        "hashed_at": utc_now_iso(),
    }


class ChainOfCustody:
    """Construye el registro de cadena de custodia de un caso."""

    def __init__(self, case_id: str, examiner: str):
        self.case_id = case_id
        self.examiner = examiner
        self.created_at = utc_now_iso()
        self.evidence: List[Dict[str, Any]] = []
        self.artifacts: List[Dict[str, Any]] = []
        self.actions: List[Dict[str, Any]] = []

    def add_evidence(self, filepath: str, role: str = "log") -> Dict[str, Any]:
        """Registra un fichero de entrada (log o reglas) con su hash."""
        entry = _file_entry(filepath, role)
        self.evidence.append(entry)
        self.log_action(f"Evidencia registrada ({role}): {entry['filename']} (sha256={entry['sha256'][:12]}...)")
        return entry

    def add_artifact(self, filepath: str, role: str = "report") -> Dict[str, Any]:
        """Registra un fichero generado por la herramienta (el informe) con su hash."""
        entry = _file_entry(filepath, role)
        self.artifacts.append(entry)
        self.log_action(f"Artefacto generado ({role}): {entry['filename']} (sha256={entry['sha256'][:12]}...)")
        return entry

    def log_action(self, description: str) -> None:
        self.actions.append({"timestamp": utc_now_iso(), "description": description})

    def body(self) -> Dict[str, Any]:
        """Contenido del manifiesto sin el bloque de integridad."""
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "LogHound",
            "tool_version": __version__,
            "case_id": self.case_id,
            "examiner": self.examiner,
            "created_at": self.created_at,
            "evidence": self.evidence,
            "artifacts": self.artifacts,
            "actions": self.actions,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Manifiesto provisional (sin hash ni firma), útil para mostrarlo en el informe."""
        return self.body()

    def finalize(self, output_path: str, private_key_path: Optional[str] = None) -> Dict[str, Any]:
        """Calcula hash (y firma, si se da una clave) y escribe el manifiesto definitivo."""
        self.log_action("Manifiesto de cadena de custodia finalizado" + (" y firmado." if private_key_path else " (SIN firma)."))
        body = self.body()
        data = canonical_bytes(body)

        signature = None
        if private_key_path:
            private_key = _load_private_key(private_key_path)
            raw_public = _raw_public_bytes(private_key.public_key())
            signature = {
                "algorithm": "ed25519",
                "public_key": base64.b64encode(raw_public).decode("ascii"),
                "public_key_fingerprint": public_key_fingerprint(raw_public),
                "value": base64.b64encode(private_key.sign(data)).decode("ascii"),
            }

        manifest = dict(body)
        manifest["integrity"] = {"manifest_sha256": sha256_of_bytes(data), "signature": signature}

        out_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        return manifest


# --------------------------------------------------------------------------
# Verificación
# --------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    status: str  # "ok" | "fail" | "warn" | "skip"
    detail: str = ""


@dataclass
class VerifyReport:
    checks: List[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(name, status, detail))

    @property
    def ok(self) -> bool:
        return not any(c.status == "fail" for c in self.checks)


def _verify_files(report: VerifyReport, entries: List[Dict[str, Any]], directory: Optional[str], label: str) -> None:
    for entry in entries:
        name = f"{label}: {entry.get('filename')}"
        if directory is None:
            report.add(name, "skip", "no comprobado (indica la carpeta con --evidence-dir)")
            continue
        path = os.path.join(directory, os.path.basename(str(entry.get("filename", ""))))
        if not os.path.isfile(path):
            report.add(name, "skip", f"no se encuentra en {directory}")
            continue
        if sha256_of_file(path) == entry.get("sha256"):
            report.add(name, "ok", "el SHA-256 coincide con el manifiesto")
        else:
            report.add(name, "fail", "el SHA-256 NO coincide: el fichero ha cambiado desde que se registró")


def verify_manifest(
    manifest_path: str,
    public_key_path: Optional[str] = None,
    evidence_dir: Optional[str] = None,
    artifacts_dir: Optional[str] = None,
    require_signature: bool = False,
) -> VerifyReport:
    """
    Verifica un manifiesto.

    - ``public_key_path``: clave pública de confianza del examinador. Sin ella,
      la firma solo se comprueba contra la clave incluida en el propio manifiesto
      (consistencia interna, no autenticidad).
    - ``evidence_dir``: carpeta con los logs originales para re-calcular sus hashes.
    - ``artifacts_dir``: carpeta con el informe (por defecto, la del manifiesto).
    """
    report = VerifyReport()

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        report.add("Lectura del manifiesto", "fail", f"no se puede leer: {e}")
        return report
    report.add("Lectura del manifiesto", "ok")

    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION or "integrity" not in manifest:
        report.add("Formato", "fail", f"se espera un manifiesto de LogHound con schema_version {SCHEMA_VERSION}")
        return report

    integrity = manifest.get("integrity") or {}
    body = {k: v for k, v in manifest.items() if k != "integrity"}
    data = canonical_bytes(body)

    # 1) Hash del manifiesto
    if sha256_of_bytes(data) == integrity.get("manifest_sha256"):
        report.add("Hash del manifiesto", "ok", "coincide")
    else:
        report.add("Hash del manifiesto", "fail", "NO coincide: el contenido del manifiesto ha sido modificado")

    # 2) Firma
    signature = integrity.get("signature")
    if not signature:
        status = "fail" if require_signature else "warn"
        report.add(
            "Firma digital",
            status,
            "el manifiesto no está firmado: el hash solo detecta cambios accidentales, no manipulación deliberada",
        )
    else:
        try:
            embedded_raw = base64.b64decode(signature["public_key"])
            sig_bytes = base64.b64decode(signature["value"])
            if signature.get("algorithm") != "ed25519":
                raise ValueError(f"algoritmo no soportado: {signature.get('algorithm')}")
            embedded_key = ed25519.Ed25519PublicKey.from_public_bytes(embedded_raw)
            fingerprint = public_key_fingerprint(embedded_raw)

            if public_key_path:
                trusted_key = _load_public_key(public_key_path)
                if _raw_public_bytes(trusted_key) != embedded_raw:
                    report.add(
                        "Firma digital",
                        "fail",
                        f"el manifiesto está firmado con otra clave (huella {fingerprint}) distinta de la clave de confianza",
                    )
                else:
                    trusted_key.verify(sig_bytes, data)
                    report.add("Firma digital", "ok", f"firma válida con la clave de confianza (huella {fingerprint})")
            else:
                embedded_key.verify(sig_bytes, data)
                report.add(
                    "Firma digital",
                    "warn",
                    f"firma válida con la clave incluida en el manifiesto (huella {fingerprint}), pero esa clave "
                    "NO se ha contrastado: usa --public-key con la clave pública del examinador para confirmar la autoría",
                )
        except InvalidSignature:
            report.add("Firma digital", "fail", "la firma NO es válida: el manifiesto ha sido alterado o la firma es falsa")
        except (KeyError, ValueError, TypeError, OSError) as e:
            report.add("Firma digital", "fail", f"firma o clave no utilizable: {e}")

    # 3) Ficheros referenciados
    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
    _verify_files(report, manifest.get("artifacts", []), artifacts_dir or manifest_dir, "Informe")
    _verify_files(report, manifest.get("evidence", []), evidence_dir, "Evidencia")

    return report
