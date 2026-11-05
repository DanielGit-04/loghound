"""
CLI de LogHound.

Comandos:
  keygen   Genera un par de claves para firmar manifiestos.
  analyze  Analiza logs y genera informe + manifiesto de cadena de custodia.
  verify   Verifica un manifiesto (hash, firma y ficheros).
"""

from __future__ import annotations

import os
import sys

import click
from rich.console import Console
from rich.table import Table

from loghound import __version__
from loghound.hashing import ChainOfCustody, generate_keypair, utc_now_iso, verify_manifest
from loghound.parser import LogParseError, load_many
from loghound.report import render_report
from loghound.rules_engine import RuleError, load_rules, run_rules

console = Console()

SEVERITY_COLORS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "grey62"}
STATUS_STYLE = {
    "ok": ("[green]✓ OK[/green]"),
    "fail": ("[bold red]✗ FALLO[/bold red]"),
    "warn": ("[yellow]! AVISO[/yellow]"),
    "skip": ("[grey62]– omitido[/grey62]"),
}


@click.group()
@click.version_option(__version__, prog_name="LogHound")
def cli():
    """LogHound — analizador forense de logs con cadena de custodia."""


@cli.command()
@click.option("--out-dir", default="keys", show_default=True, help="Carpeta donde guardar las claves.")
@click.option("--name", default="examiner", show_default=True, help="Prefijo de los ficheros de clave.")
def keygen(out_dir, name):
    """Genera un par de claves Ed25519 para firmar los manifiestos."""
    try:
        private_path, public_path = generate_keypair(out_dir, name)
    except FileExistsError as e:
        console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)
    console.print(f"[green]✓ Clave privada:[/green] {private_path}  [bold red](SECRETA: no la compartas ni la subas a GitHub)[/bold red]")
    console.print(f"[green]✓ Clave pública:[/green] {public_path}  (esta sí se puede compartir para que otros verifiquen tus firmas)")


@cli.command()
@click.option("--logs", "logs_paths", required=True, multiple=True, type=click.Path(exists=True, dir_okay=False),
              help="Fichero de logs (JSON o JSON Lines). Se puede repetir para analizar varios.")
@click.option("--rules", "rules_path", required=True, type=click.Path(exists=True, dir_okay=False),
              help="Fichero YAML de reglas de detección.")
@click.option("--examiner", required=True, help="Nombre del examinador/analista.")
@click.option("--case-id", required=True, help="Identificador del caso (ej. CASE-2026-001).")
@click.option("--output", "output_path", default="output/report.html", show_default=True,
              help="Ruta del informe HTML de salida.")
@click.option("--sign-key", "sign_key", default=None, envvar="LOGHOUND_SIGN_KEY",
              type=click.Path(exists=True, dir_okay=False),
              help="Clave privada (.pem) para firmar el manifiesto. También se lee de LOGHOUND_SIGN_KEY.")
def analyze(logs_paths, rules_path, examiner, case_id, output_path, sign_key):
    """Analiza logs y genera informe + cadena de custodia."""
    coc = ChainOfCustody(case_id=case_id, examiner=examiner)

    for path in logs_paths:
        console.print(f"[cyan]➤[/cyan] Registrando evidencia: {path}")
        coc.add_evidence(path, role="log")
    coc.add_evidence(rules_path, role="rules")

    try:
        console.print("[cyan]➤[/cyan] Parseando logs...")
        events = load_many(list(logs_paths))
        coc.log_action(f"Logs parseados correctamente: {len(events)} eventos.")
    except LogParseError as e:
        console.print(f"[red]✗ Error al parsear logs:[/red] {e}")
        sys.exit(1)
    if not events:
        console.print("[yellow]! Los ficheros de logs no contienen ningún evento.[/yellow]")

    try:
        console.print("[cyan]➤[/cyan] Cargando reglas de detección...")
        rules = load_rules(rules_path)
    except RuleError as e:
        console.print(f"[red]✗ Error en las reglas:[/red] {e}")
        sys.exit(1)
    coc.log_action(f"Reglas cargadas: {len(rules)} reglas.")

    console.print("[cyan]➤[/cyan] Ejecutando motor de reglas...")
    detections = run_rules(rules, events)
    coc.log_action(f"Motor de reglas ejecutado: {len(detections)} detecciones generadas.")

    output_dir = os.path.dirname(os.path.abspath(output_path))
    manifest_path = os.path.join(output_dir, "chain_of_custody.json")

    console.print("[cyan]➤[/cyan] Generando informe HTML...")
    coc.log_action("Generando informe HTML.")
    render_report(
        case_id=case_id,
        examiner=examiner,
        generated_at=utc_now_iso(),
        detections=detections,
        manifest=coc.to_dict(),  # provisional: el informe no puede contener su propio hash
        total_events=len(events),
        output_path=output_path,
    )

    # Ahora que el informe está escrito en disco, se calcula su hash y se añade al manifiesto
    coc.add_artifact(output_path, role="report")
    manifest = coc.finalize(manifest_path, private_key_path=sign_key)

    console.print(f"\n[green]✓ Informe generado:[/green] {output_path}")
    console.print(f"[green]✓ Cadena de custodia:[/green] {manifest_path}")
    if manifest["integrity"]["signature"]:
        fp = manifest["integrity"]["signature"]["public_key_fingerprint"]
        console.print(f"[green]✓ Manifiesto firmado[/green] (huella de la clave pública: {fp})\n")
    else:
        console.print(
            "[yellow]! Manifiesto SIN firma.[/yellow] Solo detecta cambios accidentales. "
            "Para firmarlo: [bold]loghound keygen[/bold] y luego [bold]--sign-key keys/examiner_private.pem[/bold]\n"
        )

    table = Table(title="Resumen de detecciones")
    for column in ("Regla", "Técnica MITRE", "Severidad", "Entidad", "Nº eventos"):
        table.add_column(column)
    for d in detections:
        color = SEVERITY_COLORS.get(d["severity"], "white")
        table.add_row(d["rule_id"], d["mitre"] or "-", f"[{color}]{d['severity']}[/]", d["entity"], str(len(d["evidence"])))
    console.print(table)


@cli.command()
@click.option("--manifest", "manifest_path", required=True, type=click.Path(exists=True, dir_okay=False),
              help="Ruta a chain_of_custody.json")
@click.option("--public-key", "public_key", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Clave pública (.pem) de confianza del examinador, para confirmar quién firmó.")
@click.option("--evidence-dir", default=None, type=click.Path(exists=True, file_okay=False),
              help="Carpeta con los logs originales, para volver a calcular sus hashes.")
@click.option("--report-dir", default=None, type=click.Path(exists=True, file_okay=False),
              help="Carpeta con el informe (por defecto, la del manifiesto).")
@click.option("--require-signature", is_flag=True, help="Falla si el manifiesto no está firmado.")
def verify(manifest_path, public_key, evidence_dir, report_dir, require_signature):
    """Verifica la integridad de un manifiesto de cadena de custodia."""
    result = verify_manifest(
        manifest_path,
        public_key_path=public_key,
        evidence_dir=evidence_dir,
        artifacts_dir=report_dir,
        require_signature=require_signature,
    )

    table = Table(title=f"Verificación de {os.path.basename(manifest_path)}")
    table.add_column("Comprobación")
    table.add_column("Resultado")
    table.add_column("Detalle", overflow="fold")
    for check in result.checks:
        table.add_row(check.name, STATUS_STYLE[check.status], check.detail)
    console.print(table)

    if result.ok:
        console.print("[green]✓ Verificación superada[/green] (revisa los avisos, si los hay).")
    else:
        console.print("[bold red]✗ ALERTA:[/bold red] alguna comprobación ha fallado. Posible manipulación o error.")
        sys.exit(1)


if __name__ == "__main__":
    cli()
