import asyncio
import json
from pathlib import Path
import typer
import time

from toolbehave.config import get_settings
from toolbehave.db import DB
from toolbehave.pipeline.orchestrator import Orchestrator
from toolbehave.services.virustotal import VirusTotalClient
from toolbehave.services.hybridanalysis import HybridAnalysisClient
from toolbehave.analysis.normalizer import normalize_report
from toolbehave.mapping.equivocal_behaviours import load_eb_rules, enrich_normalized_with_eb
from toolbehave.mapping.equivocal_behaviours import load_eb_rules, enrich_normalized_with_eb, build_eb_summary


app = typer.Typer(no_args_is_help=True)

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _stage_file(reports_dir: Path, stage: str, sha: str) -> Path:
    # reports/<stage>/<stage>_<sha>.json
    d = reports_dir / stage
    _ensure_dir(d)
    return d / f"{stage}_{sha}.json"

def build_orchestrator() -> Orchestrator:
    s = get_settings()
    db = DB(s.db_path)
    vt = VirusTotalClient(s.vt_api_key)
    ha = HybridAnalysisClient(s.ha_api_key)
    return Orchestrator(db=db, vt=vt, ha=ha)

@app.command()
def submit(path: str):
    """Submit a file to VirusTotal + Hybrid Analysis."""
    orch = build_orchestrator()
    asyncio.run(orch.submit(path))
    typer.echo("Submitted to VT + HA.")

@app.command()
def list():
    """List submissions."""
    orch = build_orchestrator()
    rows = orch.db.list_submissions()
    for r in rows:
        typer.echo(f"{r['sha256']} | {r['service']} | {r['status']} | {r['external_id']}")

@app.command()
def poll(sha256: str):
    """Poll status once for a given sha256."""
    orch = build_orchestrator()
    asyncio.run(orch.poll_once(sha256))
    typer.echo("Polled.")

@app.command()
def report(sha256: str, out: str = "report.json"):
    """Fetch raw reports (if available) and write to a json file."""
    orch = build_orchestrator()
    data = asyncio.run(orch.fetch_reports(sha256))
    Path(out).write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"Wrote {out}")
@app.command("poll-all")
def poll_all():
    """Poll status once for ALL sha256 found in the DB."""
    orch = build_orchestrator()
    asyncio.run(orch.poll_all_once())
    typer.echo("Polled all submissions once.")

@app.command()
def watch(interval: int = 60):
    """Continuously poll status for ALL submissions every N seconds (Ctrl+C to stop)."""
    orch = build_orchestrator()
    typer.echo(f"Watching submissions. Polling every {interval}s. Press Ctrl+C to stop.")
    try:
        while True:
            asyncio.run(orch.poll_all_once())
            # mostra lo stato dopo ogni giro
            rows = orch.db.list_submissions()
            typer.echo("---- status ----")
            for r in rows:
                typer.echo(f"{r['sha256']} | {r['service']} | {r['status']} | {r['external_id']}")
            time.sleep(interval)
    except KeyboardInterrupt:
        typer.echo("Stopped.")
@app.command("report-all")
def report_all(
    out_dir: str = "reports",
    force: bool = typer.Option(False, "--force", help="Regenerate and overwrite existing report files."),
):
    """Fetch raw reports for ALL sha256 found in DB, skipping already-generated files by default."""
    orch = build_orchestrator()

    # Preferisci un metodo esplicito se esiste, altrimenti usa list_sha256s()
    if hasattr(orch.db, "all_sha256s") and callable(getattr(orch.db, "all_sha256s")):
        sha_list = orch.db.all_sha256s()
    else:
        sha_list = orch.db.list_sha256s()

    if not sha_list:
        typer.echo("No submissions in DB.")
        raise typer.Exit(code=0)

    out_path_dir = Path(out_dir)
    out_path_dir.mkdir(parents=True, exist_ok=True)

    generated = 0
    skipped = 0
    failed = 0

    for sha in sha_list:
        out_file = _stage_file(out_path_dir, "raw", sha)

        # migrazione soft: se esiste il vecchio reports/report_<sha>.json copialo nel nuovo path
        legacy = out_path_dir / f"report_{sha}.json"
        if not out_file.exists() and legacy.exists():
            out_file.write_text(legacy.read_text(encoding="utf-8"), encoding="utf-8")

        # Se il report esiste già e non hai messo --force, salta
        if out_file.exists() and not force:
            skipped += 1
            continue

        try:
            data = asyncio.run(orch.fetch_reports(sha))
            out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            generated += 1
        except Exception as e:
            failed += 1
            typer.echo(f"FAILED {sha}: {e}")

    typer.echo(f"Done. Generated={generated}, Skipped={skipped}, Failed={failed}, OutDir={out_dir}")

@app.command("normalize-all")
def normalize_all(
    reports_dir: str = "reports",
    force: bool = typer.Option(False, "--force", help="Overwrite existing normalized files."),
):
    """
    Normalize ALL existing raw reports in reports_dir:
    - reads reports/report_<sha>.json
    - writes reports/normalized_<sha>.json
    Skips if normalized file exists (unless --force).
    """
    rep_dir = Path(reports_dir)
    if not rep_dir.exists():
        typer.echo(f"Reports directory not found: {reports_dir}")
        raise typer.Exit(code=1)

    raw_dir = rep_dir / "raw"
    _ensure_dir(raw_dir)
    raw_files = sorted(raw_dir.glob("raw_*.json"))

    if not raw_files:
        typer.echo("No raw reports found (report_*.json). Run report-all first.")
        raise typer.Exit(code=0)

    generated = 0
    skipped = 0
    failed = 0

    for raw_path in raw_files:
        # report_<sha>.json -> normalized_<sha>.json
        sha = raw_path.stem.replace("raw_", "", 1)
        out_path = _stage_file(rep_dir, "normalized", sha)

        # migrazione soft: se esiste il vecchio normalized_<sha>.json copialo nel nuovo path
        legacy_norm = rep_dir / f"normalized_{sha}.json"
        if not out_path.exists() and legacy_norm.exists():
            out_path.write_text(legacy_norm.read_text(encoding="utf-8"), encoding="utf-8")

        if out_path.exists() and not force:
            skipped += 1
            continue

        try:
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            normalized = normalize_report(raw, sha256=sha)
            out_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
            generated += 1
        except Exception as e:
            failed += 1
            typer.echo(f"FAILED normalize {raw_path.name}: {e}")

    typer.echo(f"Done. Generated={generated}, Skipped={skipped}, Failed={failed}, Dir={reports_dir}")
@app.command("eb-all")
def eb_all(
    reports_dir: str = "reports",
    force: bool = typer.Option(False, "--force", help="Overwrite existing enriched files."),
):
    """
    Legge reports/normalized_*.json e genera reports/enriched_*.json aggiungendo le observations EB.
    Incrementale: se enriched_<sha>.json esiste, lo salta (a meno di --force).
    """
    rep_dir = Path(reports_dir)
    if not rep_dir.exists():
        typer.echo(f"Reports directory not found: {reports_dir}")
        raise typer.Exit(code=1)

    norm_dir = rep_dir / "normalized"
    if not norm_dir.exists():
        typer.echo("No normalized directory found. Run normalize-all first.")
        raise typer.Exit(code=0)

    normalized_files = sorted(norm_dir.glob("normalized_*.json"))
    if not normalized_files:
        typer.echo("No normalized reports found (normalized_*.json). Run normalize-all first.")
        raise typer.Exit(code=0)

    # Carica regole EB dai due file in src/resources/
    rules = load_eb_rules()

    generated = 0
    skipped = 0
    failed = 0

    for npath in normalized_files:
        sha = npath.stem.replace("normalized_", "", 1)
        out_path = _stage_file(rep_dir, "enriched", sha)

        # migrazione soft: se esiste il vecchio enriched_<sha>.json copialo nel nuovo path
        legacy_enr = rep_dir / f"enriched_{sha}.json"
        if not out_path.exists() and legacy_enr.exists():
            out_path.write_text(legacy_enr.read_text(encoding="utf-8"), encoding="utf-8")

        if out_path.exists() and not force:
            skipped += 1
            continue

        try:
            normalized = json.loads(npath.read_text(encoding="utf-8"))
            enriched = enrich_normalized_with_eb(normalized, rules)
            # EB-only (sintesi compatta)
            eb_out = _stage_file(rep_dir, "eb", sha)
            if eb_out.exists() and not force:
                # se enriched è stato rigenerato ma eb già esiste, manteniamo lo skip coerente
                pass
            else:
                eb_summary = build_eb_summary(enriched)
                eb_out.write_text(json.dumps(eb_summary, indent=2), encoding="utf-8")

            generated += 1
        except Exception as e:
            failed += 1
            typer.echo(f"FAILED EB {npath.name}: {e}")

    typer.echo(f"Done. Generated={generated}, Skipped={skipped}, Failed={failed}, Dir={reports_dir}")
