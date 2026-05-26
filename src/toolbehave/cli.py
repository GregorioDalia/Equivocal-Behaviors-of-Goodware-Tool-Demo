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
from toolbehave.mapping.equivocal_behaviours import (
    load_eb_rules,
    load_requirement_rules,
    enrich_normalized_with_eb,
    build_eb_summary,
)
app = typer.Typer(no_args_is_help=True)

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _stage_file(reports_dir: Path, stage: str, sha: str) -> Path:
    # reports/<stage>/<stage>_<sha>.json
    d = reports_dir / stage
    _ensure_dir(d)
    return d / f"{stage}_{sha}.json"

def _row_get(row, key: str, default=None):
    """
    Safe getter for sqlite3.Row or dict-like rows.
    Useful because older DBs may not have newer columns such as environment_id.
    """
    try:
        return row[key]
    except Exception:
        if isinstance(row, dict):
            return row.get(key, default)
        return default

def _format_submission_row(row) -> str:
    sha = _row_get(row, "sha256", "-")
    service = _row_get(row, "service", "-")
    status = _row_get(row, "status", "-")
    external_id = _row_get(row, "external_id", "-")
    environment_id = _row_get(row, "environment_id", None)

    env = environment_id if environment_id is not None else "-"

    return f"{sha} | {service} | env={env} | {status} | {external_id}"

def build_orchestrator() -> Orchestrator:
    s = get_settings()
    db = DB(s.db_path)
    vt = VirusTotalClient(s.vt_api_key)
    ha = HybridAnalysisClient(s.ha_api_key)
    return Orchestrator(db=db, vt=vt, ha=ha)

@app.command()
def submit(
    path: str,
    force: bool = typer.Option(
        False,
        "--force",
        help="Force resubmission even if the sample already exists in the DB.",
    ),
):
    """
    Submit a file to VirusTotal + Hybrid Analysis.

    Default behavior:
      - reuse existing VT/HA submissions from the DB when available;
      - submit only missing/stale providers.

    With --force:
      - resubmit to both providers and update the DB.
    """
    orch = build_orchestrator()
    asyncio.run(orch.submit(path, force=force))
    typer.echo("Submit/resume step completed.")

@app.command("list")
def list_cmd():
    """List submissions."""
    orch = build_orchestrator()
    rows = orch.db.list_submissions()

    if not rows:
        typer.echo("No submissions found.")
        raise typer.Exit(code=0)

    for r in rows:
        typer.echo(_format_submission_row(r))

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

            rows = orch.db.list_submissions()
            typer.echo("---- status ----")

            if not rows:
                typer.echo("No submissions found.")
            else:
                for r in rows:
                    typer.echo(_format_submission_row(r))

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
    fixed:
    reports/raw/raw_*.json e scrivi in reports/normalized/normalized_<sha>.json.
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
    force: bool = typer.Option(False, "--force", help="Overwrite existing enriched/eb files."),
    requirements: str = typer.Option(
        "",
        "--requirements",
        help="Optional custom requirements JSON (same structure as Equivocal_Behaviours.json).",
    ),
):
    """
    Generate enriched + EB-only synth files from normalized reports.

    Reads:
      - reports/normalized/normalized_<sha>.json

    Writes:
      - reports/enriched/enriched_<sha>.json
      - reports/eb/eb_<sha>.json

    If --requirements is provided, also computes custom Requirements (R1..Rn) in addition to standard ESB.
    """
    import json
    from pathlib import Path

    rep_dir = Path(reports_dir)
    _ensure_dir(rep_dir)

    norm_dir = rep_dir / "normalized"
    if not norm_dir.exists():
        typer.echo(f"Normalized directory not found: {norm_dir}. Run 'toolbehave normalize-all' first.")
        raise typer.Exit(code=1)

    norm_files = sorted(norm_dir.glob("normalized_*.json"))
    if not norm_files:
        typer.echo(f"No normalized files found in: {norm_dir}")
        raise typer.Exit(code=0)

    # Load rules
    eb_rules = load_eb_rules()

    req_rules = None
    if requirements:
        req_rules = load_requirement_rules(Path(requirements))

    generated_enriched = 0
    generated_eb = 0
    skipped = 0
    failed = 0

    for p in norm_files:
        sha = p.stem.replace("normalized_", "", 1).strip()
        if not sha:
            continue

        enriched_path = _stage_file(rep_dir, "enriched", sha)
        eb_path = _stage_file(rep_dir, "eb", sha)

        if not force and enriched_path.exists() and eb_path.exists():
            skipped += 1
            continue

        try:
            normalized = json.loads(p.read_text(encoding="utf-8"))

            schema_meta = {"enabled": False}
            if requirements:
                schema_meta = _requirements_fingerprint(requirements)

            enriched = enrich_normalized_with_eb(normalized, eb_rules, req_rules)
            eb_summary = build_eb_summary(enriched)

            # IMPORTANT: add schema metadata BEFORE writing files
            enriched["requirements_schema"] = schema_meta
            eb_summary["requirements_schema"] = schema_meta

            # Write enriched (unless exists and not force)
            if force or not enriched_path.exists():
                enriched_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
                generated_enriched += 1

            # Write eb synth (unless exists and not force)
            if force or not eb_path.exists():
                eb_path.write_text(json.dumps(eb_summary, indent=2), encoding="utf-8")
                generated_eb += 1

        except Exception as e:
            failed += 1
            typer.echo(f"FAILED {sha}: {e}")

    typer.echo(
        "Done. "
        f"EnrichedWritten={generated_enriched}, EBSynthWritten={generated_eb}, "
        f"Skipped={skipped}, Failed={failed}, OutDir={rep_dir}"
    )



@app.command("eb-summary")
def eb_summary(
    reports_dir: str = "reports",
    top: int = typer.Option(20, "--top", help="Max rows to show (sorted by total EB desc)."),
    csv_out: str = typer.Option("", "--csv", help="Optional path to write CSV (e.g., reports/eb_summary.csv)."),
):
    """
    Reads reports/eb/eb_<sha>.json files and prints a summary table.
    Optionally writes a CSV. (No plots generated here.)
    """
    import json
    from pathlib import Path

    rep_dir = Path(reports_dir)
    eb_dir = rep_dir / "eb"
    if not eb_dir.exists():
        typer.echo(f"EB directory not found: {eb_dir}. Run 'toolbehave eb-all' first.")
        raise typer.Exit(code=1)

    eb_files = sorted(eb_dir.glob("eb_*.json"))
    if not eb_files:
        typer.echo(f"No EB files found in: {eb_dir}")
        raise typer.Exit(code=0)

    rows = []
    for p in eb_files:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            typer.echo(f"FAILED to read {p.name}: {e}")
            continue

        sha = data.get("sha256") or p.stem.replace("eb_", "", 1)
        counts = data.get("counts") or {}
        total = int(counts.get("total", 0) or 0)
        ha = int(counts.get("hybridanalysis", 0) or 0)
        vt = int(counts.get("virustotal", 0) or 0)
        both = int(counts.get("both", 0) or 0)

        rows.append({
            "sha256": sha,
            "total_eb": total,
            "ha_eb": ha,
            "vt_eb": vt,
            "both_eb": both,
            "file": str(p),
        })

    # sort by total desc then sha
    rows.sort(key=lambda r: (-r["total_eb"], r["sha256"]))

    # limit view
    view = rows[: max(1, top)]

    # --- print table ---
    headers = ["sha256", "total_eb", "ha_eb", "vt_eb", "both_eb"]
    colw = {h: len(h) for h in headers}
    for r in view:
        for h in headers:
            colw[h] = max(colw[h], len(str(r[h])))

    def fmt_row(r):
        return "  ".join(str(r[h]).ljust(colw[h]) for h in headers)

    typer.echo(fmt_row({h: h for h in headers}))
    typer.echo("-" * (sum(colw.values()) + 2 * (len(headers) - 1)))
    for r in view:
        typer.echo(fmt_row(r))

    typer.echo(f"\nRows: {len(rows)} (showing top {len(view)}). Source dir: {eb_dir}")

    # --- optional CSV ---
    if csv_out:
        outp = Path(csv_out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        import csv as _csv

        with outp.open("w", newline="", encoding="utf-8") as f:
            w = _csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
            for r in rows:
                w.writerow({h: r[h] for h in headers})
        typer.echo(f"Wrote CSV: {outp}")

import hashlib
from typing import Dict, List, Any, Optional, Tuple


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _statuses_for_sha(db: DB, sha256: str) -> dict[str, str]:
    """
    Returns {service: status} for a given sha across DB rows.
    Supports sqlite3.Row (mapping-like) and plain dict rows.
    """
    out: dict[str, str] = {}

    for r in db.list_submissions():
        # sqlite3.Row supports r["col"]; dict supports .get()
        try:
            r_sha = r["sha256"]  # type: ignore[index]
        except Exception:
            r_sha = r.get("sha256") if isinstance(r, dict) else None

        if r_sha != sha256:
            continue

        try:
            svc = r["service"]  # type: ignore[index]
        except Exception:
            svc = r.get("service") if isinstance(r, dict) else ""

        try:
            st = r["status"]  # type: ignore[index]
        except Exception:
            st = r.get("status") if isinstance(r, dict) else ""

        svc = str(svc or "").strip()
        st = str(st or "").strip()
        if svc:
            out[svc] = st



    return out



def _is_completed_both(statuses: Dict[str, str]) -> bool:
    """
    True if BOTH VT and HA are COMPLETED.
    (If in futuro aggiungi servizi, potrai generalizzare qui.)
    """
    return statuses.get("virustotal") == "COMPLETED" and statuses.get("hybridanalysis") == "COMPLETED"


def _report_one(orch: Orchestrator, sha256: str, reports_dir: Path, force: bool = False) -> Path:
    """
    Fetch raw reports for ONE sha and write reports/raw/raw_<sha>.json
    """
    out_file = _stage_file(reports_dir, "raw", sha256)
    if out_file.exists() and not force:
        return out_file

    data = asyncio.run(orch.fetch_reports(sha256))
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out_file


def _normalize_one(sha256: str, reports_dir: Path, force: bool = False) -> Path:
    """
    Read reports/raw/raw_<sha>.json and write reports/normalized/normalized_<sha>.json
    """
    raw_path = _stage_file(reports_dir, "raw", sha256)
    if not raw_path.exists():
        raise FileNotFoundError(f"Missing raw file: {raw_path}. Run report step first.")

    out_path = _stage_file(reports_dir, "normalized", sha256)
    if out_path.exists() and not force:
        return out_path

    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    normalized = normalize_report(raw, sha256=sha256)
    out_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    return out_path


def _eb_one(
    sha256: str,
    reports_dir: Path,
    force: bool = False,
    requirements: str = "",
):
    """
    Read reports/normalized/normalized_<sha>.json and write:
      - reports/enriched/enriched_<sha>.json
      - reports/eb/eb_<sha>.json

    If requirements is provided, also computes custom Requirements (R1..Rn),
    and writes requirements_schema metadata to BOTH enriched + eb summary.
    """
    import json
    from pathlib import Path

    norm_path = _stage_file(reports_dir, "normalized", sha256)
    if not norm_path.exists():
        raise FileNotFoundError(f"Missing normalized file: {norm_path}. Run normalize step first.")

    enriched_path = _stage_file(reports_dir, "enriched", sha256)
    eb_path = _stage_file(reports_dir, "eb", sha256)

    if not force and enriched_path.exists() and eb_path.exists():
        return enriched_path, eb_path

    normalized = json.loads(norm_path.read_text(encoding="utf-8"))

    eb_rules = load_eb_rules()

    req_rules = None
    schema_meta = {"enabled": False}
    if requirements:
        req_path = Path(requirements).resolve()
        req_rules = load_requirement_rules(req_path)
        schema_meta = _requirements_fingerprint(str(req_path))

    enriched = enrich_normalized_with_eb(normalized, eb_rules, req_rules)
    eb_summary = build_eb_summary(enriched)

    # IMPORTANT: add schema metadata BEFORE writing files
    enriched["requirements_schema"] = schema_meta
    eb_summary["requirements_schema"] = schema_meta

    enriched_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
    eb_path.write_text(json.dumps(eb_summary, indent=2), encoding="utf-8")

    return enriched_path, eb_path

def _count_requirements_entries(p: "Path") -> int:
    import json
    import builtins

    obj = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(obj, builtins.dict):
        return len(obj)
    if isinstance(obj, builtins.list):
        return len(obj)
    raise ValueError("Requirements JSON must be a dict or list.")


def _requirements_fingerprint(requirements_path: str) -> dict:
    """
    Build a stable fingerprint for a requirements JSON.

    - Uses resolved absolute path for metadata
    - Hash is computed on raw file bytes (content-based)
    """
    import hashlib
    from pathlib import Path

    p_in = Path(requirements_path)
    p = p_in.resolve()

    if not p.exists():
        raise FileNotFoundError(f"Requirements file not found: {p}")

    data = p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()

    return {
        "enabled": True,
        "path_original": str(p_in),
        "path": str(p),               # resolved absolute path (no ambiguity)
        "name": p.name,
        "sha256": sha,
        "count": _count_requirements_entries(p),  # see helper below
    }

@app.command("eb-stats")
def eb_stats(
    reports_dir: str = typer.Option("reports", "--reports-dir", help="Base reports directory."),
    by_os: bool = typer.Option(
        False,
        "--by-os",
        help="Also generate aggregate EB statistics grouped by target operating system.",
    ),
    sha: list[str] | None = typer.Option(
        None,
        "--sha",
        help="Filter subset by repeating: --sha <sha> --sha <sha> ...",
    ),
    sha_list: str = typer.Option(
        "",
        "--sha-list",
        help="Path to a text file with one sha256 per line (subset).",
    ),
    sha_single: str = typer.Option(
        "",
        "--sha-single",
        help="Single-sample mode for this sha256.",
    ),
    requirements: str = typer.Option(
        "",
        "--requirements",
        help="Optional custom requirements JSON used to filter to a specific schema in aggregate mode.",
    ),
):
    """
    EB statistics.

    Aggregate:
      - always writes ESB-only plots into:
          reports/plots/aggregate/<scope>/all/

      - with --by-os, also writes OS-specific aggregate plots into:
          reports/plots/aggregate/by_os/<os>/all/

      - requirements plots are written only when the requirements schema is coherent.

    Single-sample mode:
      - writes single-sample table and matrix into:
          reports/plots/single/<sha-prefix>/
    """
    import builtins
    import csv
    import json
    import re
    from collections import Counter
    from pathlib import Path
    from typing import Optional, List, Set, Dict, Any, Tuple

    # -------------------------
    # Normalize --sha
    # -------------------------
    sha_values: Optional[List[str]]
    if sha is None:
        sha_values = None
    elif isinstance(sha, builtins.list):
        sha_values = [str(s) for s in sha]
    else:
        sha_values = [str(sha)]

    # -------------------------
    # OS helpers
    # -------------------------
    HA_ENV_TO_OS = {
        140: "windows",
        330: "linux",
        430: "macos",
    }

    def _os_from_environment_id(environment_id) -> str:
        if environment_id is None:
            return "unknown"

        try:
            environment_id = int(environment_id)
        except (TypeError, ValueError):
            return "unknown"

        return HA_ENV_TO_OS.get(environment_id, "unknown")

    def _sha_to_target_os_from_db(db) -> dict[str, str]:
        """
        Build a mapping:
          sha256 -> target_os

        The OS is derived from the Hybrid Analysis environment_id stored
        in the submissions table.
        """
        out: dict[str, str] = {}

        rows = db.list_submissions()

        for r in rows:
            try:
                service = r["service"]
                sha256 = r["sha256"]
            except Exception:
                continue

            if str(service).lower() != "hybridanalysis":
                continue

            try:
                environment_id = r["environment_id"]
            except Exception:
                environment_id = None

            out[str(sha256)] = _os_from_environment_id(environment_id)

        return out

    # -------------------------
    # General helpers
    # -------------------------
    def code_key(c: str):
        m = re.search(r"(\d+)$", c)
        return (0, int(m.group(1))) if m else (1, c)

    def sort_key_code(c: str):
        if c.startswith("ESB"):
            return (0, code_key(c))
        if c.startswith("R"):
            return (1, code_key(c))
        return (2, c)

    def read_sha_list_file(path_str: str) -> Set[str]:
        p = Path(path_str)
        if not p.exists():
            raise FileNotFoundError(f"sha-list file not found: {p}")

        out: Set[str] = set()

        for line in p.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.add(s)

        return out

    def sanitize_folder_name(s: str) -> str:
        s = s.strip()
        s = re.sub(r"[^\w\-\.]+", "_", s)
        s = re.sub(r"_+", "_", s)
        return s.strip("_") or "schema"

    def load_code_mappings() -> Dict[str, str]:
        resources_dir = Path("src/resources").resolve()
        p = resources_dir / "code_mappings.json"

        if not p.exists():
            raise FileNotFoundError(f"Missing mapping file: {p}")

        data = json.loads(p.read_text(encoding="utf-8"))

        if not isinstance(data, builtins.dict):
            raise ValueError("code_mappings.json must be a JSON object: EB_NAME -> ESB_CODE.")

        out: Dict[str, str] = {}

        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, str) and v.strip():
                out[k.strip()] = v.strip()

        return out

    def canonical_esb_codes() -> List[str]:
        cmap = load_code_mappings()
        return sorted(set(cmap.values()), key=code_key)

    def load_custom_requirements_codes_from_file(path_str: str) -> List[str]:
        if not path_str:
            return []

        p = Path(path_str)

        if not p.exists():
            raise FileNotFoundError(f"Requirements file not found: {p}")

        data = json.loads(p.read_text(encoding="utf-8"))

        if isinstance(data, builtins.list):
            n = len(data)
        elif isinstance(data, builtins.dict):
            n = len(list(data.values()))
        else:
            raise ValueError("Requirements JSON must be a list or object.")

        return [f"R{i}" for i in range(1, n + 1)]

    def load_eb_file(eb_path: Path) -> Dict[str, Any]:
        return json.loads(eb_path.read_text(encoding="utf-8"))

    def write_text_table(path: Path, headers: List[str], rows: List[Dict[str, Any]]) -> None:
        colw = {h: len(h) for h in headers}

        for r in rows:
            for h in headers:
                colw[h] = max(colw[h], len(str(r.get(h, ""))))

        lines = []
        lines.append("  ".join(h.ljust(colw[h]) for h in headers))
        lines.append("-" * (sum(colw.values()) + 2 * (len(headers) - 1)))

        for r in rows:
            lines.append("  ".join(str(r.get(h, "")).ljust(colw[h]) for h in headers))

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # -------------------------
    # Locate EB directory
    # -------------------------
    rep_dir = Path(reports_dir)
    eb_dir = rep_dir / "eb"

    if not eb_dir.exists():
        typer.echo(f"EB directory not found: {eb_dir}. Run 'toolbehave eb-all' first.")
        raise typer.Exit(code=1)

    esb_codes = canonical_esb_codes()
    req_codes_for_single = load_custom_requirements_codes_from_file(requirements) if requirements else []
    single_all_codes = esb_codes + req_codes_for_single

    # -------------------------
    # SINGLE SAMPLE MODE
    # -------------------------
    if sha_single:
        target = sha_single.strip()
        eb_path = eb_dir / f"eb_{target}.json"

        if not eb_path.exists():
            typer.echo(f"Missing EB file for sha: {target}")
            typer.echo(f"Expected: {eb_path}")
            raise typer.Exit(code=1)

        data = load_eb_file(eb_path)

        ebs = data.get("equivocal_behaviours") or []
        if not isinstance(ebs, builtins.list):
            ebs = []

        reqs = data.get("requirements") or []
        if not isinstance(reqs, builtins.list):
            reqs = []

        present: Dict[str, Set[str]] = {}

        for e in ebs:
            if not isinstance(e, builtins.dict):
                continue

            code = e.get("code")
            if not isinstance(code, str) or not code.strip():
                continue

            srcs = e.get("sources_triggered") or []
            if not isinstance(srcs, builtins.list):
                srcs = []

            present[code.strip()] = set(str(s) for s in srcs)

        for r_ in reqs:
            if not isinstance(r_, builtins.dict):
                continue

            code = r_.get("code")
            if not isinstance(code, str) or not code.strip():
                continue

            srcs = r_.get("sources_triggered") or []
            if not isinstance(srcs, builtins.list):
                srcs = []

            present[code.strip()] = set(str(s) for s in srcs)

        single_dir = rep_dir / "plots" / "single" / target[:10]
        single_dir.mkdir(parents=True, exist_ok=True)

        rows: List[Dict[str, Any]] = []
        headers = ["code", "type", "sources", "ha_mitre_n", "vt_mitre_n"]

        def mitre_counts(item: Dict[str, Any]) -> Tuple[int, int]:
            mm = item.get("matched_mitre") or {}

            if not isinstance(mm, builtins.dict):
                return 0, 0

            ha_m = mm.get("hybridanalysis") or []
            vt_m = mm.get("virustotal") or []

            ha_n = len(ha_m) if isinstance(ha_m, builtins.list) else 0
            vt_n = len(vt_m) if isinstance(vt_m, builtins.list) else 0

            return ha_n, vt_n

        for e in ebs:
            if not isinstance(e, builtins.dict):
                continue

            code = str(e.get("code") or "").strip()
            if not code:
                continue

            srcs = e.get("sources_triggered") or []
            if not isinstance(srcs, builtins.list):
                srcs = []

            ha_n, vt_n = mitre_counts(e)

            rows.append(
                {
                    "code": code,
                    "type": "EB",
                    "sources": ",".join(str(s) for s in srcs),
                    "ha_mitre_n": ha_n,
                    "vt_mitre_n": vt_n,
                }
            )

        for r_ in reqs:
            if not isinstance(r_, builtins.dict):
                continue

            code = str(r_.get("code") or "").strip()
            if not code:
                continue

            srcs = r_.get("sources_triggered") or []
            if not isinstance(srcs, builtins.list):
                srcs = []

            ha_n, vt_n = mitre_counts(r_)

            rows.append(
                {
                    "code": code,
                    "type": "REQ",
                    "sources": ",".join(str(s) for s in srcs),
                    "ha_mitre_n": ha_n,
                    "vt_mitre_n": vt_n,
                }
            )

        rows.sort(key=lambda r: sort_key_code(str(r["code"])))

        table_path = single_dir / "single_table.txt"
        write_text_table(table_path, headers, rows)

        try:
            import matplotlib.pyplot as plt  # type: ignore
        except Exception:
            typer.echo(f"Wrote single outputs, but matplotlib is not available for PNG:\n- {table_path}")
            raise typer.Exit(code=0)

        row_codes = list(esb_codes)

        req_codes_in_file = []
        for r_ in reqs:
            if isinstance(r_, builtins.dict):
                c = r_.get("code")
                if isinstance(c, str) and c.strip():
                    req_codes_in_file.append(c.strip())

        def _rkey(c: str):
            m = re.search(r"(\d+)$", c)
            return int(m.group(1)) if m else 10**9

        req_codes_in_file = sorted(set(req_codes_in_file), key=_rkey)
        row_codes.extend(req_codes_in_file)

        matrix_rows = []

        for code in row_codes:
            srcs = present.get(code, set())
            matrix_rows.append(
                [
                    "X" if "hybridanalysis" in srcs else "",
                    "X" if "virustotal" in srcs else "",
                ]
            )

        fig, ax = plt.subplots(figsize=(6, max(4, 0.35 * len(row_codes))), dpi=160)
        ax.axis("off")

        tbl = ax.table(
            cellText=matrix_rows,
            rowLabels=row_codes,
            colLabels=["HybridAnalysis", "VirusTotal"],
            cellLoc="center",
            rowLoc="center",
            loc="center",
        )

        tbl.auto_set_font_size(False)
        tbl.set_fontsize(10)
        tbl.scale(1.0, 1.2)

        ax.set_title(f"EB/Requirements presence matrix - {target[:10]}", pad=12)

        out_png = single_dir / "single_presence_matrix.png"
        plt.tight_layout()
        plt.savefig(out_png, bbox_inches="tight")
        plt.close()

        typer.echo(f"Wrote single outputs:\n- {table_path}\n- {out_png}")
        raise typer.Exit(code=0)

    # -------------------------
    # AGGREGATE MODE
    # -------------------------
    filter_set: Set[str] = set()

    if sha_values:
        for s in sha_values:
            s = s.strip()
            if s:
                filter_set.add(s)

    if sha_list:
        try:
            filter_set |= read_sha_list_file(sha_list)
        except Exception as e:
            typer.echo(str(e))
            raise typer.Exit(code=1)

    eb_paths = sorted(eb_dir.glob("eb_*.json"))

    if filter_set:
        eb_paths = [p for p in eb_paths if p.stem.replace("eb_", "", 1) in filter_set]

    if not eb_paths:
        typer.echo("No EB files found for the requested scope.")
        raise typer.Exit(code=0)

    if sha_list:
        scope_name = Path(sha_list).stem
        scope_desc = f"SUBSET ({Path(sha_list).name})"
    elif filter_set:
        scope_name = "subset"
        scope_desc = f"SUBSET (n={len(filter_set)})"
    else:
        scope_name = "all"
        scope_desc = "ALL"

    schema_filter_hash: str = ""
    schema_filter_name: str = ""

    if requirements:
        meta = _requirements_fingerprint(requirements)
        schema_filter_hash = str(meta.get("sha256") or "")
        schema_filter_name = str(meta.get("name") or "")

    loaded: List[Tuple[Path, Dict[str, Any]]] = []

    for p in eb_paths:
        try:
            d = load_eb_file(p)
        except Exception as e:
            typer.echo(f"FAILED to read {p.name}: {e}")
            continue

        if schema_filter_hash:
            rs = d.get("requirements_schema") or {}
            if not (
                isinstance(rs, builtins.dict)
                and rs.get("enabled")
                and str(rs.get("sha256") or "") == schema_filter_hash
            ):
                continue

        loaded.append((p, d))

    if not loaded:
        if schema_filter_hash:
            typer.echo(
                f"No EB files match the requested requirements schema: "
                f"{schema_filter_name} ({schema_filter_hash[:12]})"
            )
        else:
            typer.echo("No valid EB files found after loading.")

        raise typer.Exit(code=0)

    # -------------------------
    # Plot styling
    # -------------------------
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        typer.echo("matplotlib not available. Install with: pip install matplotlib")
        raise typer.Exit(code=0)

    plt.rcParams.update(
        {
            "font.size": 10,
            "axes.titlesize": 12,
            "axes.labelsize": 10,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
        }
    )

    C_HA = "#1F77B4"
    C_VT = "#FF7F0E"
    C_HA_ONLY = "#74C476"
    C_VT_ONLY = "#FDAE6B"
    C_BOTH = "#9E9AC8"
    EDGE = "#4D4D4D"
    ALPHA = 0.85

    # -------------------------
    # Aggregation core
    # -------------------------
    def aggregate_counts(
        items: List[Tuple[Path, Dict[str, Any]]],
        include_requirements: bool,
        req_codes_hint: List[str],
    ) -> Tuple[List[str], Dict[str, Dict[str, int]], int]:
        total_samples = len(items)

        if total_samples <= 0:
            return [], {}, 0

        codes: List[str] = list(esb_codes)

        if include_requirements:
            codes += list(req_codes_hint)

        agg: Dict[str, Dict[str, int]] = {
            c: {"ha": 0, "vt": 0, "both": 0, "total": 0} for c in codes
        }

        for _p, d in items:
            ebs = d.get("equivocal_behaviours") or []

            if isinstance(ebs, builtins.list):
                for e in ebs:
                    if not isinstance(e, builtins.dict):
                        continue

                    code = e.get("code")
                    if not isinstance(code, str) or not code.strip():
                        continue

                    code = code.strip()

                    if code not in agg:
                        agg[code] = {"ha": 0, "vt": 0, "both": 0, "total": 0}

                    srcs = e.get("sources_triggered") or []
                    if not isinstance(srcs, builtins.list):
                        srcs = []

                    has_ha = "hybridanalysis" in srcs
                    has_vt = "virustotal" in srcs

                    agg[code]["total"] += 1

                    if has_ha:
                        agg[code]["ha"] += 1

                    if has_vt:
                        agg[code]["vt"] += 1

                    if has_ha and has_vt:
                        agg[code]["both"] += 1

            if include_requirements:
                reqs = d.get("requirements") or []

                if isinstance(reqs, builtins.list):
                    for r_ in reqs:
                        if not isinstance(r_, builtins.dict):
                            continue

                        code = r_.get("code")
                        if not isinstance(code, str) or not code.strip():
                            continue

                        code = code.strip()

                        if code not in agg:
                            agg[code] = {"ha": 0, "vt": 0, "both": 0, "total": 0}

                        srcs = r_.get("sources_triggered") or []
                        if not isinstance(srcs, builtins.list):
                            srcs = []

                        has_ha = "hybridanalysis" in srcs
                        has_vt = "virustotal" in srcs

                        agg[code]["total"] += 1

                        if has_ha:
                            agg[code]["ha"] += 1

                        if has_vt:
                            agg[code]["vt"] += 1

                        if has_ha and has_vt:
                            agg[code]["both"] += 1

        labels = sorted(set(agg.keys()), key=sort_key_code)
        return labels, agg, total_samples

    def build_stats_rows(
        labels: List[str],
        agg: Dict[str, Dict[str, int]],
        total_samples: int,
    ) -> List[Dict[str, Any]]:
        """
        Build tabular statistics for CSV/TXT outputs.

        Counts:
          ha_count      = samples where the code was triggered by HybridAnalysis
          vt_count      = samples where the code was triggered by VirusTotal
          both_count    = samples where both sources triggered the same code
          ha_only_count = samples where only HybridAnalysis triggered the code
          vt_only_count = samples where only VirusTotal triggered the code

        Percentages use total_samples as denominator.
        """
        rows: List[Dict[str, Any]] = []

        for code in labels:
            ha_count = int(agg.get(code, {}).get("ha", 0))
            vt_count = int(agg.get(code, {}).get("vt", 0))
            both_count = int(agg.get(code, {}).get("both", 0))

            ha_only_count = max(0, ha_count - both_count)
            vt_only_count = max(0, vt_count - both_count)

            if total_samples > 0:
                ha_pct = ha_count / total_samples * 100.0
                vt_pct = vt_count / total_samples * 100.0
                both_pct = both_count / total_samples * 100.0
                ha_only_pct = ha_only_count / total_samples * 100.0
                vt_only_pct = vt_only_count / total_samples * 100.0
            else:
                ha_pct = 0.0
                vt_pct = 0.0
                both_pct = 0.0
                ha_only_pct = 0.0
                vt_only_pct = 0.0

            rows.append(
                {
                    "code": code,
                    "total_samples": total_samples,
                    "ha_count": ha_count,
                    "vt_count": vt_count,
                    "both_count": both_count,
                    "ha_only_count": ha_only_count,
                    "vt_only_count": vt_only_count,
                    "ha_pct": round(ha_pct, 4),
                    "vt_pct": round(vt_pct, 4),
                    "both_pct": round(both_pct, 4),
                    "ha_only_pct": round(ha_only_pct, 4),
                    "vt_only_pct": round(vt_only_pct, 4),
                }
            )

        return rows

    def write_stats_tables(
        labels: List[str],
        agg: Dict[str, Dict[str, int]],
        total_samples: int,
        out_dir: Path,
        title_prefix: str,
    ) -> None:
        """
        Write CSV and TXT summary next to the PNG plots.
        """
        out_dir.mkdir(parents=True, exist_ok=True)

        rows = build_stats_rows(labels, agg, total_samples)

        count_fields = [
            "code",
            "total_samples",
            "ha_count",
            "vt_count",
            "both_count",
            "ha_only_count",
            "vt_only_count",
        ]

        pct_fields = [
            "code",
            "total_samples",
            "ha_pct",
            "vt_pct",
            "both_pct",
            "ha_only_pct",
            "vt_only_pct",
        ]

        all_fields = [
            "code",
            "total_samples",
            "ha_count",
            "vt_count",
            "both_count",
            "ha_only_count",
            "vt_only_count",
            "ha_pct",
            "vt_pct",
            "both_pct",
            "ha_only_pct",
            "vt_only_pct",
        ]

        counts_path = out_dir / "eb_stats_counts.csv"
        percentages_path = out_dir / "eb_stats_percentages.csv"
        summary_path = out_dir / "eb_stats_summary.txt"

        with counts_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=count_fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k, "") for k in count_fields})

        with percentages_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=pct_fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k, "") for k in pct_fields})

        # Human-readable compact summary
        top_ha = sorted(rows, key=lambda r: r["ha_count"], reverse=True)[:10]
        top_vt = sorted(rows, key=lambda r: r["vt_count"], reverse=True)[:10]
        top_both = sorted(rows, key=lambda r: r["both_count"], reverse=True)[:10]

        lines: List[str] = []
        lines.append(f"Scope: {title_prefix}")
        lines.append(f"Total samples: {total_samples}")
        lines.append(f"Total codes: {len(labels)}")
        lines.append("")
        lines.append("Generated files:")
        lines.append(f"- {counts_path.name}")
        lines.append(f"- {percentages_path.name}")
        lines.append("")
        lines.append("Top codes by HybridAnalysis count:")
        for r in top_ha:
            lines.append(f"- {r['code']}: {r['ha_count']} ({r['ha_pct']}%)")
        lines.append("")
        lines.append("Top codes by VirusTotal count:")
        for r in top_vt:
            lines.append(f"- {r['code']}: {r['vt_count']} ({r['vt_pct']}%)")
        lines.append("")
        lines.append("Top codes by agreement count:")
        for r in top_both:
            lines.append(f"- {r['code']}: {r['both_count']} ({r['both_pct']}%)")
        lines.append("")

        summary_path.write_text("\n".join(lines), encoding="utf-8")

        # Optional complete all-in-one CSV for convenience
        all_path = out_dir / "eb_stats_full.csv"
        with all_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k, "") for k in all_fields})

    def plot_4(
        labels: List[str],
        agg: Dict[str, Dict[str, int]],
        total_samples: int,
        out_dir: Path,
        title_prefix: str,
    ) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)

        if total_samples <= 0:
            return

        ha_cnt = [agg[c]["ha"] for c in labels]
        vt_cnt = [agg[c]["vt"] for c in labels]
        both_cnt = [agg[c]["both"] for c in labels]

        ha_only_cnt = [max(0, ha_cnt[i] - both_cnt[i]) for i in range(len(labels))]
        vt_only_cnt = [max(0, vt_cnt[i] - both_cnt[i]) for i in range(len(labels))]

        ha_pct = [v / total_samples * 100.0 for v in ha_cnt]
        vt_pct = [v / total_samples * 100.0 for v in vt_cnt]
        both_pct = [v / total_samples * 100.0 for v in both_cnt]

        ha_only_pct = [v / total_samples * 100.0 for v in ha_only_cnt]
        vt_only_pct = [v / total_samples * 100.0 for v in vt_only_cnt]

        n = len(labels)
        x_step = 1.35
        x = [i * x_step for i in range(n)]
        width = 0.36

        def plot_hist(values_ha, values_vt, ylabel, title, outfile: Path):
            plt.figure(figsize=(14, 5), dpi=140)

            plt.bar(
                [xi - width / 2 for xi in x],
                values_ha,
                width=width,
                label="HybridAnalysis",
                color=C_HA,
                alpha=ALPHA,
                edgecolor=EDGE,
                linewidth=0.6,
            )

            plt.bar(
                [xi + width / 2 for xi in x],
                values_vt,
                width=width,
                label="VirusTotal",
                color=C_VT,
                alpha=ALPHA,
                edgecolor=EDGE,
                linewidth=0.6,
            )

            plt.xticks(x, labels, rotation=0)
            plt.tick_params(axis="x", pad=8)
            plt.xlabel("Codes (ESB / R)")
            plt.ylabel(ylabel)
            plt.title(title)
            plt.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.35)
            plt.margins(x=0.02)
            plt.legend(loc="upper center", bbox_to_anchor=(0.5, 1.18), ncol=2, frameon=False)
            plt.subplots_adjust(top=0.80)
            plt.tight_layout()
            plt.savefig(outfile)
            plt.close()

        def plot_agreement(values_ha_only, values_vt_only, values_both, ylabel, title, outfile: Path):
            plt.figure(figsize=(14, 5), dpi=140)

            # Show provider agreement as three side-by-side bars per code.
            # Order: Hybrid Analysis only / Both providers / VirusTotal only.
            agreement_width = 0.28

            plt.bar(
                [xi - agreement_width for xi in x],
                values_ha_only,
                width=agreement_width,
                label="Hybrid Analysis only",
                color=C_HA_ONLY,
                alpha=ALPHA,
                edgecolor=EDGE,
                linewidth=0.6,
            )

            plt.bar(
                x,
                values_both,
                width=agreement_width,
                label="Both",
                color=C_BOTH,
                alpha=ALPHA,
                edgecolor=EDGE,
                linewidth=0.6,
            )

            plt.bar(
                [xi + agreement_width for xi in x],
                values_vt_only,
                width=agreement_width,
                label="VirusTotal only",
                color=C_VT_ONLY,
                alpha=ALPHA,
                edgecolor=EDGE,
                linewidth=0.6,
            )

            plt.xticks(x, labels, rotation=0)
            plt.tick_params(axis="x", pad=8)
            plt.xlabel("Codes (ESB / R)")
            plt.ylabel(ylabel)
            plt.title(title)
            plt.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.35)
            plt.margins(x=0.02)
            plt.legend(loc="upper center", bbox_to_anchor=(0.5, 1.18), ncol=3, frameon=False)
            plt.subplots_adjust(top=0.80)
            plt.tight_layout()
            plt.savefig(outfile)
            plt.close()

        plot_hist(
            ha_pct,
            vt_pct,
            "Percent of samples",
            f"{title_prefix} (n={total_samples}) - Frequency by source",
            out_dir / "eb_hist_pct.png",
        )

        plot_hist(
            ha_cnt,
            vt_cnt,
            "Count of samples",
            f"{title_prefix} (n={total_samples}) - Frequency by source",
            out_dir / "eb_hist_counts.png",
        )

        plot_agreement(
            ha_only_pct,
            vt_only_pct,
            both_pct,
            "Percent of samples",
            f"{title_prefix} (n={total_samples}) - Agreement by source",
            out_dir / "eb_agreement_pct.png",
        )

        plot_agreement(
            ha_only_cnt,
            vt_only_cnt,
            both_cnt,
            "Count of samples",
            f"{title_prefix} (n={total_samples}) - Agreement by source",
            out_dir / "eb_agreement_counts.png",
        )

    # -------------------------
    # Schema helpers
    # -------------------------
    def schema_key_for(d: Dict[str, Any]) -> str:
        rs = d.get("requirements_schema") or {}

        if isinstance(rs, builtins.dict) and rs.get("enabled") and rs.get("sha256"):
            return str(rs.get("sha256"))

        return ""

    def schema_folder_from_meta(rs: Dict[str, Any]) -> str:
        name = str(rs.get("name") or "requirements.json")
        h = str(rs.get("sha256") or "")[:8]
        stem = sanitize_folder_name(Path(name).stem)
        return f"req_{stem}__{h}"

    def write_aggregate_outputs(
        items: List[Tuple[Path, Dict[str, Any]]],
        base_out: Path,
        local_scope_desc: str,
        local_is_subset_mode: bool,
    ) -> Tuple[Path, int]:
        """
        Writes ESB-only plots and, when coherent, requirements plots.
        Returns:
          out_all path,
          number of requirements schema folders written.
        """
        labels_all, agg_all, n_all = aggregate_counts(
            items,
            include_requirements=False,
            req_codes_hint=[],
        )

        out_all = base_out / "all"

        plot_4(
            labels_all,
            agg_all,
            n_all,
            out_all,
            title_prefix=f"{local_scope_desc} | ESB-only",
        )
        write_stats_tables(
            labels_all,
            agg_all,
            n_all,
            out_all,
            title_prefix=f"{local_scope_desc} | ESB-only",
        )
        schema_hashes = [schema_key_for(d) for _, d in items]
        unique_schema_hashes = sorted(set(h for h in schema_hashes if h))

        wrote_schema_groups = 0

        if local_is_subset_mode:
            if len(unique_schema_hashes) == 1 and all(h == unique_schema_hashes[0] for h in schema_hashes):
                wanted = unique_schema_hashes[0]
                schema_items = [(p, d) for (p, d) in items if schema_key_for(d) == wanted]

                rs = (schema_items[0][1].get("requirements_schema") or {}) if schema_items else {}

                if isinstance(rs, builtins.dict) and rs.get("enabled") and rs.get("sha256"):
                    nreq = int(rs.get("count") or 0)
                    req_codes = [f"R{i}" for i in range(1, nreq + 1)] if nreq > 0 else []

                    labels_g, agg_g, n_g = aggregate_counts(
                        schema_items,
                        include_requirements=True,
                        req_codes_hint=req_codes,
                    )

                    out_g = base_out / schema_folder_from_meta(rs)

                    plot_4(
                        labels_g,
                        agg_g,
                        n_g,
                        out_g,
                        title_prefix=f"{local_scope_desc} | {rs.get('name', 'requirements')}",
                    )
                    write_stats_tables(
                        labels_g,
                        agg_g,
                        n_g,
                        out_g,
                        title_prefix=f"{local_scope_desc} | {rs.get('name', 'requirements')}",
                    )

                    wrote_schema_groups += 1
            else:
                c = Counter(schema_hashes)
                parts = []

                for k, v in c.items():
                    if not k:
                        parts.append(f"no_schema={v}")
                    else:
                        parts.append(f"{k[:12]}={v}")

                typer.echo(
                    "WARNING: Mixed or missing requirements schemas in this subset. "
                    "ESB-only plots were generated, but requirements plots are skipped. "
                    f"Scope={local_scope_desc}. "
                    f"Schema distribution: {', '.join(parts)}"
                )
        else:
            groups: Dict[str, List[Tuple[Path, Dict[str, Any]]]] = {}
            metas: Dict[str, Dict[str, Any]] = {}

            for p, d in items:
                rs = d.get("requirements_schema") or {}

                if isinstance(rs, builtins.dict) and rs.get("enabled") and rs.get("sha256"):
                    h = str(rs.get("sha256"))
                    groups.setdefault(h, []).append((p, d))
                    metas[h] = rs

            for h, schema_items in groups.items():
                rs = metas.get(h) or {}
                nreq = int(rs.get("count") or 0)
                req_codes = [f"R{i}" for i in range(1, nreq + 1)] if nreq > 0 else []

                labels_g, agg_g, n_g = aggregate_counts(
                    schema_items,
                    include_requirements=True,
                    req_codes_hint=req_codes,
                )

                out_g = base_out / schema_folder_from_meta(rs)

                plot_4(
                    labels_g,
                    agg_g,
                    n_g,
                    out_g,
                    title_prefix=f"{local_scope_desc} | {rs.get('name', 'requirements')}",
                )
                write_stats_tables(
                    labels_g,
                    agg_g,
                    n_g,
                    out_g,
                    title_prefix=f"{local_scope_desc} | {rs.get('name', 'requirements')}",
                )

                wrote_schema_groups += 1

        return out_all, wrote_schema_groups

    # -------------------------
    # Global aggregate
    # -------------------------
    is_subset_mode = bool(filter_set) or bool(sha_list) or bool(schema_filter_hash)

    base_out = rep_dir / "plots" / "aggregate" / scope_name

    out_all, wrote_schema_groups = write_aggregate_outputs(
        loaded,
        base_out,
        scope_desc,
        is_subset_mode,
    )

    typer.echo(f"Samples used: {len(loaded)} | Scope: {scope_desc}")
    typer.echo(f"Wrote ESB-only plots: {out_all}")

    if wrote_schema_groups:
        typer.echo(f"Wrote requirements plots: {base_out} (folders: {wrote_schema_groups})")
    else:
        typer.echo("No requirements plots written for global aggregate.")

    # -------------------------
    # OS-specific aggregate
    # -------------------------
    if by_os:
        try:
            orch = build_orchestrator()
            sha_to_os = _sha_to_target_os_from_db(orch.db)
        except Exception as e:
            typer.echo(f"WARNING: Could not load OS mapping from DB. Skipping --by-os. Reason: {e}")
            raise typer.Exit(code=0)

        grouped_by_os: Dict[str, List[Tuple[Path, Dict[str, Any]]]] = {
            "windows": [],
            "linux": [],
            "macos": [],
            "unknown": [],
        }

        for p, d in loaded:
            item_sha = p.stem.replace("eb_", "", 1)
            target_os = sha_to_os.get(item_sha, "unknown")
            grouped_by_os.setdefault(target_os, []).append((p, d))

        wrote_any_os = False

        for target_os, os_items in grouped_by_os.items():
            if not os_items:
                continue

            wrote_any_os = True

            os_base_out = rep_dir / "plots" / "aggregate" / "by_os" / target_os
            os_scope_desc = f"{scope_desc} | OS={target_os}"

            os_out_all, os_schema_groups = write_aggregate_outputs(
                os_items,
                os_base_out,
                os_scope_desc,
                is_subset_mode,
            )

            typer.echo(
                f"Wrote OS-specific ESB-only plots: {os_out_all} "
                f"(os={target_os}, n={len(os_items)})"
            )

            if os_schema_groups:
                typer.echo(
                    f"Wrote OS-specific requirements plots: {os_base_out} "
                    f"(os={target_os}, folders={os_schema_groups})"
                )

        if not wrote_any_os:
            typer.echo("WARNING: --by-os requested, but no OS-specific groups were generated.")



@app.command("run")
def run(
    path: str = typer.Argument(..., help="Path to the sample file to analyze."),
    reports_dir: str = typer.Option("reports", "--reports-dir", help="Base reports directory."),
    poll_every: int = typer.Option(10, "--poll-every", help="Polling interval seconds."),
    timeout_sec: int = typer.Option(900, "--timeout", help="Max seconds to wait for BOTH providers."),
    force: bool = typer.Option(
        False,
        "--force",
        help=(
            "Force resubmission and regenerate raw/normalized/enriched/eb outputs. "
            "Without --force, the command reuses DB submissions and existing output files when possible."
        ),
    ),
    requirements: str = typer.Option("", "--requirements", help="Optional custom requirements JSON."),
):
    """
    Full pipeline for ONE file.

    Default behavior:
      1) compute SHA256
      2) reuse existing VT/HA submissions from DB when available
      3) submit only missing/stale providers
      4) poll until BOTH providers are COMPLETED
      5) fetch raw reports
      6) normalize
      7) generate enriched + EB summary

    With --force:
      - resubmit to providers;
      - overwrite raw/normalized/enriched/eb outputs.
    """
    import time
    from pathlib import Path

    sample_path = Path(path)

    if not sample_path.exists():
        typer.echo(f"File not found: {sample_path}")
        raise typer.Exit(code=1)

    if not sample_path.is_file():
        typer.echo(f"Path is not a file: {sample_path}")
        raise typer.Exit(code=1)

    rep_dir = Path(reports_dir)
    _ensure_dir(rep_dir)

    sha256 = _sha256_of_file(sample_path)
    typer.echo(f"SHA256: {sha256}")

    final_eb_path = rep_dir / "eb" / f"eb_{sha256}.json"

    if final_eb_path.exists() and not force:
        typer.echo(f"[SKIP] Final EB report already exists: {final_eb_path}")
        typer.echo("Use --force to resubmit and regenerate outputs.")
        raise typer.Exit(code=0)

    orch = build_orchestrator()

    # 1) submit/resume
    try:
        asyncio.run(orch.submit(str(sample_path), force=force))
    except RuntimeError as e:
        typer.echo(f"[SKIP] {e}")
        raise typer.Exit(code=0)

    typer.echo("Submit/resume step completed.")

    # 2) poll loop
    start = time.time()
    last_print = 0.0

    while True:
        asyncio.run(orch.poll_once(sha256))

        statuses = _statuses_for_sha(orch.db, sha256)

        failed_services = [
            service
            for service, status in statuses.items()
            if str(status).upper() in {"FAILED", "ERROR"}
        ]

        if failed_services:
            typer.echo(f"Provider failed with terminal status: {failed_services}")
            typer.echo(f"Last status: {statuses}")
            raise typer.Exit(code=3)

        now = time.time()

        if now - last_print >= poll_every:
            vt_s = statuses.get("virustotal", "UNKNOWN")
            ha_s = statuses.get("hybridanalysis", "UNKNOWN")
            typer.echo(f"Status: VT={vt_s} | HA={ha_s}")
            last_print = now

        if _is_completed_both(statuses):
            typer.echo("Both providers COMPLETED.")
            break

        if now - start > timeout_sec:
            typer.echo("Timeout waiting for providers to complete.")
            typer.echo(f"Last status: {statuses}")
            raise typer.Exit(code=2)

        time.sleep(poll_every)

    # 3) report raw
    raw_path = _report_one(orch, sha256, rep_dir, force=force)
    typer.echo(f"Wrote raw: {raw_path}")

    # 4) normalize
    norm_path = _normalize_one(sha256, rep_dir, force=force)
    typer.echo(f"Wrote normalized: {norm_path}")

    # 5) EB enrichment + EB summary
    enr_path, eb_path = _eb_one(
        sha256,
        rep_dir,
        force=force,
        requirements=requirements,
    )

    typer.echo(f"Wrote enriched: {enr_path}")
    typer.echo(f"Wrote eb: {eb_path}")

    typer.echo("Done.")



if __name__ == "__main__":
    app()


