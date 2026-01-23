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

@app.command("list")
def list_cmd():
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
        help="Optional custom requirements JSON (same structure as Comportamenti_Equivoci.json).",
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
            enriched = enrich_normalized_with_eb(normalized, eb_rules, req_rules)

            # Write enriched (unless exists and not force)
            if force or not enriched_path.exists():
                enriched_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
                generated_enriched += 1

            eb_summary = build_eb_summary(enriched)

            schema_meta = {"enabled": False}
            if requirements:
                schema_meta = _requirements_fingerprint(requirements)

            enriched["requirements_schema"] = schema_meta
            eb_summary["requirements_schema"] = schema_meta


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
    reports_dir: str = "reports",
    sha=typer.Option(None, "--sha", help="Filter subset by repeating: --sha <sha> --sha <sha> ..."),
    sha_list: str = typer.Option("", "--sha-list", help="Path to a text file with one sha256 per line (subset)."),
    sha_single: str = typer.Option("", "--sha-single", help="Single-sample mode for this sha256."),
    requirements: str = typer.Option("", "--requirements", help="Optional custom requirements JSON (used to FILTER to a specific schema in aggregate mode)."),
):
    """
    EB statistics.

    Aggregate (Soluzione A - schema isolation):
      - ALWAYS writes ESB-only plots into:
          reports/plots/aggregate/<scope>/all/
            eb_hist_pct.png, eb_hist_counts.png
            eb_agreement_pct.png, eb_agreement_counts.png
        (percent denominators = number of samples in current scope)

      - Requirements plots are written ONLY when schema is coherent:
          * For FULL dataset (no subset filters): one folder per schema found.
          * For SUBSET (via --sha / --sha-list):
                requirements plots are generated ONLY if all samples in subset share the same requirements schema
                (enabled + same sha256). Otherwise: warning, skip requirements plots.

      - Titles always include: n=<sample_count>
    """
    import builtins
    import json
    import re
    from pathlib import Path
    from typing import Optional, List, Set, Dict, Any, Tuple

    # ---- Shadow-proof normalization of --sha
    sha_values: Optional[List[str]]
    if sha is None:
        sha_values = None
    elif isinstance(sha, builtins.list):
        sha_values = [str(s) for s in sha]
    else:
        sha_values = [str(sha)]

    # -------------------------
    # Helpers
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
            raise ValueError("code_mappings.json must be a JSON object (EB_NAME -> ESB_CODE).")
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

    def write_text_table(path: Path, headers: List[str], rows: List[Dict[str, Any]]):
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
    # SINGLE SAMPLE MODE (unchanged behaviour: writes files, no console spam)
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
            rows.append({"code": code, "type": "EB", "sources": ",".join(str(s) for s in srcs), "ha_mitre_n": ha_n, "vt_mitre_n": vt_n})

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
            rows.append({"code": code, "type": "REQ", "sources": ",".join(str(s) for s in srcs), "ha_mitre_n": ha_n, "vt_mitre_n": vt_n})

        def sort_key(code: str):
            if code.startswith("ESB"):
                return (0, code_key(code))
            if code.startswith("R"):
                return (1, code_key(code))
            return (2, code)

        rows.sort(key=lambda r: sort_key(str(r["code"])))

        table_path = single_dir / "single_table.txt"
        write_text_table(table_path, headers, rows)

        try:
            import matplotlib.pyplot as plt  # type: ignore
        except Exception:
            typer.echo(f"Wrote single outputs (no matplotlib for PNG):\n- {table_path}")
            raise typer.Exit(code=0)

        colnames = ["HybridAnalysis", "VirusTotal"]
        # --- Build row codes for the PNG matrix ---
        # Always include ESB canonici
        row_codes = list(esb_codes)

        # Add requirements codes found in the eb_<sha>.json (robust even if --requirements not passed to eb-stats)
        req_codes_in_file = []
        for r_ in reqs:
            if isinstance(r_, dict):
                c = r_.get("code")
                if isinstance(c, str) and c.strip():
                    req_codes_in_file.append(c.strip())

        # keep order: R1, R2, ...
        def _rkey(c: str):
            import re
            m = re.search(r"(\d+)$", c)
            return int(m.group(1)) if m else 10 ** 9

        req_codes_in_file = sorted(set(req_codes_in_file), key=_rkey)

        row_codes.extend(req_codes_in_file)

        # --- Build matrix rows using row_codes ---
        matrix_rows = []
        for code in row_codes:
            srcs = present.get(code, set())
            matrix_rows.append([
                "X" if "hybridanalysis" in srcs else "",
                "X" if "virustotal" in srcs else "",
            ])

        # --- Render table ---
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

        plt.rcParams.update({"font.size": 10, "axes.titlesize": 12})
        fig, ax = plt.subplots(figsize=(6, max(4, 0.35 * len(row_codes))), dpi=160)
        ax.axis("off")

        tbl = ax.table(
            cellText=matrix_rows,
            rowLabels=row_codes,  # <-- FIX: labels must match matrix_rows
            colLabels=colnames,
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
    # AGGREGATE MODE (ALL or SUBSET)
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

    # If user provided --requirements in aggregate mode: filter to that schema hash
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
            if not (isinstance(rs, builtins.dict) and rs.get("enabled") and str(rs.get("sha256") or "") == schema_filter_hash):
                continue

        loaded.append((p, d))

    if not loaded:
        if schema_filter_hash:
            typer.echo(f"No EB files match the requested requirements schema: {schema_filter_name} ({schema_filter_hash[:12]})")
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

    plt.rcParams.update({
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
    })

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
        """
        Returns:
          labels,
          agg map {code: {ha,vt,both,total}},
          total_samples (LEN(items)) -> IMPORTANT denominator for percentages
        """
        total_samples = len(items)
        if total_samples <= 0:
            return [], {}, 0

        codes: List[str] = list(esb_codes)
        if include_requirements:
            codes += list(req_codes_hint)

        agg: Dict[str, Dict[str, int]] = {c: {"ha": 0, "vt": 0, "both": 0, "total": 0} for c in codes}

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
            plt.bar([xi - width / 2 for xi in x], values_ha, width=width, label="HybridAnalysis",
                    color=C_HA, alpha=ALPHA, edgecolor=EDGE, linewidth=0.6)
            plt.bar([xi + width / 2 for xi in x], values_vt, width=width, label="VirusTotal",
                    color=C_VT, alpha=ALPHA, edgecolor=EDGE, linewidth=0.6)
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
            plt.bar(x, values_ha_only, label="HA-only", color=C_HA_ONLY, alpha=ALPHA, edgecolor=EDGE, linewidth=0.6)
            bottoms = [values_ha_only[i] for i in range(len(x))]
            plt.bar(x, values_vt_only, bottom=bottoms, label="VT-only",
                    color=C_VT_ONLY, alpha=ALPHA, edgecolor=EDGE, linewidth=0.6)
            bottoms2 = [bottoms[i] + values_vt_only[i] for i in range(len(x))]
            plt.bar(x, values_both, bottom=bottoms2, label="Both",
                    color=C_BOTH, alpha=ALPHA, edgecolor=EDGE, linewidth=0.6)

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

        # IMPORTANT: titles contain n=<total_samples>
        plot_hist(
            ha_pct, vt_pct,
            "Percent of samples",
            f"{title_prefix} (n={total_samples}) - Frequency by source",
            out_dir / "eb_hist_pct.png"
        )
        plot_hist(
            ha_cnt, vt_cnt,
            "Count of samples",
            f"{title_prefix} (n={total_samples}) - Frequency by source",
            out_dir / "eb_hist_counts.png"
        )
        plot_agreement(
            ha_only_pct, vt_only_pct, both_pct,
            "Percent of samples",
            f"{title_prefix} (n={total_samples}) - Agreement by source",
            out_dir / "eb_agreement_pct.png"
        )
        plot_agreement(
            ha_only_cnt, vt_only_cnt, both_cnt,
            "Count of samples",
            f"{title_prefix} (n={total_samples}) - Agreement by source",
            out_dir / "eb_agreement_counts.png"
        )

    # -------------------------
    # Output base: aggregate/<scope>/
    # -------------------------
    base_out = rep_dir / "plots" / "aggregate" / scope_name

    # 1) ESB-only plots always (use current scope loaded -> denominator = len(loaded))
    labels_all, agg_all, n_all = aggregate_counts(
        loaded,
        include_requirements=False,
        req_codes_hint=[],
    )
    out_all = base_out / "all"
    plot_4(labels_all, agg_all, n_all, out_all, title_prefix=f"{scope_desc} | ESB-only")

    # -------------------------
    # Requirements plotting rules
    # -------------------------
    # Full dataset (no subset filters): can generate one folder per schema.
    # Subset (via --sha/--sha-list): generate requirements plots ONLY if schema is unique and shared by ALL items.
    is_subset_mode = bool(filter_set) or bool(sha_list) or bool(schema_filter_hash)

    # compute schema distribution over loaded
    def schema_key_for(d: Dict[str, Any]) -> str:
        rs = d.get("requirements_schema") or {}
        if isinstance(rs, builtins.dict) and rs.get("enabled") and rs.get("sha256"):
            return str(rs.get("sha256"))
        return ""  # empty means "no schema"

    schema_hashes = [schema_key_for(d) for _, d in loaded]
    unique_schema_hashes = sorted(set(h for h in schema_hashes if h))

    def schema_folder_from_meta(rs: Dict[str, Any]) -> str:
        name = str(rs.get("name") or "requirements.json")
        h = str(rs.get("sha256") or "")[:8]
        stem = sanitize_folder_name(Path(name).stem)
        return f"req_{stem}__{h}"

    wrote_schema_groups = 0

    if is_subset_mode:
        # In subset mode: requirements plots only if ALL have SAME non-empty schema hash
        if len(unique_schema_hashes) == 1 and all(h == unique_schema_hashes[0] for h in schema_hashes):
            wanted = unique_schema_hashes[0]
            # group items by that schema
            items = [(p, d) for (p, d) in loaded if schema_key_for(d) == wanted]
            # meta from first
            rs = (items[0][1].get("requirements_schema") or {}) if items else {}
            if isinstance(rs, builtins.dict) and rs.get("enabled") and rs.get("sha256"):
                nreq = int(rs.get("count") or 0)
                req_codes = [f"R{i}" for i in range(1, nreq + 1)] if nreq > 0 else []

                labels_g, agg_g, n_g = aggregate_counts(items, include_requirements=True, req_codes_hint=req_codes)
                out_g = base_out / schema_folder_from_meta(rs)
                plot_4(labels_g, agg_g, n_g, out_g, title_prefix=f"{scope_desc} | {rs.get('name','requirements')}")
                wrote_schema_groups += 1
        else:
            # WARNING + skip requirements plots
            # build counts for message
            from collections import Counter
            c = Counter(schema_hashes)
            # c[""] = no schema
            parts = []
            for k, v in c.items():
                if not k:
                    parts.append(f"no_schema={v}")
                else:
                    parts.append(f"{k[:12]}={v}")
            typer.echo(
                "WARNING: Mixed or missing requirements schemas in this subset. "
                "EB-only plots were generated, but requirements plots are skipped. "
                f"Schema distribution: {', '.join(parts)}"
            )
    else:
        # FULL dataset (no subset): generate one folder per schema found
        # group by schema sha256
        groups: Dict[str, List[Tuple[Path, Dict[str, Any]]]] = {}
        metas: Dict[str, Dict[str, Any]] = {}
        for p, d in loaded:
            rs = d.get("requirements_schema") or {}
            if isinstance(rs, builtins.dict) and rs.get("enabled") and rs.get("sha256"):
                h = str(rs.get("sha256"))
                groups.setdefault(h, []).append((p, d))
                metas[h] = rs

        for h, items in groups.items():
            rs = metas.get(h) or {}
            nreq = int(rs.get("count") or 0)
            req_codes = [f"R{i}" for i in range(1, nreq + 1)] if nreq > 0 else []
            labels_g, agg_g, n_g = aggregate_counts(items, include_requirements=True, req_codes_hint=req_codes)
            out_g = base_out / schema_folder_from_meta(rs)
            plot_4(labels_g, agg_g, n_g, out_g, title_prefix=f"{scope_desc} | {rs.get('name','requirements')}")
            wrote_schema_groups += 1

    typer.echo(f"Samples used: {len(loaded)} | Scope: {scope_desc}")
    typer.echo(f"Wrote ESB-only plots: {out_all}")
    if wrote_schema_groups:
        typer.echo(f"Wrote requirements plots: {base_out} (folders: {wrote_schema_groups})")
    else:
        typer.echo("No requirements plots written (none found or skipped due to mixed schemas).")



@app.command("run")
def run(
    path: str = typer.Argument(..., help="Path to the sample file to analyze."),
    reports_dir: str = typer.Option("reports", "--reports-dir", help="Base reports directory."),
    poll_every: int = typer.Option(10, "--poll-every", help="Polling interval seconds."),
    timeout_sec: int = typer.Option(900, "--timeout", help="Max seconds to wait for BOTH providers."),
    force: bool = typer.Option(False, "--force", help="Regenerate raw/normalized/enriched/eb for this sha."),
    requirements: str = typer.Option("", "--requirements", help="Optional custom requirements JSON."),
):
    """
    Full pipeline for ONE file:
      1) submit to VT + HA
      2) poll until BOTH COMPLETED (or timeout)
      3) write raw/<sha>
      4) write normalized/<sha>
      5) write enriched/<sha> + eb/<sha>

    Output:
      reports/raw/raw_<sha>.json
      reports/normalized/normalized_<sha>.json
      reports/enriched/enriched_<sha>.json
      reports/eb/eb_<sha>.json
    """
    import time
    from pathlib import Path

    sample_path = Path(path)
    if not sample_path.exists():
        typer.echo(f"File not found: {sample_path}")
        raise typer.Exit(code=1)

    rep_dir = Path(reports_dir)
    _ensure_dir(rep_dir)

    sha256 = _sha256_of_file(sample_path)
    typer.echo(f"SHA256: {sha256}")

    orch = build_orchestrator()

    # 1) submit
    asyncio.run(orch.submit(str(sample_path)))
    typer.echo("Submitted to VT + HA.")

    # 2) poll loop
    start = time.time()
    last_print = 0.0

    while True:
        asyncio.run(orch.poll_once(sha256))

        statuses = _statuses_for_sha(orch.db, sha256)
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

    # 5) EB enrichment + EB summary (includes optional requirements)
    enr_path, eb_path = _eb_one(sha256, rep_dir, force=force, requirements=requirements)
    typer.echo(f"Wrote enriched: {enr_path}")
    typer.echo(f"Wrote eb: {eb_path}")

    typer.echo("Done.")





