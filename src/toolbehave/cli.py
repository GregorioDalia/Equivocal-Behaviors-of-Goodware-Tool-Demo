import asyncio
import json
from pathlib import Path
import typer
import time
import builtins


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


@app.command("eb-stats")
def eb_stats(
    reports_dir: str = "reports",
    sha=typer.Option(None, "--sha", help="Filter to a subset by repeating: --sha <sha> --sha <sha> ..."),
    sha_list: str = typer.Option("", "--sha-list", help="Path to a text file with one sha256 per line (subset)."),
    sha_single: str = typer.Option("", "--sha-single", help="Generate single-sample stats for this sha256."),
):
    """
    EB statistics.

    Modes:
      - Aggregate (default): all eb_<sha>.json files
      - Aggregate subset: use --sha (repeatable) OR --sha-list <file>
      - Single sample: use --sha-single <sha>

    Aggregate outputs (always):
      - Table in console (includes both pct and count columns)
      - 4 PNG files in reports/plots/aggregate/<scope>/:
          eb_hist_pct.png
          eb_hist_counts.png
          eb_agreement_pct.png
          eb_agreement_counts.png

        where <scope> is:
          - all                     (no filters)
          - <sha_list_filename_stem> (if --sha-list is used)
          - subset                  (if only --sha is used)

    Single-sample outputs:
      - Console table (EB detected + sources + matched_mitre counts)
      - 1 PNG in reports/plots/single/:
          eb_single_<sha_prefix>.png
    """
    import builtins
    import json
    import re
    from pathlib import Path
    from typing import Optional, List, Set, Dict, Any

    # Normalize --sha option into Optional[List[str]] (shadow-proof vs 'list')
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

    def load_canonical_codes() -> List[str]:
        resources_dir = Path("src/resources").resolve()
        code_map_path = resources_dir / "code_mappings.json"
        if not code_map_path.exists():
            typer.echo(f"Missing mapping file: {code_map_path}")
            raise typer.Exit(code=1)

        code_map = json.loads(code_map_path.read_text(encoding="utf-8"))
        if not isinstance(code_map, builtins.dict):
            typer.echo("code_mappings.json must be a JSON object (EB_NAME -> ESB_CODE).")
            raise typer.Exit(code=1)

        codes_set: Set[str] = set()
        for _, code in code_map.items():
            if isinstance(code, str) and code.strip():
                codes_set.add(code.strip())

        return sorted(codes_set, key=code_key)

    def load_eb_file(eb_path: Path) -> Dict[str, Any]:
        return json.loads(eb_path.read_text(encoding="utf-8"))

    # -------------------------
    # Locate EB directory
    # -------------------------
    rep_dir = Path(reports_dir)
    eb_dir = rep_dir / "eb"
    if not eb_dir.exists():
        typer.echo(f"EB directory not found: {eb_dir}. Run 'toolbehave eb-all' first.")
        raise typer.Exit(code=1)

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

        typer.echo(f"Single-sample EB report: {target}")
        headers = ["eb", "name", "sources", "ha_mitre_n", "vt_mitre_n"]
        out_rows: List[Dict[str, Any]] = []

        for e in ebs:
            if not isinstance(e, builtins.dict):
                continue

            code = str(e.get("code") or "").strip()
            name = str(e.get("name") or "").strip()

            srcs = e.get("sources_triggered") or []
            if not isinstance(srcs, builtins.list):
                srcs = []
            srcs_s = ",".join([str(x) for x in srcs])

            mm = e.get("matched_mitre") or {}
            if not isinstance(mm, builtins.dict):
                mm = {}

            ha_m = mm.get("hybridanalysis") or []
            vt_m = mm.get("virustotal") or []
            ha_n = len(ha_m) if isinstance(ha_m, builtins.list) else 0
            vt_n = len(vt_m) if isinstance(vt_m, builtins.list) else 0

            out_rows.append({
                "eb": code,
                "name": name,
                "sources": srcs_s,
                "ha_mitre_n": ha_n,
                "vt_mitre_n": vt_n,
            })

        out_rows.sort(key=lambda r: code_key(str(r["eb"])))

        # print table
        colw = {h: len(h) for h in headers}
        for r in out_rows:
            for h in headers:
                colw[h] = max(colw[h], len(str(r[h])))

        typer.echo("  ".join(h.ljust(colw[h]) for h in headers))
        typer.echo("-" * (sum(colw.values()) + 2 * (len(headers) - 1)))
        for r in out_rows:
            typer.echo("  ".join(str(r[h]).ljust(colw[h]) for h in headers))

        # plot detected EB (HA vs VT presence)
        try:
            import matplotlib.pyplot as plt  # type: ignore
        except Exception:
            typer.echo("matplotlib not available. Install with: pip install matplotlib")
            return

        plot_dir = rep_dir / "plots" / "single"
        plot_dir.mkdir(parents=True, exist_ok=True)

        labels = [str(r["eb"]) for r in out_rows if str(r["eb"]).strip()]
        if not labels:
            typer.echo("No EB detected for this sample; no plot generated.")
            return

        ha_vals = []
        vt_vals = []
        for r in out_rows:
            srcs = str(r["sources"]).split(",") if r["sources"] else []
            ha_vals.append(1 if "hybridanalysis" in srcs else 0)
            vt_vals.append(1 if "virustotal" in srcs else 0)

        n = len(labels)
        x_step = 1.35
        x = [i * x_step for i in range(n)]
        width = 0.36

        plt.rcParams.update({
            "font.size": 10,
            "axes.titlesize": 12,
            "axes.labelsize": 10,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
        })

        C_HA = "#1F77B4"
        C_VT = "#FF7F0E"
        EDGE = "#4D4D4D"
        ALPHA = 0.85

        plt.figure(figsize=(12, 4), dpi=140)
        plt.bar([xi - width / 2 for xi in x], ha_vals, width=width, label="HybridAnalysis",
                color=C_HA, alpha=ALPHA, edgecolor=EDGE, linewidth=0.6)
        plt.bar([xi + width / 2 for xi in x], vt_vals, width=width, label="VirusTotal",
                color=C_VT, alpha=ALPHA, edgecolor=EDGE, linewidth=0.6)

        plt.xticks(x, labels, rotation=0)
        plt.tick_params(axis="x", pad=8)
        plt.xlabel("Equivocal Behaviours (detected)")
        plt.ylabel("Present (1/0)")
        plt.ylim(0, 1.2)
        plt.title(f"EB detected by source (single sample) - {target[:10]}")
        plt.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.35)

        plt.legend(loc="upper center", bbox_to_anchor=(0.5, 1.18), ncol=2, frameon=False)
        plt.subplots_adjust(top=0.80)
        plt.tight_layout()

        outp = plot_dir / f"eb_single_{target[:10]}.png"
        plt.savefig(outp)
        plt.close()

        typer.echo(f"Wrote plot:\n- {outp}")
        return

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

    eb_files = sorted(eb_dir.glob("eb_*.json"))
    if filter_set:
        eb_files = [p for p in eb_files if p.stem.replace("eb_", "", 1) in filter_set]

    if not eb_files:
        typer.echo("No EB files found for the requested scope.")
        raise typer.Exit(code=0)

    canonical_codes = load_canonical_codes()

    # counts by EB code
    agg: Dict[str, Dict[str, int]] = {c: {"ha": 0, "vt": 0, "both": 0, "total": 0} for c in canonical_codes}

    total_samples = 0
    for p in eb_files:
        try:
            data = load_eb_file(p)
        except Exception as e:
            typer.echo(f"FAILED to read {p.name}: {e}")
            continue

        total_samples += 1
        ebs = data.get("equivocal_behaviours") or []
        if not isinstance(ebs, builtins.list):
            continue

        for e in ebs:
            if not isinstance(e, builtins.dict):
                continue
            code = e.get("code")
            if not isinstance(code, str) or not code.strip():
                continue
            code = code.strip()

            # allow future EB extensions beyond canonical list
            if code not in agg:
                agg[code] = {"ha": 0, "vt": 0, "both": 0, "total": 0}
                canonical_codes.append(code)
                canonical_codes.sort(key=code_key)

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

    if total_samples == 0:
        typer.echo("No valid EB samples found.")
        raise typer.Exit(code=0)

    # scope naming for folder
    if sha_list:
        scope_name = Path(sha_list).stem
    elif filter_set:
        scope_name = "subset"
    else:
        scope_name = "all"

    scope_desc = "ALL"
    if sha_list:
        scope_desc = f"SUBSET ({Path(sha_list).name})"
    elif filter_set:
        scope_desc = f"SUBSET (n={len(filter_set)})"

    # -------------------------
    # Console table includes both pct and count
    # -------------------------
    headers = ["eb", "ha_pct", "vt_pct", "both_pct", "total_pct", "ha_cnt", "vt_cnt", "both_cnt", "total_cnt"]
    table_rows: List[Dict[str, Any]] = []
    for c in canonical_codes:
        ha = agg[c]["ha"]
        vt = agg[c]["vt"]
        both = agg[c]["both"]
        tot = agg[c]["total"]
        table_rows.append({
            "eb": c,
            "ha_pct": ha / total_samples * 100.0,
            "vt_pct": vt / total_samples * 100.0,
            "both_pct": both / total_samples * 100.0,
            "total_pct": tot / total_samples * 100.0,
            "ha_cnt": ha,
            "vt_cnt": vt,
            "both_cnt": both,
            "total_cnt": tot,
        })

    def cell(r: Dict[str, Any], h: str) -> str:
        if h == "eb":
            return str(r[h])
        if h.endswith("_pct"):
            return f"{float(r[h]):.2f}"
        return str(int(r[h]))

    colw = {h: len(h) for h in headers}
    for r in table_rows:
        for h in headers:
            colw[h] = max(colw[h], len(cell(r, h)))

    typer.echo("  ".join(h.ljust(colw[h]) for h in headers))
    typer.echo("-" * (sum(colw.values()) + 2 * (len(headers) - 1)))
    for r in table_rows:
        typer.echo("  ".join(cell(r, h).ljust(colw[h]) for h in headers))

    typer.echo(f"\nSamples used: {total_samples} | Scope folder: aggregate/{scope_name} | Scope: {scope_desc}")
    typer.echo(f"EB files dir: {eb_dir}")

    # -------------------------
    # Plots: ALWAYS 4 files into reports/plots/aggregate/<scope_name>/
    # -------------------------
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        typer.echo("matplotlib not available. Install with: pip install matplotlib")
        return

    plot_dir = rep_dir / "plots" / "aggregate" / scope_name
    plot_dir.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update({
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
    })

    # colors
    C_HA = "#1F77B4"       # blue
    C_VT = "#FF7F0E"       # orange
    C_HA_ONLY = "#74C476"  # soft green
    C_VT_ONLY = "#FDAE6B"  # soft orange
    C_BOTH = "#9E9AC8"     # soft violet/grey
    EDGE = "#4D4D4D"
    ALPHA = 0.85

    labels = [r["eb"] for r in table_rows]
    ha_cnt = [agg[c]["ha"] for c in labels]
    vt_cnt = [agg[c]["vt"] for c in labels]
    both_cnt = [agg[c]["both"] for c in labels]

    ha_pct = [v / total_samples * 100.0 for v in ha_cnt]
    vt_pct = [v / total_samples * 100.0 for v in vt_cnt]
    both_pct = [v / total_samples * 100.0 for v in both_cnt]

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
        plt.xlabel("Equivocal Behaviours (EB codes)")
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
        plt.xlabel("Equivocal Behaviours (EB codes)")
        plt.ylabel(ylabel)
        plt.title(title)
        plt.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.35)
        plt.margins(x=0.02)
        plt.legend(loc="upper center", bbox_to_anchor=(0.5, 1.18), ncol=3, frameon=False)
        plt.subplots_adjust(top=0.80)
        plt.tight_layout()
        plt.savefig(outfile)
        plt.close()

    # agreement derived series
    ha_only_cnt = [max(0, ha_cnt[i] - both_cnt[i]) for i in range(n)]
    vt_only_cnt = [max(0, vt_cnt[i] - both_cnt[i]) for i in range(n)]

    ha_only_pct = [v / total_samples * 100.0 for v in ha_only_cnt]
    vt_only_pct = [v / total_samples * 100.0 for v in vt_only_cnt]

    # ALWAYS generate 4 files
    plot_hist(ha_pct, vt_pct, "Percent of samples", f"EB frequency by source ({scope_desc})",
              plot_dir / "eb_hist_pct.png")
    plot_hist(ha_cnt, vt_cnt, "Count of samples", f"EB frequency by source ({scope_desc})",
              plot_dir / "eb_hist_counts.png")

    plot_agreement(ha_only_pct, vt_only_pct, both_pct, "Percent of samples", f"EB agreement by source ({scope_desc})",
                   plot_dir / "eb_agreement_pct.png")
    plot_agreement(ha_only_cnt, vt_only_cnt, both_cnt, "Count of samples", f"EB agreement by source ({scope_desc})",
                   plot_dir / "eb_agreement_counts.png")

    typer.echo("Wrote plots to:")
    typer.echo(f"- {plot_dir / 'eb_hist_pct.png'}")
    typer.echo(f"- {plot_dir / 'eb_hist_counts.png'}")
    typer.echo(f"- {plot_dir / 'eb_agreement_pct.png'}")
    typer.echo(f"- {plot_dir / 'eb_agreement_counts.png'}")





