from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


# -------------------------
# Paths (src/resources/...)
# -------------------------

def default_resources_dir() -> Path:
    """
    Risolve src/resources/ in modo robusto partendo da src/toolbehave/mapping/...
    """
    here = Path(__file__).resolve()
    # .../src/toolbehave/mapping/equivocal_behaviours.py
    # parents[0]=mapping, [1]=toolbehave, [2]=src
    src_dir = here.parents[2]
    return src_dir / "resources"


# -------------------------
# Models
# -------------------------

@dataclass(frozen=True)
class EBRule:
    eb_name: str                 # es: "System Analysis and Resource Discovery"
    eb_code: str                 # es: "ESB1"
    mitre_any: Set[str]          # set di technique IDs, match "ANY"


# -------------------------
# Loaders
# -------------------------

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_eb_rules(resources_dir: Path | None = None) -> List[EBRule]:
    """
    Legge:
      - code_mappings.json (EB name -> ESB code)
      - Comportamenti_Equivoci.json (EB name -> [Txxxx,...])

    e costruisce una lista di regole EB basate su ANY(MITRE).
    """
    res_dir = resources_dir or default_resources_dir()

    code_map_path = res_dir / "code_mappings.json"
    eb_map_path = res_dir / "Comportamenti_Equivoci.json"

    if not code_map_path.exists():
        raise FileNotFoundError(f"Missing {code_map_path}")
    if not eb_map_path.exists():
        raise FileNotFoundError(f"Missing {eb_map_path}")

    code_map = load_json(code_map_path)
    eb_map = load_json(eb_map_path)

    if not isinstance(code_map, dict):
        raise ValueError("code_mappings.json must be a JSON object")
    if not isinstance(eb_map, dict):
        raise ValueError("Comportamenti_Equivoci.json must be a JSON object")

    rules: List[EBRule] = []

    for eb_name, techniques in eb_map.items():
        if not isinstance(eb_name, str):
            continue
        if not isinstance(techniques, list):
            continue

        eb_code = code_map.get(eb_name)
        if not isinstance(eb_code, str) or not eb_code.strip():
            # se manca il codice, manteniamo comunque una regola con fallback
            eb_code = f"EB_{eb_name}".replace(" ", "_")[:40]

        tech_set = set()
        for t in techniques:
            if isinstance(t, str) and t.strip():
                tech_set.add(t.strip().upper())

        if not tech_set:
            continue

        rules.append(EBRule(eb_name=eb_name, eb_code=eb_code.strip(), mitre_any=tech_set))

    return rules


# -------------------------
# Feature extraction (dal normalized)
# -------------------------

def extract_mitre_by_source_from_normalized(normalized: Dict[str, Any]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {"virustotal": set(), "hybridanalysis": set()}
    obs = normalized.get("observations")
    if not isinstance(obs, list):
        return out

    for o in obs:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "mitre" or o.get("name") != "technique":
            continue
        v = o.get("value")
        src = o.get("source")
        if isinstance(v, str) and v.strip() and isinstance(src, str):
            s = src.strip().lower()
            if s in out:
                out[s].add(v.strip().upper())

    return out



# -------------------------
# Matching
# -------------------------

def match_equivocal_behaviours(
    normalized: Dict[str, Any],
    rules: List[EBRule],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:

    mitre_by_src = extract_mitre_by_source_from_normalized(normalized)
    mitre_vt = mitre_by_src.get("virustotal", set())
    mitre_ha = mitre_by_src.get("hybridanalysis", set())

    present: List[Dict[str, Any]] = []
    absent: List[Dict[str, Any]] = []

    for r in rules:
        matched_vt = sorted(mitre_vt.intersection(r.mitre_any))
        matched_ha = sorted(mitre_ha.intersection(r.mitre_any))

        if matched_vt or matched_ha:
            sources_triggered = []
            if matched_ha:
                sources_triggered.append("hybridanalysis")
            if matched_vt:
                sources_triggered.append("virustotal")

            present.append({
                "type": "equivocal_behaviour",
                "category": "eb",
                "name": r.eb_code,
                "value": True,
                "source": "toolbehave",
                "severity": "info",
                "meta": {
                    "eb_name": r.eb_name,
                    "match_mode": "any",
                    "matched_mitre": {
                        "hybridanalysis": matched_ha,
                        "virustotal": matched_vt,
                    },
                    "sources_triggered": sources_triggered,
                }
            })

    return present, absent



def enrich_normalized_with_eb(
    normalized: Dict[str, Any],
    rules: List[EBRule],
) -> Dict[str, Any]:
    """
    Crea un nuovo oggetto enriched:
      - copia il normalized
      - aggiunge observations di tipo equivocal_behaviour
      - NON modifica in-place il file normalized su disco
    """
    present, _ = match_equivocal_behaviours(normalized, rules)

    out = dict(normalized)
    out["enriched_at"] = out.get("enriched_at")  # lasciamo spazio se vorrai aggiungere timestamp
    obs = out.get("observations")
    if not isinstance(obs, list):
        obs = []
    else:
        obs = list(obs)

    # dedupe base su (type, category, name, value)
    seen = {(o.get("type"), o.get("category"), o.get("name"), str(o.get("value"))) for o in obs if isinstance(o, dict)}
    for o in present:
        key = (o.get("type"), o.get("category"), o.get("name"), str(o.get("value")))
        if key in seen:
            continue
        seen.add(key)
        obs.append(o)

    out["observations"] = obs
    return out
def build_eb_summary(enriched: Dict[str, Any]) -> Dict[str, Any]:
    """
    Estrae SOLO le observation di tipo equivocal_behaviour dall'enriched report e
    costruisce un JSON compatto per reportistica/triage.
    """
    sha = enriched.get("sha256", "unknown")
    obs = enriched.get("observations")
    if not isinstance(obs, list):
        obs = []

    eb_list = []
    for o in obs:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "equivocal_behaviour":
            continue

        meta = o.get("meta") if isinstance(o.get("meta"), dict) else {}
        eb_list.append({
            "code": o.get("name"),
            "name": meta.get("eb_name"),
            "sources_triggered": meta.get("sources_triggered", []),
            "matched_mitre": meta.get("matched_mitre", {"hybridanalysis": [], "virustotal": []}),
        })

    # ordine stabile per diff / confronti
    eb_list.sort(key=lambda x: (str(x.get("code") or ""), str(x.get("name") or "")))

    return {
        "sha256": sha,
        "equivocal_behaviours": eb_list,
        "counts": {
            "total": len(eb_list),
            "hybridanalysis": sum(1 for e in eb_list if "hybridanalysis" in (e.get("sources_triggered") or [])),
            "virustotal": sum(1 for e in eb_list if "virustotal" in (e.get("sources_triggered") or [])),
            "both": sum(1 for e in eb_list if set(e.get("sources_triggered") or []) == {"hybridanalysis", "virustotal"}),
        }
    }
