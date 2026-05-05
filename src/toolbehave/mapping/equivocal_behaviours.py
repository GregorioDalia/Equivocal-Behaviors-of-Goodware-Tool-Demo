from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Optional


# -------------------------
# Paths (src/resources/.)
# -------------------------

def default_resources_dir() -> Path:
    """
    Risolve src/resources/ in modo robusto partendo da src/toolbehave/mapping/.
    """
    here = Path(__file__).resolve()
    # ./src/toolbehave/mapping/equivocal_behaviours.py
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
    mitre_any: Set[str]          # match ANY of these technique IDs


@dataclass(frozen=True)
class RequirementRule:
    req_name: str                # name from custom file (key)
    req_code: str                # "R1", "R2", ...
    mitre_any: Set[str]          # match ANY of these technique IDs


# -------------------------
# Load helpers
# -------------------------

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _to_tech_set(techniques: Any) -> Set[str]:
    """
    Normalize a list of technique IDs into an uppercase set.
    Accepts: list[str] only (anything else -> empty).
    """
    if not isinstance(techniques, list):
        return set()
    out: Set[str] = set()
    for t in techniques:
        if isinstance(t, str) and t.strip():
            out.add(t.strip().upper())
    return out

def _technique_with_parent(technique: str) -> Set[str]:
    """
    Return the observed MITRE technique together with its parent technique.

    Example:
      T1059.001 -> {"T1059.001", "T1059"}
      T1059     -> {"T1059"}

    This allows a rule defined on a parent technique, e.g. T1059,
    to match a more specific observed sub-technique, e.g. T1059.001.
    """
    t = technique.strip().upper()
    if not t:
        return set()

    out = {t}

    if "." in t:
        parent = t.split(".", 1)[0].strip()
        if parent:
            out.add(parent)

    return out


def _matched_observed_techniques(observed: Set[str], rule_techniques: Set[str]) -> List[str]:
    """
    Match observed MITRE techniques against rule techniques.

    The output keeps the observed technique IDs, not the expanded parent IDs.
    Example:
      observed={"T1059.001"}, rule_techniques={"T1059"}
      -> ["T1059.001"]
    """
    matched: List[str] = []

    for technique in observed:
        expanded = _technique_with_parent(technique)
        if expanded.intersection(rule_techniques):
            matched.append(technique)

    return sorted(matched)
# -------------------------
# Loaders (standard EB)
# -------------------------

def load_eb_rules(resources_dir: Path | None = None) -> List[EBRule]:
    """
    Legge:
      - code_mappings.json (EB name -> ESB code)
      - Comportamenti_Equivoci.json (EB name -> [Txxxx,])

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

        tech_set = _to_tech_set(techniques)
        if not tech_set:
            continue

        eb_code = code_map.get(eb_name)
        if not isinstance(eb_code, str) or not eb_code.strip():
            # fallback code: keeps tool usable but flags non-standard names
            eb_code = f"EB_{eb_name}".replace(" ", "_")[:40]

        rules.append(EBRule(eb_name=eb_name, eb_code=eb_code.strip(), mitre_any=tech_set))

    return rules


# -------------------------
# Loaders (custom Requirements)
# -------------------------

def load_requirement_rules(custom_requirements_path: Path) -> List[RequirementRule]:
    """
    Carica un JSON custom con struttura uguale a Comportamenti_Equivoci.json:
      {
        "Nome requisito 1": ["T1059", ...],
        "Nome requisito 2": ["T1497", ...],
        ...
      }

    e genera regole RequirementRule con codici sequenziali:
      R1, R2, R3, ... nell'ordine d'inserimento del JSON (Py3.7+ preserva l'ordine)
    """
    if not custom_requirements_path.exists():
        raise FileNotFoundError(f"Requirements file not found: {custom_requirements_path}")

    data = load_json(custom_requirements_path)
    if not isinstance(data, dict):
        raise ValueError("Requirements JSON must be an object: {name: [techniques]}")

    rules: List[RequirementRule] = []
    i = 1
    for req_name, techniques in data.items():
        if not isinstance(req_name, str):
            continue

        tech_set = _to_tech_set(techniques)
        if not tech_set:
            i += 1
            continue

        rules.append(RequirementRule(req_name=req_name, req_code=f"R{i}", mitre_any=tech_set))
        i += 1

    return rules


# -------------------------
# Feature extraction (from normalized)
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
# Matching (EB)
# -------------------------

def match_equivocal_behaviours(
    normalized: Dict[str, Any],
    rules: List[EBRule],
) -> List[Dict[str, Any]]:
    mitre_by_src = extract_mitre_by_source_from_normalized(normalized)
    mitre_vt = mitre_by_src.get("virustotal", set())
    mitre_ha = mitre_by_src.get("hybridanalysis", set())

    present: List[Dict[str, Any]] = []

    for r in rules:
        matched_vt = _matched_observed_techniques(mitre_vt, r.mitre_any)
        matched_ha = _matched_observed_techniques(mitre_ha, r.mitre_any)

        if not (matched_vt or matched_ha):
            continue

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

    return present


# -------------------------
# Matching (Requirements)
# -------------------------

def match_requirements(
    normalized: Dict[str, Any],
    rules: List[RequirementRule],
) -> List[Dict[str, Any]]:
    mitre_by_src = extract_mitre_by_source_from_normalized(normalized)
    mitre_vt = mitre_by_src.get("virustotal", set())
    mitre_ha = mitre_by_src.get("hybridanalysis", set())

    present: List[Dict[str, Any]] = []

    for r in rules:
        matched_vt = _matched_observed_techniques(mitre_vt, r.mitre_any)
        matched_ha = _matched_observed_techniques(mitre_ha, r.mitre_any)

        if not (matched_vt or matched_ha):
            continue

        sources_triggered = []
        if matched_ha:
            sources_triggered.append("hybridanalysis")
        if matched_vt:
            sources_triggered.append("virustotal")

        present.append({
            "type": "requirement",
            "category": "req",
            "name": r.req_code,        # R1, R2...
            "value": True,
            "source": "toolbehave",
            "severity": "info",
            "meta": {
                "req_name": r.req_name,
                "match_mode": "any",
                "matched_mitre": {
                    "hybridanalysis": matched_ha,
                    "virustotal": matched_vt,
                },
                "sources_triggered": sources_triggered,
            }
        })

    return present


# -------------------------
# Enrichment
# -------------------------

def enrich_normalized_with_eb(
    normalized: Dict[str, Any],
    eb_rules: List[EBRule],
    requirement_rules: Optional[List[RequirementRule]] = None,
) -> Dict[str, Any]:
    """
    Crea un nuovo oggetto enriched:
      - copia il normalized
      - aggiunge observations di tipo equivocal_behaviour
      - (opzionale) aggiunge observations di tipo requirement
      - NON modifica in-place il file normalized su disco
    """
    eb_present = match_equivocal_behaviours(normalized, eb_rules)
    req_present: List[Dict[str, Any]] = []
    if requirement_rules:
        req_present = match_requirements(normalized, requirement_rules)

    out = dict(normalized)

    obs = out.get("observations")
    if not isinstance(obs, list):
        obs = []
    else:
        obs = list(obs)

    # dedupe base su (type, category, name, value)
    seen = {(o.get("type"), o.get("category"), o.get("name"), str(o.get("value"))) for o in obs if isinstance(o, dict)}

    for o in eb_present + req_present:
        key = (o.get("type"), o.get("category"), o.get("name"), str(o.get("value")))
        if key in seen:
            continue
        seen.add(key)
        obs.append(o)

    out["observations"] = obs
    return out


# -------------------------
# Summary builders
# -------------------------

def _sources_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total": len(items),
        "hybridanalysis": sum(1 for e in items if "hybridanalysis" in (e.get("sources_triggered") or [])),
        "virustotal": sum(1 for e in items if "virustotal" in (e.get("sources_triggered") or [])),
        "both": sum(1 for e in items if set(e.get("sources_triggered") or []) == {"hybridanalysis", "virustotal"}),
    }


def build_eb_summary(enriched: Dict[str, Any]) -> Dict[str, Any]:
    """
    Estrae:
      - observation type=equivocal_behaviour => equivocal_behaviours[]
      - observation type=requirement        => requirements[]

    e costruisce un JSON compatto per reportistica/triage.
    """
    sha = enriched.get("sha256", "unknown")
    obs = enriched.get("observations")
    if not isinstance(obs, list):
        obs = []

    eb_list: List[Dict[str, Any]] = []
    req_list: List[Dict[str, Any]] = []

    for o in obs:
        if not isinstance(o, dict):
            continue

        otype = o.get("type")
        meta = o.get("meta") if isinstance(o.get("meta"), dict) else {}

        if otype == "equivocal_behaviour":
            eb_list.append({
                "code": o.get("name"),
                "name": meta.get("eb_name"),
                "sources_triggered": meta.get("sources_triggered", []),
                "matched_mitre": meta.get("matched_mitre", {"hybridanalysis": [], "virustotal": []}),
            })

        elif otype == "requirement":
            req_list.append({
                "code": o.get("name"),  # R1, R2...
                "name": meta.get("req_name"),
                "sources_triggered": meta.get("sources_triggered", []),
                "matched_mitre": meta.get("matched_mitre", {"hybridanalysis": [], "virustotal": []}),
            })

    # ordine stabile per diff / confronti
    eb_list.sort(key=lambda x: (str(x.get("code") or ""), str(x.get("name") or "")))
    req_list.sort(key=lambda x: (str(x.get("code") or ""), str(x.get("name") or "")))

    return {
        "sha256": sha,
        "equivocal_behaviours": eb_list,
        "requirements": req_list,
        "counts": _sources_counts(eb_list),
        "requirements_counts": _sources_counts(req_list),
    }
