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

def extract_mitre_set_from_normalized(normalized: Dict[str, Any]) -> Set[str]:
    """
    Dal normalized report estrae tutte le technique IDs presenti come observations:
      { "type": "mitre", "name": "technique", "value": "T1059", ... }
    """
    out: Set[str] = set()
    obs = normalized.get("observations")
    if not isinstance(obs, list):
        return out

    for o in obs:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "mitre":
            continue
        if o.get("name") != "technique":
            continue
        v = o.get("value")
        if isinstance(v, str) and v.strip():
            out.add(v.strip().upper())

    return out


# -------------------------
# Matching
# -------------------------

def match_equivocal_behaviours(
    normalized: Dict[str, Any],
    rules: List[EBRule],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Ritorna:
      - lista di EB observations (presenti)
      - lista di EB observations (assenti) [opzionale, al momento vuota per semplicità]
    """
    mitre_set = extract_mitre_set_from_normalized(normalized)

    present: List[Dict[str, Any]] = []
    absent: List[Dict[str, Any]] = []

    for r in rules:
        matched = sorted(mitre_set.intersection(r.mitre_any))
        if matched:
            present.append({
                "type": "equivocal_behaviour",
                "category": "eb",
                "name": r.eb_code,                 # codice ESB1/ESB2...
                "value": True,
                "source": "toolbehave",
                "severity": "info",
                "meta": {
                    "eb_name": r.eb_name,
                    "match_mode": "any",
                    "matched_mitre": matched,
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
