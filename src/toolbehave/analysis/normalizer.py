from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# -------------------------
# Helpers (robusti)
# -------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get(d: Any, path: List[str], default=None):
    """Safe nested get: _get(obj, ["a","b","c"])"""
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _first_non_empty(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return None


def _overall_verdict(labels: List[str]) -> str:
    """
    Regola conservativa e spiegabile:
    malicious > suspicious > benign > unknown
    """
    order = {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}
    best = "unknown"
    for l in labels:
        l = (l or "unknown").lower()
        if l not in order:
            l = "unknown"
        if order[l] > order[best]:
            best = l
    return best


def _severity_from_level(level: Any) -> str:
    """
    Mappa a un set chiuso: info/low/medium/high
    Molti provider usano numeri o stringhe.
    """
    if level is None:
        return "info"
    if isinstance(level, (int, float)):
        if level >= 8:
            return "high"
        if level >= 5:
            return "medium"
        if level >= 2:
            return "low"
        return "info"
    s = str(level).lower()
    if "high" in s or "severe" in s or "critical" in s:
        return "high"
    if "med" in s:
        return "medium"
    if "low" in s:
        return "low"
    return "info"

def _is_public_ip(s: str) -> bool:
    # check minimale: se vuoi, raffiniamo dopo
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    # filtra localhost e private ranges più comuni
    if nums[0] == 127:
        return False
    if nums[0] == 10:
        return False
    if nums[0] == 192 and nums[1] == 168:
        return False
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return False
    return True


def _add_ioc(obs: List[Dict[str, Any]], kind: str, value: str, source: str, severity: str = "info"):
    v = (value or "").strip()
    if not v:
        return
    obs.append({
        "type": "ioc",
        "category": "network",
        "name": kind,          # "domain" | "ip" | "url"
        "value": v,
        "source": source,
        "severity": severity,
    })
import re

_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

def _extract_technique_ids(obj: Any, limit: int = 300) -> List[str]:
    """
    Estrae technique IDs (Txxxx o Txxxx.xxx) da:
    - liste/dict con campi 'technique', 'technique_id', 'id'
    - oppure testo libero
    """
    found: List[str] = []

    def add(x: str):
        for m in _TECH_RE.findall(x or ""):
            found.append(m)

    def walk(x: Any):
        if len(found) >= limit:
            return
        if isinstance(x, str):
            add(x)
        elif isinstance(x, dict):
            # pattern comuni
            for k in ("technique_id", "technique", "id", "mitre", "attck", "attack"):
                v = x.get(k)
                if isinstance(v, str):
                    add(v)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for it in x:
                walk(it)

    walk(obj)

    # dedupe preservando ordine
    seen = set()
    out = []
    for t in found:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
def _add_mitre(obs: List[Dict[str, Any]], technique_id: str, source: str, severity: str = "info"):
    t = (technique_id or "").strip()
    if not t:
        return
    obs.append({
        "type": "mitre",
        "category": "tactic",
        "name": "technique",
        "value": t,
        "source": source,
        "severity": severity,
    })


# -------------------------
# Extractors
# -------------------------

def extract_virustotal(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Estrae: identity, verdict, observations (incluso MITRE) in forma uniforme.

    Input atteso: raw['virustotal'] è il JSON che noi salviamo come report VT.
    Con il patch lato API, dentro vt avremo anche:
      - vt['behaviour_mitre_trees']  (GET /files/{sha}/behaviour_mitre_trees)
      - vt['behaviour_summary']      (GET /files/{sha}/behaviour_summary)

    Logica verdict:
      - se malware_classification è CLEAN -> benign
      - se malware/malicious -> malicious
      - fallback su last_analysis_stats:
            malicious > 0 -> malicious
            suspicious > 0 -> suspicious
            altrimenti -> benign
    """
    vt = raw.get("virustotal")
    if not isinstance(vt, dict):
        return {
            "present": False,
            "identity": {},
            "verdict": {"label": "unknown", "score": None},
            "observations": [],
        }

    attrs = _get(vt, ["data", "attributes"], {}) or {}

    # -------------------------
    # Identity (minimale)
    # -------------------------
    size = attrs.get("size")
    type_desc = attrs.get("type_description") or attrs.get("type_tag")
    names = attrs.get("names") or []
    file_name = names[0] if isinstance(names, list) and names else None

    identity = {
        "file_name": file_name,
        "file_type": type_desc,
        "size": size,
    }

    # -------------------------
    # Verdict
    # -------------------------
    vt_class = attrs.get("malware_classification") or attrs.get("popular_threat_classification")
    label = "unknown"

    if isinstance(vt_class, str):
        c = vt_class.strip().upper()
        if c == "CLEAN":
            label = "benign"
        elif c in ("MALWARE", "MALICIOUS"):
            label = "malicious"

    stats = attrs.get("last_analysis_stats") or {}
    malicious_count = stats.get("malicious")
    suspicious_count = stats.get("suspicious")

    if isinstance(malicious_count, int) and isinstance(suspicious_count, int):
        if malicious_count > 0:
            label = "malicious"
        elif suspicious_count > 0 and label != "malicious":
            label = "suspicious"
        elif malicious_count == 0 and suspicious_count == 0 and label == "unknown":
            label = "benign"

    verdict = {"label": label, "score": None}

    # -------------------------
    # Observations
    # -------------------------
    obs: List[Dict[str, Any]] = []

    # Engine stats -> metriche utili
    if isinstance(malicious_count, int):
        obs.append({
            "type": "metric",
            "category": "static",
            "name": "vt_malicious_engines",
            "value": malicious_count,
            "source": "virustotal",
            "severity": "info" if malicious_count == 0 else "medium",
        })
    if isinstance(suspicious_count, int):
        obs.append({
            "type": "metric",
            "category": "static",
            "name": "vt_suspicious_engines",
            "value": suspicious_count,
            "source": "virustotal",
            "severity": "info" if suspicious_count == 0 else "low",
        })

    if type_desc:
        obs.append({
            "type": "tag",
            "category": "static",
            "name": "file_type",
            "value": type_desc,
            "source": "virustotal",
            "severity": "info",
        })

    if file_name:
        obs.append({
            "type": "tag",
            "category": "static",
            "name": "file_name",
            "value": file_name,
            "source": "virustotal",
            "severity": "info",
        })

    # -------------------------
    # MITRE (preferisci behaviour_mitre_trees)
    # -------------------------
    vt_behaviour_mitre = vt.get("behaviour_mitre_trees")
    vt_mitre_error = None
    if isinstance(vt_behaviour_mitre, dict) and "error" in vt_behaviour_mitre:
        vt_mitre_error = str(vt_behaviour_mitre.get("error"))

    if isinstance(vt_behaviour_mitre, dict) and not vt_mitre_error:
        vt_techs = _extract_technique_ids(vt_behaviour_mitre, limit=300)
        for tid in vt_techs:
            _add_mitre(obs, tid, "virustotal")
    else:
        # fallback: prova ad estrarre technique ids "in giro" (di solito vuoto, ma non rompe)
        vt_techs = _extract_technique_ids(attrs, limit=200)
        for tid in vt_techs:
            _add_mitre(obs, tid, "virustotal")

    # -------------------------
    # IOC (best-effort)
    # - Se behaviour_summary include url/domains (dipende dal piano/endpoint), li estraiamo.
    # -------------------------
    vt_behaviour_summary = vt.get("behaviour_summary")
    if isinstance(vt_behaviour_summary, dict) and "error" not in vt_behaviour_summary:
        # alcuni payload possono contenere liste con nomi evidenti
        for key, kind in [
            ("domains", "domain"),
            ("domain", "domain"),
            ("urls", "url"),
            ("url", "url"),
            ("ip_addresses", "ip"),
            ("ips", "ip"),
            ("hosts", "domain"),
        ]:
            v = vt_behaviour_summary.get(key)
            if isinstance(v, list):
                for item in v[:200]:
                    if isinstance(item, str):
                        _add_ioc(obs, kind, item, "virustotal")
            elif isinstance(v, str):
                _add_ioc(obs, kind, v, "virustotal")

    return {
        "present": True,
        "identity": identity,
        "verdict": verdict,
        "observations": obs,
    }



def extract_hybridanalysis(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Estrae: identity, verdict, observations in forma uniforme.
    Supporta HA /report/{id}/summary response.

    Logica verdict:
    1) Se esiste un punteggio numerico (threat_score o threat_level), usa soglie:
       >= 70 => malicious
       >= 20 => suspicious
       < 20  => benign
    2) Altrimenti fallback su stringhe nel verdict/classification.
    """
    ha = raw.get("hybridanalysis")
    if not isinstance(ha, dict):
        return {
            "present": False,
            "identity": {},
            "verdict": {"label": "unknown", "score": None},
            "observations": [],
            "job_id": None,
        }

    verdict_raw = ha.get("verdict") or ha.get("classification") or ha.get("analysis_result")

    threat_level = ha.get("threat_level")
    threat_score = ha.get("threat_score")

    # -------------------------
    # Verdict (robusto)
    # -------------------------
    label = "unknown"
    score_num: Optional[float] = None

    if isinstance(threat_score, (int, float)):
        score_num = float(threat_score)
    elif isinstance(threat_level, (int, float)):
        score_num = float(threat_level)

    if score_num is not None:
        if score_num >= 70:
            label = "malicious"
        elif score_num >= 20:
            label = "suspicious"
        else:
            label = "benign"
    else:
        if verdict_raw is not None:
            s = str(verdict_raw).lower()
            if "benign" in s or "clean" in s:
                label = "benign"
            elif "malicious" in s or "malware" in s:
                label = "malicious"
            elif "suspicious" in s:
                label = "suspicious"

    # -------------------------
    # Observations
    # -------------------------
    obs: List[Dict[str, Any]] = []

    # Metriche utili (se presenti)
    metric_map = [
        ("total_network_connections", "ha_total_network_connections", "dynamic"),
        ("total_processes", "ha_total_processes", "dynamic"),
        ("total_signatures", "ha_total_signatures", "static"),
    ]

    for key, out_name, cat in metric_map:
        v = ha.get(key)
        if isinstance(v, int):
            obs.append({
                "type": "metric",
                "category": cat,
                "name": out_name,
                "value": v,
                "source": "hybridanalysis",
                "severity": "info",
            })

    # signatures/indicators (limite per non esplodere il JSON)
    sigs = ha.get("signatures")
    if isinstance(sigs, list):
        for sig in sigs[:200]:
            if not isinstance(sig, dict):
                continue
            sig_name = sig.get("name") or sig.get("signature") or sig.get("title")
            if not sig_name:
                continue
            sev = _severity_from_level(sig.get("severity") or sig.get("level") or sig.get("score"))
            obs.append({
                "type": "indicator",
                "category": "dynamic",
                "name": str(sig_name).strip().lower().replace(" ", "_")[:80],
                "value": True,
                "source": "hybridanalysis",
                "severity": sev,
            })

    # Identity minimale
    file_name = ha.get("submit_name") or ha.get("file_name")
    file_type = ha.get("type") or ha.get("file_type")
    size = ha.get("size")

    # -------------------------
    # IOC extraction (se presenti nel summary)
    # -------------------------
    # Alcuni summary HA includono liste tipo "domains", "hosts", "urls" o simili.
    domains = ha.get("domains")
    if isinstance(domains, list):
        for d in domains[:200]:
            if isinstance(d, str):
                _add_ioc(obs, "domain", d, "hybridanalysis")

    urls = ha.get("urls")
    if isinstance(urls, list):
        for u in urls[:200]:
            if isinstance(u, str):
                _add_ioc(obs, "url", u, "hybridanalysis")

    hosts = ha.get("hosts") or ha.get("ips") or ha.get("ip_addresses")
    if isinstance(hosts, list):
        for h in hosts[:200]:
            if isinstance(h, str) and _is_public_ip(h):
                _add_ioc(obs, "ip", h, "hybridanalysis")

    # -------------------------
    # MITRE extraction (best-effort)
    # -------------------------
    # Hybrid Analysis spesso include mitre in campi tipo 'mitre_attcks' o dentro signatures/summary.
    mitre_blob = ha.get("mitre_attcks") or ha.get("mitre_attacks") or ha.get("mitre") or ha.get("attck") or ha.get("attack")
    techs = _extract_technique_ids(mitre_blob, limit=300)

    # fallback: prova a scavare anche nelle signatures se non hai trovato nulla
    if not techs and isinstance(sigs, list):
        techs = _extract_technique_ids(sigs, limit=300)

    for tid in techs:
        _add_mitre(obs, tid, "hybridanalysis")

    return {
        "present": True,
        "job_id": ha.get("job_id") or ha.get("id"),
        "identity": {
            "file_name": file_name,
            "file_type": file_type,
            "size": size,
        },
        "verdict": {"label": label, "score": score_num},
        "observations": obs,
    }




# -------------------------
# Normalizer (merge)
# -------------------------

def normalize_report(raw_report: Dict[str, Any], sha256: Optional[str] = None, ha_job_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Crea un normalized report stabile.
    """
    sha = sha256 or raw_report.get("sha256") or raw_report.get("hash") or "unknown"

    vt = extract_virustotal(raw_report)
    ha = extract_hybridanalysis(raw_report)

    # sources metadata
    sources = {
        "virustotal": {"present": bool(vt.get("present"))},
        "hybridanalysis": {
            "present": bool(ha.get("present")),
            "job_id": _first_non_empty(ha_job_id, ha.get("job_id")),
        },
    }

    # identity: scegliamo valori migliori (priorità VT per tipo/size spesso più consistente, ma fallback HA)
    identity = {
        "file_name": _first_non_empty(vt["identity"].get("file_name"), ha["identity"].get("file_name")),
        "file_type": _first_non_empty(vt["identity"].get("file_type"), ha["identity"].get("file_type")),
        "size": _first_non_empty(vt["identity"].get("size"), ha["identity"].get("size")),
    }

    # verdict
    vt_label = vt["verdict"]["label"]
    ha_label = ha["verdict"]["label"]
    overall = _overall_verdict([vt_label, ha_label])

    verdict = {
        "virustotal": vt["verdict"],
        "hybridanalysis": ha["verdict"],
        "overall": overall,
    }

    # observations: concat + dedupe base
    obs_all = (vt.get("observations") or []) + (ha.get("observations") or [])
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for o in obs_all:
        key = (o.get("type"), o.get("category"), o.get("name"), str(o.get("value")), o.get("source"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(o)

    return {
        "sha256": sha,
        "generated_at": _now_iso(),
        "sources": sources,
        "identity": identity,
        "verdict": verdict,
        "observations": deduped,
    }
