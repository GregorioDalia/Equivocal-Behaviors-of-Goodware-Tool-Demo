import hashlib
import httpx
from typing import Any, Dict

VT_API = "https://www.virustotal.com/api/v3"

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    async def submit_file(self, file_path: str) -> Dict[str, Any]:
        sha = sha256_file(file_path)
        async with httpx.AsyncClient(timeout=60) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path, f)}
                r = await client.post(f"{VT_API}/files", headers=self._headers(), files=files)
            r.raise_for_status()
            data = r.json()
        external_id = data["data"]["id"]  # analysis id
        return {"sha256": sha, "external_id": external_id, "status": "SUBMITTED"}

    async def poll_status(self, sha256: str, external_id: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{VT_API}/analyses/{external_id}", headers=self._headers())
            r.raise_for_status()
            j = r.json()

        status = j["data"]["attributes"]["status"]  # queued / in-progress / completed
        if status == "completed":
            return {"status": "COMPLETED"}
        if status in ("queued", "in-progress"):
            return {"status": "IN_PROGRESS"}
        return {"status": "FAILED", "error": f"Unexpected VT status: {status}"}


    async def fetch_behaviour_summary(self, sha256: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{VT_API}/files/{sha256}/behaviour_summary", headers=self._headers())
            if r.status_code in (403, 404):
                return {"error": f"VT behaviour_summary not available ({r.status_code})"}
            r.raise_for_status()
            return r.json()

    async def fetch_behaviour_mitre_trees(self, sha256: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{VT_API}/files/{sha256}/behaviour_mitre_trees", headers=self._headers())
            if r.status_code in (403, 404):
                return {"error": f"VT behaviour_mitre_trees not available ({r.status_code})"}
            r.raise_for_status()
            return r.json()

    async def fetch_report(self, sha256: str, external_id: str) -> Dict[str, Any]:
        # 1) file report “classico”
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{VT_API}/files/{sha256}", headers=self._headers())
            r.raise_for_status()
            file_report = r.json()

        # 2) behaviour (best-effort: se non disponibile non falliamo)
        behaviour_summary = await self.fetch_behaviour_summary(sha256)
        behaviour_mitre = await self.fetch_behaviour_mitre_trees(sha256)

        # 3) ritorniamo un oggetto unico (così il normalizer lo trova facilmente)
        file_report["behaviour_summary"] = behaviour_summary
        file_report["behaviour_mitre_trees"] = behaviour_mitre
        return file_report
