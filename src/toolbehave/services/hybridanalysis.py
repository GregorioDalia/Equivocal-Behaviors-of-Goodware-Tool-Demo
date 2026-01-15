import hashlib
import httpx
from typing import Any, Dict

HA_API = "https://hybrid-analysis.com/api/v2"

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

class HybridAnalysisClient:
    def __init__(self, api_key: str, user_agent: str = "Falcon Sandbox"):
        self.api_key = api_key
        self.user_agent = user_agent

    def _headers(self) -> Dict[str, str]:
        return {
            "accept": "application/json",
            "api-key": self.api_key,
            "user-agent": self.user_agent,
        }

    async def submit_file(self, file_path: str, environment_id: int = 160) -> Dict[str, Any]:
        sha = sha256_file(file_path)
        async with httpx.AsyncClient(timeout=120) as client:
            with open(file_path, "rb") as f:
                files = {"file": (file_path, f)}
                data = {
                    "environment_id": str(environment_id),
                    "allow_community_access": "true",
                }
                r = await client.post(f"{HA_API}/submit/file", headers=self._headers(), files=files, data=data)
            r.raise_for_status()
            j = r.json()

        external_id = j.get("job_id") or j.get("sha256") or sha
        return {"sha256": sha, "external_id": str(external_id), "status": "SUBMITTED", "raw": j}

    async def poll_status(self, sha256: str, external_id: str) -> Dict[str, Any]:
        """
        Usa lo stato del job direttamente:
        GET /report/{id}/state
        dove id = jobId oppure sha256:environmentId
        """
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{HA_API}/report/{external_id}/state", headers=self._headers())

            # se il report non è ancora indicizzato o non esiste, trattiamolo come in progress
            if r.status_code in (404, 410):
                return {"status": "IN_PROGRESS"}

            r.raise_for_status()
            j = r.json()

        # La risposta può cambiare un po' nel tempo; gestiamo in modo robusto
        raw_state = (
            j.get("state")
            or j.get("status")
            or j.get("verdict")  # a volte presente in altri oggetti
            or ""
        )
        state = str(raw_state).upper()

        # mapping "tollerante"
        if any(x in state for x in ["IN_PROGRESS", "RUN", "QUEUE", "PENDING", "START"]):
            return {"status": "IN_PROGRESS"}
        if any(x in state for x in ["SUCCESS", "DONE", "FINISH", "COMPLETE"]):
            return {"status": "COMPLETED"}
        if any(x in state for x in ["FAIL", "ERROR", "INVALID"]):
            return {"status": "FAILED", "error": f"HA state={raw_state}"}

        # fallback prudente
        return {"status": "IN_PROGRESS", "error": f"Unknown HA state payload: {j}"}

    async def fetch_report(self, sha256: str, external_id: str) -> Dict[str, Any]:
        """
        Report summary corretto:
        GET /report/{id}/summary
        dove id = jobId oppure sha256:environmentId
        """
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.get(f"{HA_API}/report/{external_id}/summary", headers=self._headers())

            if r.status_code in (404, 410):
                return {"error": f"Report not ready ({r.status_code})", "sha256": sha256, "id": external_id}

            r.raise_for_status()
            return r.json()

