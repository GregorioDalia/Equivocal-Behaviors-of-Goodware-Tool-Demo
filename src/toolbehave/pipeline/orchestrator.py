from toolbehave.db import DB
from toolbehave.models import Service
from toolbehave.services.virustotal import VirusTotalClient
from toolbehave.services.hybridanalysis import HybridAnalysisClient
import asyncio

class Orchestrator:
    def __init__(self, db: DB, vt: VirusTotalClient, ha: HybridAnalysisClient):
        self.db = db
        self.vt = vt
        self.ha = ha

    async def submit(self, file_path: str) -> None:
        vt_res = await self.vt.submit_file(file_path)
        self.db.upsert_file(vt_res["sha256"], file_path)
        self.db.upsert_submission(vt_res["sha256"], Service.VIRUSTOTAL.value, vt_res["external_id"], vt_res["status"])

        ha_res = await self.ha.submit_file(file_path, environment_id=160)
        self.db.upsert_file(ha_res["sha256"], file_path)
        self.db.upsert_submission(ha_res["sha256"], Service.HYBRIDANALYSIS.value, ha_res["external_id"], ha_res["status"])

    async def poll_once(self, sha256: str) -> None:
        vt_row = self.db.get_submission(sha256, Service.VIRUSTOTAL.value)
        if vt_row:
            res = await self.vt.poll_status(sha256, vt_row["external_id"])
            self.db.update_status(sha256, Service.VIRUSTOTAL.value, res["status"], res.get("error"))

        ha_row = self.db.get_submission(sha256, Service.HYBRIDANALYSIS.value)
        if ha_row:
            res = await self.ha.poll_status(sha256, ha_row["external_id"])
            self.db.update_status(sha256, Service.HYBRIDANALYSIS.value, res["status"], res.get("error"))

    async def fetch_reports(self, sha256: str) -> dict:
        out = {"sha256": sha256, "virustotal": None, "hybridanalysis": None}

        vt_row = self.db.get_submission(sha256, Service.VIRUSTOTAL.value)
        if vt_row:
            out["virustotal"] = await self.vt.fetch_report(sha256, vt_row["external_id"])

        ha_row = self.db.get_submission(sha256, Service.HYBRIDANALYSIS.value)
        if ha_row:
            out["hybridanalysis"] = await self.ha.fetch_report(sha256, ha_row["external_id"])

        return out

    async def poll_all_once(self) -> None:
        sha_list = self.db.list_sha256s()
        if not sha_list:
            return

        # Poll in parallelo per ogni sha (limitato dal numero di sha; per ora va bene)
        await asyncio.gather(*(self.poll_once(sha) for sha in sha_list))



