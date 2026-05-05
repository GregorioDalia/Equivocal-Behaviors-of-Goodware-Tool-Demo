from toolbehave.db import DB
from toolbehave.models import Service
from toolbehave.services.virustotal import VirusTotalClient
from toolbehave.services.hybridanalysis import HybridAnalysisClient
from pathlib import Path
import asyncio

class Orchestrator:
    def __init__(self, db: DB, vt: VirusTotalClient, ha: HybridAnalysisClient):
        self.db = db
        self.vt = vt
        self.ha = ha
    def detect_ha_environment_id(self, file_path: str) -> int:
        """
        Select the Hybrid Analysis environment ID according to the input file type.

        PE     -> Windows 11 64 bit      -> 140
        ELF    -> Linux Ubuntu 24.04     -> 330
        Mach-O -> macOS Tahoe ARM64      -> 430
        """
        path = Path(file_path)

        if not path.is_file():
            raise FileNotFoundError(f"Input file not found: {path}")

        with path.open("rb") as f:
            header = f.read(4)

        # ELF
        if header == b"\x7fELF":
            return 330

        # Mach-O / Universal binary
        macho_magics = {
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        }

        if header in macho_magics:
            return 430

        # PE: starts with MZ, then PE signature at offset stored at 0x3C
        if header[:2] == b"MZ":
            with path.open("rb") as f:
                f.seek(0x3C)
                offset_bytes = f.read(4)

                if len(offset_bytes) == 4:
                    pe_offset = int.from_bytes(offset_bytes, byteorder="little", signed=False)
                    f.seek(pe_offset)
                    pe_signature = f.read(4)

                    if pe_signature == b"PE\x00\x00":
                        return 140

        raise ValueError(
            f"Unsupported file type for Hybrid Analysis environment selection: {path}"
        )

    async def submit(self, file_path: str) -> None:
        ha_environment_id = self.detect_ha_environment_id(file_path)

        vt_res = await self.vt.submit_file(file_path)
        self.db.upsert_file(vt_res["sha256"], file_path)
        self.db.upsert_submission(
            vt_res["sha256"],
            Service.VIRUSTOTAL.value,
            vt_res["external_id"],
            vt_res["status"],
        )

        ha_res = await self.ha.submit_file(file_path, environment_id=ha_environment_id)
        self.db.upsert_file(ha_res["sha256"], file_path)
        self.db.upsert_submission(
            ha_res["sha256"],
            Service.HYBRIDANALYSIS.value,
            ha_res["external_id"],
            ha_res["status"],
        )

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



