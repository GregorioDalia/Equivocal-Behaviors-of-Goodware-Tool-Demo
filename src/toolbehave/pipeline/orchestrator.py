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
        Select the Hybrid Analysis environment ID according to the file extension.

        Windows PE-like files -> Windows 11 64 bit      -> 140
        ELF/Linux files       -> Linux Ubuntu 24.04     -> 330
        macOS files           -> macOS Tahoe ARM64      -> 430
        """
        suffix = Path(file_path).suffix.lower()

        windows_extensions = {
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".ocx",
            ".cpl",
            ".drv",
            ".efi",
            ".msi",
        }

        linux_extensions = {
            ".elf",
            ".so",
            ".bin",
            ".run",
            ".out",
        }

        macos_extensions = {
            ".macho",
            ".dylib",
            ".app",
            ".pkg",
            ".dmg",
        }

        if suffix in windows_extensions:
            print("[DEBUG] Selected HA environment_id=140 for Windows/PE extension", flush=True)
            return 140

        if suffix in linux_extensions:
            print("[DEBUG] Selected HA environment_id=330 for Linux/ELF extension", flush=True)
            return 330

        if suffix in macos_extensions:
            print("[DEBUG] Selected HA environment_id=430 for macOS extension", flush=True)
            return 430

        raise ValueError(
            f"Unsupported file extension for Hybrid Analysis environment selection: {suffix or '[no extension]'}"
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
            environment_id=ha_environment_id,
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



