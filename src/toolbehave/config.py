from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()  # carica .env se presente

@dataclass(frozen=True)
class Settings:
    vt_api_key: str
    ha_api_key: str
    db_path: str = "toolbehave.sqlite3"

def get_settings() -> Settings:
    vt = os.getenv("VT_API_KEY", "").strip()
    ha = os.getenv("HA_API_KEY", "").strip()
    if not vt:
        raise RuntimeError("Missing VT_API_KEY env var")
    if not ha:
        raise RuntimeError("Missing HA_API_KEY env var")
    return Settings(vt_api_key=vt, ha_api_key=ha)
