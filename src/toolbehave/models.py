from dataclasses import dataclass
from enum import Enum
from typing import Optional

class Service(str, Enum):
    VIRUSTOTAL = "virustotal"
    HYBRIDANALYSIS = "hybridanalysis"

class Status(str, Enum):
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

@dataclass
class Submission:
    file_path: str
    sha256: str
    service: Service
    external_id: str
    status: Status
    error: Optional[str] = None
