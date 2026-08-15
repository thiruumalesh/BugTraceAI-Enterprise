from dataclasses import dataclass
from datetime import datetime


@dataclass
class ScanResult:
    scanner: str
    target: str
    severity: str
    title: str
    description: str
    evidence: str
    recommendation: str
    timestamp: str = datetime.now().isoformat()
