from dataclasses import dataclass, field
from typing import List
import time
from models import Parameter, XSSFinding

@dataclass
class ScanState:
    target_url: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    current_step: int = 0
    parameters: List[Parameter] = field(default_factory=list)
    findings: List[XSSFinding] = field(default_factory=list)
    status: str = "initialized"

    def mark_completed(self):
        self.end_time = time.time()
        self.status = "completed"

    @property
    def elapsed_seconds(self) -> float:
        end = self.end_time if self.end_time > 0 else time.time()
        return round(end - self.start_time, 2)
