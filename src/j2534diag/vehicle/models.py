from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, List

@dataclass
class DTCInfo:
    code: str
    description: str
    status: str
    module: str
    freeze_frame: Dict[str, Any] = None
    timestamp: datetime = None

@dataclass
class ECUInfo:
    name: str
    address: int
    protocol:   
    supported_pids: List[int]
    vin: str = ""
    calibration_id: str = ""
