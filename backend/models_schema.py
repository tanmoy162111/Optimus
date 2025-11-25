from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime

@dataclass
class Vulnerability:
    name: str
    type: str  # sql_injection, xss, rce, etc.
    severity: float  # CVSS score 0-10
    confidence: float  # 0-1
    evidence: str
    location: str  # URL, parameter, file path
    tool: str  # Tool that found it
    exploitable: bool = False
    remediation: str = ""
    ml_classified: bool = False
    pattern_matched: bool = False

@dataclass
class ScanState:
    scan_id: str
    target: str
    phase: str  # Current pentesting phase
    status: str  # running, paused, completed, error
    start_time: datetime
    findings: List[Vulnerability] = field(default_factory=list)
    tools_executed: List[str] = field(default_factory=list)
    time_elapsed: int = 0  # seconds
    coverage: float = 0.0  # 0-1
    risk_score: float = 0.0
    ml_confidence: float = 0.5
    
    # Phase-specific state
    phase_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        return data

@dataclass
class ToolExecution:
    tool_name: str
    phase: str
    parameters: Dict[str, Any]
    start_time: datetime
    end_time: Optional[datetime] = None
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    vulnerabilities_found: List[Vulnerability] = field(default_factory=list)
    success: bool = False
    
    def to_dict(self):
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
        return data

@dataclass
class TrainingMetrics:
    model_name: str
    precision: float
    recall: float
    f1: float
    accuracy: float
    sample_count: int
    training_date: datetime
    
    def to_dict(self):
        data = asdict(self)
        data['training_date'] = self.training_date.isoformat()
        return data

@dataclass
class RLMetrics:
    avg_episode_reward: float
    episodes_trained: int
    vulnerability_discovery_rate: float
    resource_efficiency: float
    time_efficiency: float
    adaptation_score: float
    generalization: Dict[str, float]  # Per target type
