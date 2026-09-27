"""Core data models for the MFA Security Assessment Tool."""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
 

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    nist_ref: str = ""
    owasp_ref: str = ""
    cwe_ref: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    auth_type: str = "unknown"
    mfa_indicators: List[str] = field(default_factory=list)
    status_code: Optional[int] = None


@dataclass
class AssessmentResult:
    target: str
    scan_started: datetime
    scan_finished: Optional[datetime] = None
    endpoints: List[Endpoint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    resilience_score: float = 100.0
    rating: str = "Unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def recompute_score(self) -> float:
        deduction = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings)
        self.resilience_score = max(0.0, 100.0 - deduction)
        self.rating = _rating_for(self.resilience_score)
        return self.resilience_score


def _rating_for(score: float) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Poor"
    return "Critical"