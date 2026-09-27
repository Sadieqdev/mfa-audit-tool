"""Analysis Engine: scores findings and maps to compliance frameworks."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List

from .models import AssessmentResult, Finding, Severity, SEVERITY_WEIGHTS

DATA_DIR = Path(__file__).parent / "data"


class AnalysisEngine:
    def __init__(self) -> None:
        self.compliance_map = json.loads(
            (DATA_DIR / "compliance_map.json").read_text()
        )["mappings"]

    def run(self, result: AssessmentResult) -> AssessmentResult:
        self._enrich_compliance(result.findings)
        self._compute_score(result)
        result.metadata["severity_breakdown"] = self._breakdown(result.findings)
        return result

    def _enrich_compliance(self, findings: List[Finding]) -> None:
        for f in findings:
            m = self.compliance_map.get(f.check_id, {})
            if not f.nist_ref and m.get("nist"):
                f.nist_ref = m["nist"]
            if not f.owasp_ref and m.get("owasp"):
                f.owasp_ref = m["owasp"]
            if not f.cwe_ref and m.get("cwe"):
                f.cwe_ref = m["cwe"]

    def _compute_score(self, result: AssessmentResult) -> None:
        result.recompute_score()

    @staticmethod
    def _breakdown(findings: List[Finding]) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in findings:
            out[f.severity.value] += 1
        return out