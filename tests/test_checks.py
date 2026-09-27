"""Unit tests for scoring and analysis logic."""
from mfa_audit.models import AssessmentResult, Finding, Severity
from mfa_audit.analysis import AnalysisEngine
from datetime import datetime, timezone


def test_score_starts_at_100():
    r = AssessmentResult(target="https://x", scan_started=datetime.now(timezone.utc))
    r.recompute_score()
    assert r.resilience_score == 100
    assert r.rating == "Excellent"


def test_critical_finding_deducts_25():
    r = AssessmentResult(target="https://x", scan_started=datetime.now(timezone.utc))
    r.add_finding(Finding(check_id="X", title="t", severity=Severity.CRITICAL,
                          description="d"))
    r.recompute_score()
    assert r.resilience_score == 75
    assert r.rating == "Good"


def test_compliance_enrichment():
    r = AssessmentResult(target="https://x", scan_started=datetime.now(timezone.utc))
    f = Finding(check_id="CFG-001", title="t", severity=Severity.HIGH,
                description="d")
    r.add_finding(f)
    AnalysisEngine().run(r)
    assert "NIST" in f.nist_ref
    assert "OWASP" in f.owasp_ref


def test_entropy_helper_flags_low_entropy():
    from mfa_audit.assessment import _shannon_entropy
    # A predictable token has near-zero entropy
    assert _shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    # A random-looking token has high entropy
    assert _shannon_entropy("X7k9mP2qR8vT4wZ6") > 3.0