"""Quick smoke-test for the incident classifier."""

from classifier import classify_incident, Thresholds, Severity, Category

def _p(result) -> None:
    print(f"  → {result.severity.value} | {result.category.value} | conf={result.confidence} | tags={result.tags}")

print("=== Incident Classifier Smoke Tests ===\n")

print("1) Critical infra outage:")
result = classify_incident({"name": "node down outage", "score": 0.05, "tags": ["cluster"]})
_p(result)
assert result.severity == Severity.P1 and result.category == Category.INFRA

print("2) Security breach:")
result = classify_incident({"name": "data breach compromised", "score": 0.1})
_p(result)
assert result.severity == Severity.P1 and result.category == Category.SECURITY

print("3) App error rate (high):")
result = classify_incident({"name": "error_rate timeout 5xx", "score": 0.35, "category": "app"})
_p(result)
assert result.severity == Severity.P2 and result.category == Category.APP

print("4) Network flapping (medium):")
result = classify_incident({"name": "dns flapping latency_spike", "score": 0.55})
_p(result)
assert result.severity == Severity.P3 and result.category == Category.NETWORK

print("5) Low-severity info:")
result = classify_incident({"name": "info heartbeat_missed", "score": 0.9})
_p(result)
assert result.severity == Severity.P4

print("6) Custom thresholds:")
custom = Thresholds(p1_max_score=0.15, p2_max_score=0.40, auto_escalate_confidence=0.80)
result = classify_incident({"name": "degraded latency", "score": 0.30}, thresholds=custom)
_p(result)
assert result.severity == Severity.P2

print("\n✅ All assertions passed.")