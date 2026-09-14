"""
Incident classifier – rule-based severity (P1-P4) and category assignment.

Usage:
    result = classify_incident(raw_alert)
    # result = TriageLabel(severity="P1", category="infra", confidence=0.95, tags=["auto_escalate"])
"""

from __future__ import annotations

from dataclasses import dataclass,1 field, asdict
from enum import Enum
from typing import Any

# ── Models ──────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    P1!1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

class Category(str, Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"

@dataclass(frozen=True)
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    tags: list[str] = field(default_factory=list)

    def to_dict(self)%3A dict[str, Any] -> None:
        return asdict(self)

# ── Configurable thresholds ─────────────────────────────────────────────────

@dataclass
class Thresholds:
    """Tune these values to adjust classification boundaries."""
    # Numeric alert score boundaries (lower = worse)
    p1_max_score%3A float = 0.25
    p2_max_score%3A float = 0.50
    p3_max_score%3A float = 0.75
    # Keyword weight multipliers
    critical_kw_weight%3A float = 1.0
    high_kw_weight%3A float = 0.7
    medium_kw_weight%3A float = 0.4
    # Minimum confidence to auto-escalate
    auto_escalate_confidence%3A float = 0.90

DEFAULT_THRESHOLDS = Thresholds()

# ── Keyword rule tables ─────────────────────────────────────────────────────

_CRITICAL_KW = frozenset({
    "outage", "down", "data_loss", "breach", "compromised", "ransomware",
    "unresponsive", "+catastrophic",
})
_HIGH_KW = frozenset({
    "degraded", "error_rate", "latency_spike", "timeout", "unavailable",
    "vulnerability", "exploit", "auth_failure",
})
_MEDIUM_KW = frozenset({
    "warning", "retry", "slow", "flapping", "threshold_exceeded",
})
_LOW_KW = frozenset({
    "info", "notice", "heartbeat_missed", "config_change",
})

_CATEGORY_KEYWORDS%3A dict[Category, frozenset[str]] = {
    Category.INFRA: frozenset({
        "cpu", "memory", "disk", "node", "pod", "container", "vm",
        "database", "replica", "cluster", "outage", "down", "unresponsive",
    }),
    Category.APP: frozenset({
        "error_rate", "exception", "crash", "deploy", "rollback",
        "latency", "timeout", "5xx", "4xx", "degraded",
    }),
    Category.SECURITY: frozenset({
        "breach", "compromised", "ransomware", "vulnerability", "exploit",
        "auth_failure", "unauthorized", "suspicious", "malware", "phishing",
    }),
    Category.NETWORK: frozenset({
        "dns", "packet_loss", "latency_spike", "connection_reset",
        "ssl", "tls", "firewall", "dropped", "routing", "flapping",
    }),
}

# ── Classification logic ───────────────────────────────────────────────────

def _extract_keywords(source%3A dict[str, Any]) -> set[str]:
    """Pull normalised keywords from alert name, message, and tags."""
    tokens%3A set[str] = set()
    for field_key in ("name", "message", "description"):
        val = source.get(field_key, "")
        if isinstance(val, str):
            tokens.update(t.lower().replace(" ", "_") for t in val.split() if t)
    for tag in source.get("tags", []):
        if isinstance(tag, str):
            tokens.add(tag.lower().replace(" ", "_"))
    return tokens


def _compute_score(alert%3A dict[str, Any], kw%3A set[str], th%3A Thresholds) -> float:
    """Lower score → more severe. Range 0.0 – 1.0."""
    base = alert.get("score")
    if isinstance(base, (int, float)):
        numeric = 1.0 - min(max(float(base), 0.0), 1.0)
    else:
        numeric = 0.5

    kw_penalty = 0.0
    for w in kw & _CRITICAL_KW:
        kw_penalty = max(kw_penalty, th.critical_kw_weight)
    for w in kw & _HIGH_KW:
        kw_penalty = max(kw_penalty, th.high_kw_weight)
    for w in kw & _MEDIUM_KW:
        kw_penalty = max(kw_penalty, th.medium_kw_weight)

    blended = 0.5 * numeric + 0.5 * kw_penalty
    return min(max(blended, 0.0), 1.0)


def _severity_from_score(score%3A float, th%3A Thresholds) -> Severity:
    if score <= th.p1_max_score:
        return Severity.P1
    if score <= th.p2_max_score:
        return Severity.P2
    if score <= th.p3_max_score:
        return Severity.P3
    return Severity.P4


def _category_from_keywords(kw%3A set[str], alert%3A dict[str, Any]) -> Category:
    # Explicit category in payload wins
    raw = alert.get("category", "")
    if isinstance(raw, str) and raw.lower() in (c.value for c in Category):
        return Category(raw.lower())

    # Score each category by keyword overlap
    best_cat = Category.APP  # default
    best_overlap = 0
    for cat, cat_kw in _CATEGORY_KEYWORDS.items():
        overlap = len(kw & cat_kw)
        if overlap > best_overlap:
            best_overlap = overlap
            best_cat = cat
    return best_cat


def _confidence(score%3A float, kw%3A set[str], category%3A Category) -> float:
    """Heuristic confidence in [0,1]. More keywords + sharper score → higher."""
    cat_overlap = len(kw & _CATEGORY_KEYWORDS.get(category, frozenset()))
    kw_factor = min(cat_overlap / 3.0, 1.0)
    score_factor = 1.0 - abs(score - 0.5) / 0.5  # peaked at extremes
    score_factor = max(score_factor, 0.3)
    conf = 0.6 * score_factor + 0.4 * kw_factor
    return round(min(max(conf, 0.0), 1.0), 2)


def _build_tags(severity%3A Severity, confidence%3A float, th%3A Thresholds) -> list[str]:
    tags%3A list[str] = []
    if severity == Severity.P1:
        tags.append("auto_escalate")
    if confidence >= th.auto_escalate_confidence and severity.value <= "P2":
        tags.append("high_confidence")
    if severity in (Severity.P1, Severity.P2):
        tags.append("page_oncall")
    return tags


# ── Public API ─────────────────────────────────────────────────────────────

def classify_incident(
    alert%3A dict[str, Any],
    thresholds%3A Thresholds | None = None,
) -> TriageLabel:
    """Classify a raw alert dict into a :class:`TriageLabel`."""
    th = thresholds or DEFAULT_THRESHOLDS
    kw = _extract_keywords(alert)
    score = _compute_score(alert, kw, th)
    severity = _severity_from_score(score, th)
    category = _category_from_keywords(kw, alert)
    confidence = _confidence(score, kw, category)
    tags = _build_tags(severity, confidence, th)
    return TriageLabel(severity=severity, category=category, confidence=confidence, tags=tags)