import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Callable
from collections import defaultdict

import httpx


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class RoutingRule:
    channels: List[Channel]
    min_severity: Severity
    categories: Optional[List[str]] = None

    def matches(self, incident: Incident) -> bool:
        if SEVERITY_ORDER[incident.severity] > SEVERITY_ORDER[self.min_severity]:
            return False
        if self.categories and incident.category not in self.categories:
            return False
        return True


class RateLimiter:
    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window = window_seconds
        self._timestamps: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        timestamps = self._timestamps[key]
        cutoff = now - self.window
        self._timestamps[key] = [t for t in timestamps if t > cutoff]
        if len(self._timestamps[key]) >= self.max_calls:
            return False
        self._timestamps[key].append(now)
        return True


class SlackDispatcher:
    def __init__(self, webhook_url: str, client: Optional[httpx.Client] = None):
        self.webhook_url = webhook_url
        self._client = client or httpx.Client(timeout=10.0)

    def send(self, incident: Incident) -> bool:
        severity_color = {
            Severity.CRITICAL: "#ff0000",
            Severity.HIGH: "#ff6600",
            Severity.MEDIUM: "#ffcc00",
            Severity.LOW: "#36a64f",
            Severity.INFO: "#808080",
        }
        payload = {
            "attachments": [{
                "color": severity_color.get(incident.severity, "#808080"),
                "title": f"[{incident.severity.value.upper()}] {incident.title}",
                "text": incident.description,
                "fields": [
                    {"title": "Category", "value": incident.category, "short": True},
                    {"title": "Incident ID", "value": incident.id, "short": True},
                ],
                "footer": "incident-triage",
            }]
        }
        try:
            resp = self._client.post(self.webhook_url, json=payload)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False


class PagerDutyDispatcher:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self.routing_key = routing_key
        self.api_url = api_url
        self._client = httpx.Client(timeout=10.0)

    def send(self, incident: Incident) -> bool:
        severity_map = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "high",
            Severity.MEDIUM: "warning",
            Severity.LOW: "info",
            Severity.INFO: "info",
        }
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": incident.title,
                "severity": severity_map.get(incident.severity, "info"),
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "group": incident.id,
                "custom_details": {"description": incident.description},
            },
        }
        try:
            resp = self._client.post(self.api_url, json=payload)
            return resp.status_code in (200, 202)
        except httpx.HTTPError:
            return False


class EmailDispatcher:
    def __init__(self, smtp_host: str, smtp_port: int, sender: str, recipients: List[str]):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients

    def send(self, incident: Incident) -> bool:
        import smtplib
        from email.mime.text import MIMEText
        subject = f"[{incident.severity.value.upper()}] {incident.title} ({incident.category})"
        body = f"Incident ID: {incident.id}\nSeverity: {incident.severity.value}\nCategory: {incident.category}\n\n{incident.description}"
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.sendmail(self.sender, self.recipients, msg.as_string())
            return True
        except Exception:
            return False


class NotificationDispatcher:
    def __init__(
        self,
        routing_rules: List[RoutingRule],
        channel_dispatchers: Dict[Channel, object],
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.routing_rules = routing_rules
        self.channel_dispatchers = channel_dispatchers
        self.rate_limiter = rate_limiter or RateLimiter(max_calls=60, window_seconds=60.0)
        self.logger = logging.getLogger("notification-dispatcher")

    def resolve_channels(self, incident: Incident) -> List[Channel]:
        channels: List[Channel] = []
        seen: set = set()
        for rule in self.routing_rules:
            if rule.matches(incident):
                for ch in rule.channels:
                    if ch not in seen:
                        channels.append(ch)
                        seen.add(ch)
        return channels

    def dispatch(self, incident: Incident) -> Dict[Channel, bool]:
        channels = self.resolve_channels(incident)
        results: Dict[Channel, bool] = {}
        for channel in channels:
            rate_key = f"{channel.value}:{incident.category}"
            if not self.rate_limiter.is_allowed(rate_key):
                self.logger.warning("Rate limited: channel=%s category=%s", channel.value, incident.category)
                results[channel] = False
                continue
            dispatcher = self.channel_dispatchers.get(channel)
            if dispatcher is None:
                self.logger.error("No dispatcher configured for channel: %s", channel.value)
                results[channel] = False
                continue
            try:
                ok = dispatcher.send(incident)
                results[channel] = ok
                self.logger.info("Dispatched incident=%s channel=%s success=%s", incident.id, channel.value, ok)
            except Exception as exc:
                self.logger.exception("Dispatch error incident=%s channel=%s: %s", incident.id, channel.value, exc)
                results[channel] = False
        return results