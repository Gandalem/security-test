from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class RawLog:
    raw_id: str
    raw_index: str
    timestamp: datetime
    message: str
    host_name: str
    log_file_path: str
    agent_name: str
    processed: bool = False
    processed_at: datetime | None = None
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedLog:
    raw_id: str
    raw_index: str
    log_type: str
    event_time: datetime
    message: str
    host_name: str | None = None
    service_name: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    username: str | None = None
    query_string: str | None = None
    http_method: str | None = None
    url_path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    level: str | None = None
    auth_outcome: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedLog:
    raw_id: str
    raw_index: str
    event_time: datetime
    host_name: str | None
    source_ip: str | None
    source_port: int | None
    log_type: str
    service_name: str | None
    raw_message: str
    http_method: str | None
    url_path: str | None
    query_string: str | None
    status_code: int | None
    username: str | None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SecurityEvent:
    event_id: str
    raw_id: str
    raw_index: str
    timestamp: datetime
    event_time: datetime
    event_type: str
    severity: str
    attack_category: str
    source_ip: str | None
    source_port: int | None
    host_name: str | None
    log_type: str
    service_name: str | None
    username: str | None
    http_method: str | None
    url_path: str | None
    status_code: int | None
    tags: list[str]
    detection_reason: str
    recommendation: str
    raw_message: str
    rule_id: str
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
