from __future__ import annotations

from datetime import UTC, datetime

from cloud_security_dashboard.models import SecurityEvent
from cloud_security_dashboard.storage import build_security_event_document


def test_security_event_payload_is_serializable_dict() -> None:
    event = SecurityEvent(
        event_id="event-1",
        raw_id="raw-1",
        raw_index="raw-logs-demo",
        timestamp=datetime(2026, 6, 25, 0, 0, tzinfo=UTC),
        event_time=datetime(2026, 6, 25, 0, 0, tzinfo=UTC),
        event_type="SQL_INJECTION",
        severity="HIGH",
        attack_category="web_attack",
        source_ip="198.51.100.10",
        source_port=44321,
        host_name="demo-host",
        log_type="web",
        service_name="nginx",
        username=None,
        http_method="GET",
        url_path="/login",
        status_code=200,
        tags=["web", "attack"],
        detection_reason="URL 파라미터에 SQL Injection 의심 패턴 포함",
        recommendation="입력값 검증을 확인하세요.",
        raw_message="demo",
        rule_id="SQL_INJECTION",
        mitre_tactic=None,
        mitre_technique=None,
        metadata={"demo": True},
    )

    document = build_security_event_document(event)

    assert isinstance(document, dict)
    assert document["@timestamp"].startswith("2026-06-25T00:00:00")
    assert document["event_time"].startswith("2026-06-25T00:00:00")
    assert document["host_name"] == "demo-host"
    assert document["source_ip"] == "198.51.100.10"
    assert document["source_port"] == 44321
    assert document["log_type"] == "web"
    assert document["service_name"] == "nginx"
    assert document["event_type"] == "SQL_INJECTION"
    assert document["severity"] == "HIGH"
    assert document["attack_category"] == "web_attack"
    assert document["tags"] == ["web", "attack"]
    assert document["detection_reason"] == "URL 파라미터에 SQL Injection 의심 패턴 포함"
    assert document["recommendation"] == "입력값 검증을 확인하세요."
    assert document["raw_message"] == "demo"
    assert document["raw_index"] == "raw-logs-demo"
    assert document["raw_id"] == "raw-1"
    assert document["rule_id"] == "SQL_INJECTION"
