from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cloud_security_dashboard.detector import RuleBasedDetector
from cloud_security_dashboard.models import NormalizedLog


def build_log(
    *,
    raw_id: str,
    log_type: str,
    source_ip: str | None = "198.51.100.10",
    event_time: datetime | None = None,
    url_path: str | None = None,
    query_string: str | None = None,
    status_code: int | None = None,
    tags: list[str] | None = None,
    metadata: dict | None = None,
    raw_message: str = "message",
) -> NormalizedLog:
    return NormalizedLog(
        raw_id=raw_id,
        raw_index="raw-logs-demo",
        event_time=event_time or datetime(2026, 6, 25, 0, 0, tzinfo=UTC),
        host_name="demo-host",
        source_ip=source_ip,
        source_port=12345,
        log_type=log_type,
        service_name="service",
        raw_message=raw_message,
        http_method="GET",
        url_path=url_path,
        query_string=query_string,
        status_code=status_code,
        username="user",
        tags=tags or [],
        metadata=metadata or {},
    )


def test_detects_sql_injection() -> None:
    detector = RuleBasedDetector()
    log = build_log(
        raw_id="1",
        log_type="web",
        url_path="/login",
        query_string="username=admin' or '1'='1",
        tags=["web", "attack"],
    )

    events = detector.detect(log)

    assert any(event.event_type == "SQL_INJECTION" for event in events)


def test_detects_xss_attack() -> None:
    detector = RuleBasedDetector()
    log = build_log(
        raw_id="2",
        log_type="web",
        url_path="/search",
        query_string="q=<script>alert(1)</script>",
        tags=["web", "attack"],
    )

    events = detector.detect(log)

    assert any(event.event_type == "XSS_ATTACK" for event in events)


def test_detects_path_traversal() -> None:
    detector = RuleBasedDetector()
    log = build_log(
        raw_id="3",
        log_type="web",
        url_path="/download",
        query_string="file=../../etc/passwd",
        tags=["web", "attack"],
    )

    events = detector.detect(log)

    assert any(event.event_type == "PATH_TRAVERSAL" for event in events)


def test_detects_admin_page_scan() -> None:
    detector = RuleBasedDetector()
    log = build_log(
        raw_id="4",
        log_type="web",
        url_path="/admin",
        tags=["web", "attack"],
    )

    events = detector.detect(log)

    assert any(event.event_type == "ADMIN_PAGE_SCAN" for event in events)


def test_detects_brute_force() -> None:
    detector = RuleBasedDetector()
    base_time = datetime(2026, 6, 25, 0, 0, tzinfo=UTC)
    events = []
    for index in range(5):
        log = build_log(
            raw_id=f"bf-{index}",
            log_type="auth",
            source_ip="203.0.113.10",
            event_time=base_time + timedelta(minutes=index),
            metadata={"auth_outcome": "failed"},
            tags=["auth", "abnormal"],
        )
        events.extend(detector.detect(log))

    assert any(event.event_type == "BRUTE_FORCE" for event in events)
