from __future__ import annotations

from datetime import UTC, datetime

from cloud_security_dashboard.models import ParsedLog
from cloud_security_dashboard.normalizer import LogNormalizer


def test_normalizer_maps_common_fields() -> None:
    normalizer = LogNormalizer()
    parsed = ParsedLog(
        raw_id="raw-1",
        raw_index="raw-logs-demo",
        log_type="web",
        event_time=datetime(2026, 6, 25, 0, 0, tzinfo=UTC),
        message="demo",
        host_name="demo-host",
        service_name="nginx",
        source_ip="198.51.100.10",
        source_port=44321,
        username=None,
        query_string="q=test",
        http_method="GET",
        url_path="/search",
        status_code=200,
        user_agent="Mozilla/5.0",
        extra={"trace_id": "abc123"},
    )

    normalized = normalizer.normalize(parsed)

    assert normalized.raw_id == "raw-1"
    assert normalized.raw_index == "raw-logs-demo"
    assert normalized.log_type == "web"
    assert normalized.host_name == "demo-host"
    assert normalized.source_ip == "198.51.100.10"
    assert normalized.http_method == "GET"
    assert normalized.url_path == "/search"
    assert normalized.status_code == 200
    assert normalized.metadata["user_agent"] == "Mozilla/5.0"
