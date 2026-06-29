from __future__ import annotations

from datetime import UTC, datetime

from cloud_security_dashboard.models import RawLog
from cloud_security_dashboard.parser import LogParser


def build_raw_log(message: str, file_name: str) -> RawLog:
    return RawLog(
        raw_id="raw-1",
        raw_index="raw-logs-demo",
        timestamp=datetime(2026, 6, 25, 0, 0, tzinfo=UTC),
        message=message,
        host_name="demo-host",
        log_file_path=file_name,
        agent_name="pytest",
    )


def test_parse_auth_log_extracts_source_ip_and_username() -> None:
    parser = LogParser()
    raw_log = build_raw_log(
        "Jun 25 09:01:00 ip-10-0-0-10 sshd[1202]: Failed password for root from 203.0.113.10 port 54002 ssh2",
        "auth.log",
    )

    parsed = parser.parse(raw_log)

    assert parsed.log_type == "auth"
    assert parsed.raw_index == "raw-logs-demo"
    assert parsed.source_ip == "203.0.113.10"
    assert parsed.username == "root"
    assert parsed.auth_outcome == "failed"


def test_parse_access_log_extracts_url_path_and_status_code() -> None:
    parser = LogParser()
    raw_log = build_raw_log(
        '198.51.100.20 - - [25/Jun/2026:09:11:03 +0900] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.0"',
        "access.log",
    )

    parsed = parser.parse(raw_log)

    assert parsed.log_type == "web"
    assert parsed.url_path == "/admin"
    assert parsed.status_code == 404
    assert parsed.http_method == "GET"
