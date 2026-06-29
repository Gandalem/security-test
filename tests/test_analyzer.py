from __future__ import annotations

from datetime import datetime

from cloud_security_dashboard.analyzer import Analyzer
from cloud_security_dashboard.config import Settings
from cloud_security_dashboard.models import SecurityEvent


class FakeStorage:
    def __init__(self) -> None:
        self.indexed_events: list[tuple[SecurityEvent, str]] = []
        self.marked: list[tuple[str, str, datetime]] = []

    def fetch_unprocessed_logs(self) -> list[dict]:
        return [
            {
                "_index": "raw-logs-demo",
                "_id": "raw-doc-1",
                "_source": {
                    "@timestamp": "2026-06-25T00:00:00+00:00",
                    "message": '198.51.100.20 - - [25/Jun/2026:09:11:03 +0900] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.0"',
                    "host": {"name": "demo-host"},
                    "log": {"file": {"path": "access.log"}},
                    "agent": {"name": "pytest"},
                    "processed": False,
                    "processed_at": None,
                    "raw_id": "raw-1",
                    "fields": {},
                },
            }
        ]

    def index_security_event_if_absent(self, event: SecurityEvent, index_name: str) -> bool:
        self.indexed_events.append((event, index_name))
        return True

    def mark_raw_log_processed(self, index_name: str, doc_id: str, processed_at: datetime) -> None:
        self.marked.append((index_name, doc_id, processed_at))


def test_analyzer_marks_raw_log_processed_and_preserves_required_fields() -> None:
    settings = Settings(security_event_index="security-events-demo")
    storage = FakeStorage()
    analyzer = Analyzer(settings=settings, storage=storage)  # type: ignore[arg-type]

    result = analyzer.run_once()

    assert result.processed_logs == 1
    assert result.generated_events == 1
    assert len(storage.indexed_events) == 1
    assert len(storage.marked) == 1
    first_event, index_name = storage.indexed_events[0]
    assert first_event.raw_id == "raw-1"
    assert first_event.raw_index == "raw-logs-demo"
    assert first_event.rule_id == "ADMIN_PAGE_SCAN"
    assert index_name == "security-events-demo"
    assert storage.marked[0][0] == "raw-logs-demo"
    assert storage.marked[0][1] == "raw-doc-1"
