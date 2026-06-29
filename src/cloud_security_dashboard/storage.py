from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConflictError, NotFoundError

from .config import Settings, get_settings
from .models import RawLog, SecurityEvent


RAW_TEMPLATE_NAME = "raw-logs-template"
EVENT_TEMPLATE_NAME = "security-events-template"


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def build_raw_log_document(raw_log: RawLog) -> dict[str, Any]:
    return {
        "@timestamp": raw_log.timestamp.isoformat(),
        "message": raw_log.message,
        "host": {"name": raw_log.host_name},
        "log": {"file": {"path": raw_log.log_file_path}},
        "agent": {"name": raw_log.agent_name},
        "processed": raw_log.processed,
        "processed_at": _serialize_datetime(raw_log.processed_at),
        "raw_id": raw_log.raw_id,
        "raw_index": raw_log.raw_index,
        "fields": raw_log.fields,
    }


def build_security_event_document(event: SecurityEvent) -> dict[str, Any]:
    document = asdict(event)
    document["@timestamp"] = event.timestamp.isoformat()
    document["event_time"] = event.event_time.isoformat()
    document["timestamp"] = event.timestamp.isoformat()
    return document


class ElasticsearchStorage:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.client = Elasticsearch(self.settings.elasticsearch_url)

    def create_index_templates(self) -> None:
        self.client.indices.put_index_template(
            name=RAW_TEMPLATE_NAME,
            index_patterns=["raw-logs-*"],
            template={
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "message": {"type": "text"},
                        "host": {"properties": {"name": {"type": "keyword"}}},
                        "log": {
                            "properties": {
                                "file": {"properties": {"path": {"type": "keyword"}}}
                            }
                        },
                        "agent": {"properties": {"name": {"type": "keyword"}}},
                        "processed": {"type": "boolean"},
                        "processed_at": {"type": "date"},
                        "raw_id": {"type": "keyword"},
                        "raw_index": {"type": "keyword"},
                    }
                }
            },
        )
        self.client.indices.put_index_template(
            name=EVENT_TEMPLATE_NAME,
            index_patterns=["security-events-*"],
            template={
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_time": {"type": "date"},
                        "host_name": {"type": "keyword"},
                        "source_ip": {"type": "ip", "ignore_malformed": True},
                        "source_port": {"type": "integer"},
                        "log_type": {"type": "keyword"},
                        "service_name": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "attack_category": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "detection_reason": {"type": "text"},
                        "recommendation": {"type": "text"},
                        "raw_message": {"type": "text"},
                        "raw_index": {"type": "keyword"},
                        "raw_id": {"type": "keyword"},
                        "rule_id": {"type": "keyword"},
                        "status_code": {"type": "integer"},
                        "mitre_tactic": {"type": "keyword"},
                        "mitre_technique": {"type": "keyword"},
                    }
                }
            },
        )

    def index_raw_log_if_absent(self, index_name: str, raw_log: RawLog) -> bool:
        document = build_raw_log_document(raw_log)
        try:
            self.client.create(index=index_name, id=raw_log.raw_id, document=document)
            return True
        except ConflictError:
            return False
        except Exception as exc:  # pragma: no cover - network error path
            raise RuntimeError(f"raw log 저장 실패: {exc}") from exc

    def fetch_unprocessed_logs(self) -> list[dict[str, Any]]:
        try:
            response = self.client.search(
                index=self.settings.raw_index_pattern,
                size=self.settings.analyzer_batch_size,
                sort=[{"@timestamp": {"order": "asc"}}],
                query={
                    "bool": {
                        "should": [
                            {"term": {"processed": False}},
                            {"bool": {"must_not": {"exists": {"field": "processed"}}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            )
        except NotFoundError:
            return []
        except Exception as exc:  # pragma: no cover - network error path
            raise RuntimeError(f"미처리 raw log 조회 실패: {exc}") from exc
        return response.get("hits", {}).get("hits", [])

    def index_security_event_if_absent(self, event: SecurityEvent, index_name: str) -> bool:
        document = build_security_event_document(event)
        try:
            self.client.create(index=index_name, id=event.event_id, document=document)
            return True
        except ConflictError:
            return False
        except Exception as exc:  # pragma: no cover - network error path
            raise RuntimeError(f"security event 저장 실패: {exc}") from exc

    def mark_raw_log_processed(self, index_name: str, doc_id: str, processed_at: datetime) -> None:
        try:
            self.client.update(
                index=index_name,
                id=doc_id,
                doc={"processed": True, "processed_at": processed_at.isoformat()},
            )
        except Exception as exc:  # pragma: no cover - network error path
            raise RuntimeError(f"raw log 처리 상태 업데이트 실패: {exc}") from exc
