from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .config import Settings, get_settings
from .detector import RuleBasedDetector
from .models import RawLog, SecurityEvent
from .normalizer import LogNormalizer
from .parser import LogParser
from .storage import ElasticsearchStorage
from .tagger import LogTagger
from .utils import now_utc


@dataclass(slots=True)
class AnalyzerResult:
    processed_logs: int = 0
    generated_events: int = 0


class Analyzer:
    def __init__(self, settings: Settings | None = None, storage: ElasticsearchStorage | None = None) -> None:
        self.settings = settings or get_settings()
        self.storage = storage or ElasticsearchStorage(self.settings)
        self.parser = LogParser(self.settings)
        self.normalizer = LogNormalizer()
        self.tagger = LogTagger()
        self.detector = RuleBasedDetector(self.settings)

    def run_once(self) -> AnalyzerResult:
        result = AnalyzerResult()
        hits = self.storage.fetch_unprocessed_logs()
        for hit in hits:
            raw_log = self._raw_log_from_hit(hit)
            parsed_log = self.parser.parse(raw_log)
            normalized_log = self.normalizer.normalize(parsed_log)
            self.tagger.tag(normalized_log)
            events = self.detector.detect(normalized_log)
            stored_events = 0
            for event in events:
                if self.storage.index_security_event_if_absent(
                    event, self._resolve_event_index_name(event)
                ):
                    stored_events += 1
            self.storage.mark_raw_log_processed(hit["_index"], hit["_id"], now_utc())
            result.processed_logs += 1
            result.generated_events += stored_events
        return result

    def _resolve_event_index_name(self, event: SecurityEvent) -> str:
        if self.settings.event_index_mode == "daily":
            return f"security-events-{event.event_time.strftime('%Y.%m.%d')}"
        return self.settings.security_event_index

    def _raw_log_from_hit(self, hit: dict) -> RawLog:
        source = hit["_source"]
        processed_at = source.get("processed_at")
        return RawLog(
            raw_id=source.get("raw_id", hit["_id"]),
            raw_index=hit["_index"],
            timestamp=datetime.fromisoformat(source["@timestamp"].replace("Z", "+00:00")),
            message=source["message"],
            host_name=source.get("host", {}).get("name", self.settings.host_name),
            log_file_path=source.get("log", {}).get("file", {}).get("path", "unknown.log"),
            agent_name=source.get("agent", {}).get("name", self.settings.agent_name),
            processed=source.get("processed", False),
            processed_at=(
                datetime.fromisoformat(processed_at.replace("Z", "+00:00"))
                if processed_at
                else None
            ),
            fields=source.get("fields", {}),
        )
