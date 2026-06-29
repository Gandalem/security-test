from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(ROOT_DIR / ".env")


@dataclass(slots=True)
class Settings:
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    raw_index_pattern: str = os.getenv("RAW_INDEX_PATTERN", "raw-logs-*")
    raw_index_name: str = os.getenv("RAW_INDEX_NAME", "raw-logs-demo")
    security_event_index: str = os.getenv("SECURITY_EVENT_INDEX", "security-events-demo")
    host_name: str = os.getenv("HOST_NAME", "demo-host")
    agent_name: str = os.getenv("AGENT_NAME", "seed-script")
    analyzer_batch_size: int = int(os.getenv("ANALYZER_BATCH_SIZE", "200"))
    timezone: str = os.getenv("TIMEZONE", "Asia/Seoul")
    rule_file_path: str = os.getenv(
        "RULE_FILE_PATH", str(ROOT_DIR / "rules" / "detection_rules.yml")
    )
    event_index_mode: str = os.getenv("EVENT_INDEX_MODE", "static")


def get_settings() -> Settings:
    return Settings()
