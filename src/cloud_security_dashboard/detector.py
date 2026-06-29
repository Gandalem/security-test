from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .config import Settings, get_settings
from .models import NormalizedLog, SecurityEvent
from .utils import make_hash, now_utc


class RuleBasedDetector:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.rules = self._load_rules(self.settings.rule_file_path)
        self.ssh_failures: dict[str, list[NormalizedLog]] = defaultdict(list)
        self.web_status_failures: dict[str, list[NormalizedLog]] = defaultdict(list)
        self.auth_failures_before_success: dict[str, list[NormalizedLog]] = defaultdict(list)
        self.app_errors: dict[str, list[NormalizedLog]] = defaultdict(list)

    def detect(self, log: NormalizedLog) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []

        events.extend(self._detect_pattern_rule(log, "ADMIN_PAGE_SCAN"))
        events.extend(self._detect_pattern_rule(log, "SQL_INJECTION"))
        events.extend(self._detect_pattern_rule(log, "XSS_ATTACK"))
        events.extend(self._detect_pattern_rule(log, "PATH_TRAVERSAL"))
        events.extend(self._detect_brute_force(log))
        events.extend(self._detect_suspicious_status_scan(log))
        events.extend(self._detect_ssh_success_after_failure(log))
        events.extend(self._detect_app_error_spike(log))

        return events

    def _detect_pattern_rule(self, log: NormalizedLog, rule_id: str) -> list[SecurityEvent]:
        rule = self.rules.get(rule_id, {})
        patterns = [pattern.lower() for pattern in rule.get("patterns", [])]
        searchable = " ".join(
            value.lower()
            for value in (log.url_path, log.query_string, log.raw_message)
            if value
        )
        if patterns and any(pattern in searchable for pattern in patterns):
            return [self._build_event(log, rule_id, rule)]
        return []

    def _detect_brute_force(self, log: NormalizedLog) -> list[SecurityEvent]:
        rule = self.rules.get("BRUTE_FORCE", {})
        if log.log_type != "auth" or log.metadata.get("auth_outcome") != "failed" or not log.source_ip:
            return []

        bucket = self.ssh_failures[log.source_ip]
        bucket.append(log)
        self._trim_window(bucket, int(rule.get("window_minutes", 5)), log)
        if len(bucket) == int(rule.get("threshold", 5)):
            return [self._build_event(log, "BRUTE_FORCE", rule, {"failed_attempts": len(bucket)})]
        return []

    def _detect_suspicious_status_scan(self, log: NormalizedLog) -> list[SecurityEvent]:
        rule = self.rules.get("SUSPICIOUS_STATUS_SCAN", {})
        if (
            log.log_type != "web"
            or log.status_code not in set(rule.get("status_codes", []))
            or not log.source_ip
        ):
            return []

        bucket = self.web_status_failures[log.source_ip]
        bucket.append(log)
        self._trim_window(bucket, int(rule.get("window_minutes", 3)), log)
        if len(bucket) == int(rule.get("threshold", 4)):
            return [self._build_event(log, "SUSPICIOUS_STATUS_SCAN", rule, {"failed_responses": len(bucket)})]
        return []

    def _detect_ssh_success_after_failure(self, log: NormalizedLog) -> list[SecurityEvent]:
        rule = self.rules.get("SSH_SUCCESS_AFTER_FAILURE", {})
        if log.log_type != "auth" or not log.source_ip:
            return []

        bucket = self.auth_failures_before_success[log.source_ip]
        outcome = log.metadata.get("auth_outcome")
        if outcome == "failed":
            bucket.append(log)
            self._trim_window(bucket, int(rule.get("window_minutes", 10)), log)
            return []

        if outcome == "success":
            self._trim_window(bucket, int(rule.get("window_minutes", 10)), log)
            if len(bucket) >= int(rule.get("threshold", 3)):
                event = self._build_event(
                    log,
                    "SSH_SUCCESS_AFTER_FAILURE",
                    rule,
                    {"previous_failures": len(bucket)},
                )
                self.auth_failures_before_success[log.source_ip] = []
                return [event]
        return []

    def _detect_app_error_spike(self, log: NormalizedLog) -> list[SecurityEvent]:
        rule = self.rules.get("APP_ERROR_SPIKE", {})
        if log.log_type != "app" or str(log.metadata.get("level", "")).upper() != "ERROR":
            return []

        bucket = self.app_errors[log.host_name or "unknown-host"]
        bucket.append(log)
        self._trim_window(bucket, int(rule.get("window_minutes", 5)), log)
        if len(bucket) == int(rule.get("threshold", 3)):
            return [self._build_event(log, "APP_ERROR_SPIKE", rule, {"error_count": len(bucket)})]
        return []

    def _trim_window(self, bucket: list[NormalizedLog], window_minutes: int, current_log: NormalizedLog) -> None:
        threshold_time = current_log.event_time - timedelta(minutes=window_minutes)
        while bucket and bucket[0].event_time < threshold_time:
            bucket.pop(0)

    def _build_event(
        self,
        log: NormalizedLog,
        rule_id: str,
        rule: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        return SecurityEvent(
            event_id=make_hash(log.raw_id, rule_id, log.event_time.isoformat()),
            raw_id=log.raw_id,
            raw_index=log.raw_index,
            timestamp=now_utc(),
            event_time=log.event_time,
            event_type=rule_id,
            severity=rule.get("severity", "LOW"),
            attack_category=rule.get("attack_category", "unknown"),
            source_ip=log.source_ip,
            source_port=log.source_port,
            host_name=log.host_name,
            log_type=log.log_type,
            service_name=log.service_name,
            username=log.username,
            http_method=log.http_method,
            url_path=log.url_path,
            status_code=log.status_code,
            tags=list(log.tags),
            detection_reason=rule.get("detection_reason", ""),
            recommendation=rule.get("recommendation", ""),
            raw_message=log.raw_message,
            rule_id=rule_id,
            mitre_tactic=rule.get("mitre_tactic"),
            mitre_technique=rule.get("mitre_technique"),
            metadata=metadata or {},
        )

    @staticmethod
    def _load_rules(rule_path: str) -> dict[str, dict[str, Any]]:
        with Path(rule_path).open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return data.get("rules", {})
