from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .config import Settings, get_settings
from .models import ParsedLog, RawLog
from .utils import now_utc, safe_int, to_utc


AUTH_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<action>Failed password|Accepted password|Invalid user|invalid user)"
    r"(?: for (?:invalid user )?(?P<username>\S+)| (?P<invalid_username>\S+))?"
    r"(?: from (?P<source_ip>\S+) port (?P<source_port>\d+))?"
    r".*$"
)

ACCESS_REGEX = re.compile(
    r'^(?P<source_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+\S+"\s+'
    r"(?P<status>\d{3})\s+\S+\s+"
    r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"$'
)

APP_REGEX = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<level>[A-Z]+)\s+(?P<message>.*)$"
)

SYSLOG_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[^\[:]+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)

APP_USER_REGEX = re.compile(r"\buser=(?P<user>[\w.@-]+)")
APP_IP_REGEX = re.compile(r"\bip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


class LogParser:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def parse(self, raw_log: RawLog) -> ParsedLog:
        log_name = Path(raw_log.log_file_path).name.lower()
        if log_name == "auth.log":
            return self._parse_auth_log(raw_log)
        if log_name == "access.log":
            return self._parse_access_log(raw_log)
        if log_name == "app.log":
            return self._parse_app_log(raw_log)
        if log_name == "syslog":
            return self._parse_syslog(raw_log)
        return self._build_unknown(raw_log)

    def _parse_auth_log(self, raw_log: RawLog) -> ParsedLog:
        match = AUTH_REGEX.match(raw_log.message)
        if not match:
            return self._build_unknown(raw_log, log_type="auth")

        event_time = self._parse_syslog_time(
            match.group("month"), match.group("day"), match.group("time")
        )
        action = match.group("action").lower()
        auth_outcome = "unknown"
        if "failed password" in action or "invalid user" in action:
            auth_outcome = "failed"
        elif "accepted password" in action:
            auth_outcome = "success"
        username = match.group("username") or match.group("invalid_username")

        return ParsedLog(
            raw_id=raw_log.raw_id,
            raw_index=raw_log.raw_index,
            log_type="auth",
            event_time=event_time,
            message=raw_log.message,
            host_name=match.group("host"),
            service_name="sshd",
            source_ip=match.group("source_ip"),
            source_port=safe_int(match.group("source_port")),
            username=username,
            auth_outcome=auth_outcome,
            extra={"sshd_message": raw_log.message},
        )

    def _parse_access_log(self, raw_log: RawLog) -> ParsedLog:
        match = ACCESS_REGEX.match(raw_log.message)
        if not match:
            return self._build_unknown(raw_log, log_type="web")

        event_time = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
        url = urlsplit(match.group("target"))
        return ParsedLog(
            raw_id=raw_log.raw_id,
            raw_index=raw_log.raw_index,
            log_type="web",
            event_time=event_time,
            message=raw_log.message,
            host_name=raw_log.host_name,
            service_name="nginx",
            source_ip=match.group("source_ip"),
            http_method=match.group("method"),
            url_path=unquote(url.path or "/"),
            query_string=unquote(url.query) or None,
            status_code=safe_int(match.group("status")),
            user_agent=match.group("user_agent"),
        )

    def _parse_app_log(self, raw_log: RawLog) -> ParsedLog:
        match = APP_REGEX.match(raw_log.message)
        if not match:
            return self._build_unknown(raw_log, log_type="app")

        timestamp = datetime.fromisoformat(match.group("timestamp").replace("Z", "+00:00")).astimezone(UTC)
        message = match.group("message")
        user_match = APP_USER_REGEX.search(message)
        ip_match = APP_IP_REGEX.search(message)
        return ParsedLog(
            raw_id=raw_log.raw_id,
            raw_index=raw_log.raw_index,
            log_type="app",
            event_time=timestamp,
            message=raw_log.message,
            host_name=raw_log.host_name,
            service_name="application",
            source_ip=ip_match.group("ip") if ip_match else None,
            username=user_match.group("user") if user_match else None,
            level=match.group("level"),
            extra={"app_message": message},
        )

    def _parse_syslog(self, raw_log: RawLog) -> ParsedLog:
        match = SYSLOG_REGEX.match(raw_log.message)
        if not match:
            return self._build_unknown(raw_log, log_type="syslog")

        event_time = self._parse_syslog_time(
            match.group("month"), match.group("day"), match.group("time")
        )
        return ParsedLog(
            raw_id=raw_log.raw_id,
            raw_index=raw_log.raw_index,
            log_type="syslog",
            event_time=event_time,
            message=raw_log.message,
            host_name=match.group("host"),
            service_name=match.group("service"),
            extra={"service_message": match.group("message")},
        )

    def _build_unknown(self, raw_log: RawLog, log_type: str = "unknown") -> ParsedLog:
        return ParsedLog(
            raw_id=raw_log.raw_id,
            raw_index=raw_log.raw_index,
            log_type=log_type,
            event_time=raw_log.timestamp,
            message=raw_log.message,
            host_name=raw_log.host_name,
            service_name="unknown",
        )

    def _parse_syslog_time(self, month: str, day: str, time_text: str) -> datetime:
        current_year = now_utc().year
        naive = datetime.strptime(
            f"{current_year} {month} {day} {time_text}", "%Y %b %d %H:%M:%S"
        )
        return to_utc(naive, self.settings.timezone)
