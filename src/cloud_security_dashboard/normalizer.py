from __future__ import annotations

from .models import NormalizedLog, ParsedLog


class LogNormalizer:
    def normalize(self, parsed_log: ParsedLog) -> NormalizedLog:
        metadata = dict(parsed_log.extra)
        if parsed_log.auth_outcome:
            metadata["auth_outcome"] = parsed_log.auth_outcome
        if parsed_log.user_agent:
            metadata["user_agent"] = parsed_log.user_agent
        if parsed_log.level:
            metadata["level"] = parsed_log.level

        return NormalizedLog(
            raw_id=parsed_log.raw_id,
            raw_index=parsed_log.raw_index,
            event_time=parsed_log.event_time,
            host_name=parsed_log.host_name,
            source_ip=parsed_log.source_ip,
            source_port=parsed_log.source_port,
            log_type=parsed_log.log_type,
            service_name=parsed_log.service_name,
            raw_message=parsed_log.message,
            http_method=parsed_log.http_method,
            url_path=parsed_log.url_path,
            query_string=parsed_log.query_string,
            status_code=parsed_log.status_code,
            username=parsed_log.username,
            metadata=metadata,
        )
