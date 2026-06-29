from __future__ import annotations

from .models import NormalizedLog


ATTACK_KEYWORDS = (
    "../",
    "..%2f",
    "union select",
    "' or '1'='1",
    "or 1=1",
    "<script",
    "javascript:",
    "phpmyadmin",
    "wp-login.php",
)


class LogTagger:
    def tag(self, log: NormalizedLog) -> list[str]:
        tags: list[str] = []

        if log.log_type == "auth":
            tags.append("auth")
        elif log.log_type == "web":
            tags.append("web")
        elif log.log_type == "app":
            tags.append("app")

        searchable = " ".join(
            value.lower()
            for value in (log.url_path, log.query_string, log.raw_message)
            if value
        )
        if any(keyword in searchable for keyword in ATTACK_KEYWORDS):
            tags.append("attack")

        if log.status_code in {401, 403, 404, 500, 502, 503}:
            tags.append("abnormal")
        if log.metadata.get("auth_outcome") == "failed":
            tags.append("abnormal")
        if str(log.metadata.get("level", "")).upper() == "ERROR":
            tags.append("abnormal")

        log.tags = sorted(set(tags))
        return log.tags
