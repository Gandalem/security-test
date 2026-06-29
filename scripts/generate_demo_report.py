from __future__ import annotations

import _bootstrap  # noqa: F401

from cloud_security_dashboard.config import get_settings
from cloud_security_dashboard.storage import ElasticsearchStorage
from elasticsearch.exceptions import NotFoundError


def main() -> None:
    settings = get_settings()
    storage = ElasticsearchStorage(settings)
    try:
        raw_count = storage.client.count(index=settings.raw_index_pattern).get("count", 0)
    except NotFoundError:
        raw_count = 0
    try:
        event_count = storage.client.count(index="security-events-*").get("count", 0)
        recent = storage.client.search(
            index="security-events-*",
            size=5,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
    except NotFoundError:
        event_count = 0
        recent = {"hits": {"hits": []}}

    print("=== Demo Summary ===")
    print(f"Raw logs indexed: {raw_count}")
    print(f"Security events indexed: {event_count}")
    for hit in recent.get("hits", {}).get("hits", []):
        source = hit["_source"]
        print(
            f"- {source['event_type']} severity={source['severity']} "
            f"source_ip={source.get('source_ip')} reason={source['detection_reason']}"
        )


if __name__ == "__main__":
    main()
