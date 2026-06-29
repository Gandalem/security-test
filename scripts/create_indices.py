from __future__ import annotations

import _bootstrap  # noqa: F401

from cloud_security_dashboard.config import get_settings
from cloud_security_dashboard.storage import ElasticsearchStorage


def main() -> None:
    settings = get_settings()
    storage = ElasticsearchStorage(settings)
    storage.create_index_templates()
    print("Index templates created or updated successfully.")


if __name__ == "__main__":
    main()
