from __future__ import annotations

from pathlib import Path

import _bootstrap  # noqa: F401

from cloud_security_dashboard.config import get_settings
from cloud_security_dashboard.models import RawLog
from cloud_security_dashboard.storage import ElasticsearchStorage
from cloud_security_dashboard.utils import make_hash, now_utc


def main() -> None:
    settings = get_settings()
    storage = ElasticsearchStorage(settings)
    sample_dir = Path(__file__).resolve().parents[1] / "sample_logs"
    inserted = 0
    skipped = 0

    for file_path in sorted(sample_dir.iterdir()):
        if not file_path.is_file():
            continue
        for line in file_path.read_text(encoding="utf-8").splitlines():
            message = line.strip()
            if not message:
                continue
            raw_log = RawLog(
                raw_id=make_hash(file_path.as_posix(), message),
                raw_index=settings.raw_index_name,
                timestamp=now_utc(),
                message=message,
                host_name=settings.host_name,
                log_file_path=file_path.as_posix(),
                agent_name=settings.agent_name,
                processed=False,
                processed_at=None,
                fields={"project": "cloud-security-dashboard"},
            )
            if storage.index_raw_log_if_absent(settings.raw_index_name, raw_log):
                inserted += 1
            else:
                skipped += 1

    print(f"Seed complete. inserted={inserted} skipped={skipped}")


if __name__ == "__main__":
    main()
