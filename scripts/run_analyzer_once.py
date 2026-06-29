from __future__ import annotations

import _bootstrap  # noqa: F401

from cloud_security_dashboard.analyzer import Analyzer


def main() -> None:
    analyzer = Analyzer()
    result = analyzer.run_once()
    print(
        "Analyzer complete. "
        f"processed_logs={result.processed_logs} generated_events={result.generated_events}"
    )


if __name__ == "__main__":
    main()
