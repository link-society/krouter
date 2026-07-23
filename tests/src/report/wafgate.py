"""
gotestwaf score gate (docs/spec/extensions.md Verification,
docs/spec/acceptance.md criterion 25).

Reads the JSON report produced by `task tests:waf` and fails when the
overall application-security true-positive score is below the blocking
threshold. Usage:

    python wafgate.py <report.json> [threshold-percent]
"""

import json
import pathlib
import sys


def resolve_score(report: dict) -> float:
    """
    The true-positive blocking score, as a percentage.

    gotestwaf nests scores differently across versions; every known
    location is tried, loudly failing when none matches so a format
    change cannot silently pass the gate.
    """

    candidates = [
        ("summary", "score"),
        ("score", "average"),
        ("app_sec", "true_positive"),
        ("truePositiveTests", "score"),
    ]

    for path in candidates:
        node = report
        for key in path:
            if not isinstance(node, dict) or key not in node:
                node = None
                break

            node = node[key]

        if isinstance(node, (int, float)):
            return float(node)

        if isinstance(node, str) and node.rstrip("%").replace(".", "", 1).isdigit():
            return float(node.rstrip("%"))

    raise SystemExit(
        f"cannot locate the score in the gotestwaf report; "
        f"top-level keys: {sorted(report)}"
    )


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: wafgate.py <report.json> [threshold-percent]")

    report_path = pathlib.Path(sys.argv[1])
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 50.0

    report = json.loads(report_path.read_text())
    score = resolve_score(report)

    verdict = "PASS" if score >= threshold else "FAIL"
    print(f"gotestwaf score: {score:.2f}% (threshold {threshold:.2f}%) -> {verdict}")

    if score < threshold:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
