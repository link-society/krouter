"""
gotestwaf score gate (docs/spec/extensions.md Verification,
docs/spec/acceptance.md criterion 25).

Reads the JSON report produced by `task tests:waf` and fails when the
overall application-security true-positive score is below the blocking
threshold. A one-case JUnit file is written next to the JSON report so
the verdict joins the aggregate test report (build.py). Usage:

    python wafgate.py <report.json> [threshold-percent]
"""

import json
import pathlib
import sys

from junitparser import Failure, JUnitXml, TestCase, TestSuite


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


def write_junit(path: pathlib.Path, score: float, threshold: float) -> None:
    """
    One JUnit test case carrying the gate verdict, merged into the
    aggregate report by build.py.
    """

    case = TestCase("gotestwaf score gate", classname="waf")
    if score < threshold:
        case.result = [Failure(
            f"score {score:.2f}% below the {threshold:.2f}% threshold")]

    suite = TestSuite("gotestwaf")
    suite.add_testcase(case)

    xml = JUnitXml()
    xml.add_testsuite(suite)
    xml.update_statistics()
    xml.write(str(path))


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: wafgate.py <report.json> [threshold-percent]")

    report_path = pathlib.Path(sys.argv[1])
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 50.0

    report = json.loads(report_path.read_text())
    score = resolve_score(report)

    write_junit(report_path.parent / "junit.xml", score, threshold)

    verdict = "PASS" if score >= threshold else "FAIL"
    print(f"gotestwaf score: {score:.2f}% (threshold {threshold:.2f}%) -> {verdict}")

    if score < threshold:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
