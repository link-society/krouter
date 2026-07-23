"""
Build the combined test report for `task tests:report`.

Merges the per-suite JUnit files (tests/results/<suite>/junit.xml) into
tests/results/report/junit.xml and renders them as a single self-contained
HTML page at tests/results/report/report.html (see htmlreport.py).

Exits non-zero when a suite produced no JUnit file (it crashed before
reporting) or when any test failed or errored, so the task's exit code
reflects the overall verdict even though the individual suites run with
their errors ignored.
"""

import shutil
import sys

from pathlib import Path

from junitparser import Error, Failure, JUnitXml, Skipped, TestCase, TestSuite

from htmlreport import Case, Group, Suite, render

SUITES = ["unit", "e2e", "conformance", "performance", "waf"]

RESULTS = Path("tests/results")
REPORT_DIR = RESULTS / "report"

# The full gotestwaf evaluation, bundled next to report.html and linked
# from its header (docs/spec/extensions.md Verification).
GOTESTWAF_HTML = RESULTS / "waf" / "waf-evaluation.html"


def suite_elements(xml: JUnitXml | TestSuite) -> list[TestSuite]:
    if isinstance(xml, TestSuite):
        return [xml]

    return list(xml)


def case_status(case: TestCase) -> str:
    for result in case.result:
        if isinstance(result, Error):
            return "error"

        if isinstance(result, Failure):
            return "fail"

        if isinstance(result, Skipped):
            return "skip"

    return "pass"


def case_detail(case: TestCase) -> str:
    parts = []

    for result in case.result:
        if result.message:
            parts.append(result.message)

        if result.text:
            parts.append(result.text)

    if case.system_out:
        parts.append(case.system_out)

    if case.system_err:
        parts.append(case.system_err)

    return "\n\n".join(part.strip() for part in parts if part and part.strip())


def collect(element: TestSuite) -> Group:
    group = Group(name=element.name or "")

    for case in element:
        if not isinstance(case, TestCase):
            continue

        classname = case.classname or ""
        if classname == group.name:
            classname = ""

        group.cases.append(Case(
            name=case.name or "",
            classname=classname,
            time=case.time or 0.0,
            status=case_status(case),
            detail=case_detail(case),
        ))

    return group


def main() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    merged = JUnitXml("krouter test suites")
    suites: list[Suite] = []
    missing: list[str] = []

    for name in SUITES:
        path = RESULTS / name / "junit.xml"
        if not path.is_file():
            missing.append(name)
            continue

        suite = Suite(name=name)

        for element in suite_elements(JUnitXml.fromfile(str(path))):
            suite.groups.append(collect(element))

            element.name = f"{name}: {element.name or name}"
            merged.add_testsuite(element)

        suites.append(suite)

    merged.update_statistics()
    junit_path = REPORT_DIR / "junit.xml"
    merged.write(str(junit_path))

    links: list[tuple[str, str]] = []
    if GOTESTWAF_HTML.is_file():
        shutil.copyfile(GOTESTWAF_HTML, REPORT_DIR / "gotestwaf.html")
        links.append(("gotestwaf report", "gotestwaf.html"))

    html_path = REPORT_DIR / "report.html"
    html_path.write_text(render(suites, missing, links), encoding="utf-8")

    print()
    print(f"{'suite':<14} {'tests':>6} {'failed':>7} {'errors':>7} {'skipped':>8}")

    for suite in suites:
        print(
            f"{suite.name:<14} {len(suite.cases()):>6} "
            f"{suite.count('fail'):>7} {suite.count('error'):>7} "
            f"{suite.count('skip'):>8}"
        )

    for name in missing:
        print(f"{name:<14} MISSING (crashed before writing a JUnit file)")

    print()
    print(f"report: {html_path} + {junit_path}")

    failed = sum(
        suite.count("fail") + suite.count("error") for suite in suites
    )

    if missing or failed:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
