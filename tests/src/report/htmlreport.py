"""
Self-contained HTML rendering for the combined test report
(`task tests:report`, see build.py).

The page embeds all styling and a small vanilla-JS filter: no external
assets, so the report can be archived or attached to CI runs as a single
file.
"""

import html

from dataclasses import dataclass, field
from datetime import datetime, timezone

STATUS_LABELS = {
    "pass": "passed",
    "fail": "failed",
    "error": "errored",
    "skip": "skipped",
}


@dataclass
class Case:
    name: str
    classname: str
    time: float
    status: str  # one of STATUS_LABELS
    detail: str  # failure message / traceback / captured output


@dataclass
class Group:
    """One <testsuite> element (Go package, pytest run, ...)."""

    name: str
    cases: list[Case] = field(default_factory=list)


@dataclass
class Suite:
    """One krouter suite: unit, e2e, conformance or performance."""

    name: str
    groups: list[Group] = field(default_factory=list)

    def cases(self) -> list[Case]:
        return [case for group in self.groups for case in group.cases]

    def count(self, status: str) -> int:
        return sum(1 for case in self.cases() if case.status == status)

    def time(self) -> float:
        return sum(case.time for case in self.cases())


def fmt_duration(seconds: float) -> str:
    if seconds >= 60:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"

    if seconds >= 1:
        return f"{seconds:.1f}s"

    if seconds > 0:
        return f"{int(seconds * 1000)}ms"

    return ""


def render(
    suites: list[Suite],
    missing: list[str],
    links: list[tuple[str, str]] | None = None,
) -> str:
    all_cases = [case for suite in suites for case in suite.cases()]
    totals = {
        status: sum(1 for case in all_cases if case.status == status)
        for status in STATUS_LABELS
    }
    total = len(all_cases)
    duration = sum(suite.time() for suite in suites)
    failed = totals["fail"] + totals["error"] > 0 or bool(missing)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    meta = (
        f"generated {generated} &middot; "
        f"{len(suites)} suites &middot; {total} tests &middot; "
        f"{fmt_duration(duration) or '0s'}"
    )

    for label, href in links or []:
        meta += (
            f" &middot; <a href='{html.escape(href, quote=True)}'>"
            f"{html.escape(label)}</a>"
        )

    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>krouter test report</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        "<header>",
        "<div class='wrap'>",
        "<div class='title'>",
        "<h1>krouter <span>test report</span></h1>",
        f"<div class='meta'>{meta}</div>",
        "</div>",
        f"<div class='verdict {'fail' if failed else 'pass'}'>"
        f"{'FAILED' if failed else 'PASSED'}</div>",
        "</div>",
        "</header>",
        "<main class='wrap'>",
    ]

    parts.append(render_summary(totals, total))

    for suite in missing:
        parts.append(
            f"<div class='banner'>suite <b>{html.escape(suite)}</b> produced "
            "no JUnit file &mdash; it crashed before reporting</div>"
        )

    parts.append(
        "<div class='controls'>"
        "<input id='q' type='search' placeholder='filter tests&hellip;'>"
        "<label><input id='only-bad' type='checkbox'> failures only</label>"
        "</div>"
    )

    for suite in suites:
        parts.append(render_suite(suite))

    parts.extend([
        "</main>",
        f"<script>{JS}</script>",
        "</body>",
        "</html>",
    ])

    return "\n".join(parts)


def render_summary(totals: dict[str, int], total: int) -> str:
    tiles = [f"<div class='tile'><span>total</span><b>{total}</b></div>"]

    for status, label in STATUS_LABELS.items():
        tiles.append(
            f"<div class='tile {status}'><span>{label}</span>"
            f"<b>{totals[status]}</b></div>"
        )

    segments = "".join(
        f"<span class='{status}' style='width:{totals[status] / total * 100:.2f}%'></span>"
        for status in STATUS_LABELS
        if total and totals[status]
    )

    return (
        f"<section class='summary'><div class='tiles'>{''.join(tiles)}</div>"
        f"<div class='bar'>{segments}</div></section>"
    )


def render_suite(suite: Suite) -> str:
    chips = "".join(
        f"<span class='chip {status}'>{suite.count(status)} {label}</span>"
        for status, label in STATUS_LABELS.items()
        if suite.count(status)
    )

    parts = [
        f"<section class='suite' id='{html.escape(suite.name)}'>",
        "<div class='suite-head'>",
        f"<h2>{html.escape(suite.name)}</h2>",
        f"<div class='chips'>{chips}</div>",
        f"<div class='time'>{fmt_duration(suite.time())}</div>",
        "</div>",
    ]

    for group in suite.groups:
        if not group.cases:
            continue

        parts.append("<div class='group'>")

        if group.name:
            parts.append(f"<h3>{html.escape(group.name)}</h3>")

        for case in group.cases:
            parts.append(render_case(case))

        parts.append("</div>")

    parts.append("</section>")

    return "".join(parts)


def render_case(case: Case) -> str:
    label = html.escape(case.name)

    if case.classname and case.classname != case.name:
        label += f" <small>{html.escape(case.classname)}</small>"

    duration = fmt_duration(case.time)
    row = (
        f"<span class='dot'></span><span class='name'>{label}</span>"
        + (f"<span class='time'>{duration}</span>" if duration else "")
    )
    data = html.escape(f"{case.name} {case.classname}".lower(), quote=True)

    if case.detail:
        return (
            f"<details class='case {case.status}' data-name='{data}'>"
            f"<summary>{row}</summary>"
            f"<pre>{html.escape(case.detail)}</pre>"
            "</details>"
        )

    return f"<div class='case {case.status}' data-name='{data}'>{row}</div>"


CSS = """
:root {
  --bg: #f4f6f8; --card: #ffffff; --border: #e3e8ee;
  --text: #1a202c; --muted: #64748b; --accent: #485fc7;
  --pass: #16a34a; --fail: #dc2626; --error: #ea580c; --skip: #94a3b8;
  --pass-bg: #f0fdf4; --fail-bg: #fef2f2; --error-bg: #fff7ed; --skip-bg: #f8fafc;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    Inter, sans-serif;
}
.wrap { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
header {
  background: var(--card);
  border-bottom: 1px solid var(--border);
  margin-bottom: 24px;
}
header .wrap {
  display: flex; align-items: center; justify-content: space-between;
  padding-top: 20px; padding-bottom: 20px; gap: 16px; flex-wrap: wrap;
}
h1 { margin: 0; font-size: 22px; letter-spacing: -0.01em; }
h1 span { color: var(--muted); font-weight: 400; }
.meta { color: var(--muted); font-size: 13px; margin-top: 2px; }
.meta a { color: inherit; text-decoration: underline; }
.verdict {
  font-weight: 700; font-size: 14px; letter-spacing: 0.08em;
  padding: 8px 18px; border-radius: 999px; color: #fff;
}
.verdict.pass { background: var(--pass); }
.verdict.fail { background: var(--fail); }
main { padding: 24px 24px 64px; }
.summary { margin-bottom: 20px; }
.tiles { display: flex; gap: 12px; flex-wrap: wrap; }
.tile {
  flex: 1 1 120px; background: var(--card); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 16px;
}
.tile span {
  display: block; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--muted);
}
.tile b { font-size: 24px; font-variant-numeric: tabular-nums; }
.tile.pass b { color: var(--pass); }
.tile.fail b { color: var(--fail); }
.tile.error b { color: var(--error); }
.tile.skip b { color: var(--skip); }
.bar {
  display: flex; height: 8px; border-radius: 999px; overflow: hidden;
  margin-top: 12px; background: var(--border);
}
.bar .pass { background: var(--pass); }
.bar .fail { background: var(--fail); }
.bar .error { background: var(--error); }
.bar .skip { background: var(--skip); }
.banner {
  background: var(--fail-bg); border: 1px solid var(--fail);
  color: var(--fail); border-radius: 10px; padding: 12px 16px;
  margin-bottom: 16px;
}
.controls {
  display: flex; gap: 16px; align-items: center; margin: 24px 0 16px;
}
.controls input[type=search] {
  flex: 1; max-width: 420px; padding: 9px 14px; font: inherit;
  border: 1px solid var(--border); border-radius: 10px; background: var(--card);
}
.controls input[type=search]:focus {
  outline: 2px solid var(--accent); outline-offset: -1px;
}
.controls label {
  display: flex; gap: 8px; align-items: center; color: var(--muted);
  font-size: 14px; cursor: pointer;
}
.suite {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 12px; margin-bottom: 20px; overflow: hidden;
}
.suite-head {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 14px 20px; border-bottom: 1px solid var(--border);
}
.suite-head h2 { margin: 0; font-size: 17px; }
.suite-head .time { margin-left: auto; color: var(--muted); font-size: 13px; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip {
  font-size: 12px; font-weight: 600; padding: 2px 10px;
  border-radius: 999px; border: 1px solid;
}
.chip.pass { color: var(--pass); background: var(--pass-bg); border-color: #bbe7c8; }
.chip.fail { color: var(--fail); background: var(--fail-bg); border-color: #f5c2c2; }
.chip.error { color: var(--error); background: var(--error-bg); border-color: #f8d5b8; }
.chip.skip { color: #475569; background: var(--skip-bg); border-color: var(--border); }
.group { padding: 6px 8px; }
.group + .group { border-top: 1px solid var(--border); }
.group h3 {
  margin: 8px 12px 4px; font-size: 12px; font-weight: 600;
  letter-spacing: 0.02em; color: var(--muted);
}
.case {
  display: flex; align-items: baseline; gap: 10px;
  padding: 6px 12px; border-radius: 8px; font-size: 14px;
}
details.case { display: block; }
details.case > summary {
  display: flex; align-items: baseline; gap: 10px; cursor: pointer;
  list-style: none;
}
details.case > summary::-webkit-details-marker { display: none; }
details.case[open] { background: var(--skip-bg); }
.case:hover, details.case > summary:hover { background: var(--skip-bg); }
.dot {
  flex: none; width: 9px; height: 9px; border-radius: 999px;
  align-self: center;
}
.case.pass .dot { background: var(--pass); }
.case.fail .dot { background: var(--fail); }
.case.error .dot { background: var(--error); }
.case.skip .dot { background: var(--skip); }
.case.skip .name { color: var(--muted); }
.case .name { word-break: break-word; }
.case .name small { color: var(--muted); font-size: 12px; margin-left: 6px; }
.case .time {
  margin-left: auto; flex: none; color: var(--muted); font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.case pre {
  margin: 8px 4px 10px 19px; padding: 12px 14px; max-height: 420px;
  overflow: auto; background: #0f172a; color: #e2e8f0; border-radius: 8px;
  font: 12px/1.6 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre-wrap; word-break: break-word;
}
"""

JS = """
const q = document.getElementById('q');
const onlyBad = document.getElementById('only-bad');

function visible(el) { return el.style.display !== 'none'; }

function apply() {
  const term = q.value.toLowerCase().trim();

  document.querySelectorAll('.case').forEach(el => {
    const bad = el.classList.contains('fail') || el.classList.contains('error');
    const match = (!term || el.dataset.name.includes(term)) &&
      (!onlyBad.checked || bad);
    el.style.display = match ? '' : 'none';
  });

  document.querySelectorAll('.group').forEach(el => {
    el.style.display =
      [...el.querySelectorAll('.case')].some(visible) ? '' : 'none';
  });

  document.querySelectorAll('.suite').forEach(el => {
    el.style.display =
      [...el.querySelectorAll('.group')].some(visible) ? '' : 'none';
  });
}

q.addEventListener('input', apply);
onlyBad.addEventListener('change', apply);
"""
