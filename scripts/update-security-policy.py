#!/usr/bin/env python3
"""Regenerate SECURITY.md for a release.

Invoked by .github/workflows/trigger-release.yml with the version about to
be tagged; prints the new policy on stdout. The supported-versions table
marks the latest release of each supported major as supported, mirroring
the flowg policy.
"""

from argparse import ArgumentParser

import subprocess

from packaging.version import InvalidVersion, Version

REPOSITORY = "https://github.com/link-society/krouter"
MAJOR_SUPPORT_WINDOW = 3

SECURITY_POLICY_HEADER = f"""
# Security Policy

## Reporting a Vulnerability

Please open a `Security Report` on the
[bug tracker]({REPOSITORY}/issues/new/choose).

## Supported Versions

| Version | Supported |
| --- | --- |
"""


def get_tags() -> list[Version]:
    output = subprocess.check_output(
        "git tag --list --sort=-v:refname",
        text=True,
        shell=True,
    )

    tags = []

    for line in output.splitlines():
        tag = line.strip()
        if not tag.startswith("v"):
            continue

        try:
            tags.append(Version(tag[1:]))
        except InvalidVersion:
            continue

    return tags


def is_supported(
    t: Version,
    max_major: int,
    latest_by_major: dict[int, Version],
) -> bool:
    has_stable = max_major >= 1
    min_supported_major = max(1, max_major - (MAJOR_SUPPORT_WINDOW - 1))

    if any([
        not has_stable and t.major == 0,
        has_stable and t.major >= min_supported_major,
    ]):
        return t == latest_by_major[t.major]

    return False


def get_supported_versions(tags: list[Version]) -> list[tuple[Version, bool]]:
    assert len(tags) > 0

    latest_by_major: dict[int, Version] = {}

    for t in tags:
        if t.major not in latest_by_major or t > latest_by_major[t.major]:
            latest_by_major[t.major] = t

    max_major = max(t.major for t in tags)

    return [
        (t, is_supported(t, max_major, latest_by_major))
        for t in tags
    ]


def main():
    parser = ArgumentParser()
    parser.add_argument("--next-release", nargs=1, required=True)
    args = parser.parse_args()

    next_release = Version(args.next_release[0].lstrip("v"))
    tags = get_tags()
    tags.insert(0, next_release)

    supported_versions = get_supported_versions(sorted(set(tags), reverse=True))

    print(SECURITY_POLICY_HEADER.strip())
    for t, supported in supported_versions:
        icon = ":white_check_mark:" if supported else ":x:"
        print(f"| [{t}]({REPOSITORY}/releases/tag/v{t}) | {icon} |")


if __name__ == "__main__":
    main()
