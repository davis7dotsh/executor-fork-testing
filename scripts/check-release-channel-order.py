#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import sys


NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = rf"(?:{NUMERIC_IDENTIFIER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_PATTERN = re.compile(
    rf"^({NUMERIC_IDENTIFIER})\.({NUMERIC_IDENTIFIER})\.({NUMERIC_IDENTIFIER})"
    rf"(?:-({PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Refuse release channel moves that would lower SemVer precedence"
    )
    parser.add_argument("--channel", choices=("latest", "beta"), required=True)
    current_source = parser.add_mutually_exclusive_group(required=True)
    current_source.add_argument("--current")
    current_source.add_argument("--history-file")
    parser.add_argument("--candidate", required=True)
    return parser.parse_args()


def parse_version(value):
    match = SEMVER_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid SemVer: {value}")
    major, minor, patch, prerelease = match.groups()
    return (
        (int(major), int(minor), int(patch)),
        None if prerelease is None else prerelease.split("."),
    )


def compare_prerelease(left, right):
    if left is None:
        return 0 if right is None else 1
    if right is None:
        return -1

    for left_identifier, right_identifier in zip(left, right, strict=False):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdigit()
        right_numeric = right_identifier.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_identifier) > int(right_identifier) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_identifier > right_identifier else -1

    if len(left) == len(right):
        return 0
    return 1 if len(left) > len(right) else -1


def compare_versions(left, right):
    left_core, left_prerelease = parse_version(left)
    right_core, right_prerelease = parse_version(right)
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    return compare_prerelease(left_prerelease, right_prerelease)


def validate_channel_version(channel, value, role):
    parsed = parse_version(value)
    is_prerelease = parsed[1] is not None
    expected_prerelease = channel == "beta"
    if is_prerelease != expected_prerelease:
        raise ValueError(f"{channel} channel has an incompatible {role} version")
    return parsed


def load_release_history(path):
    if path == "-":
        pages = json.load(sys.stdin)
    else:
        pages = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(pages, list):
        raise ValueError("release history must be a JSON array of pages")
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("release history page must be a JSON array")
        for release in page:
            if not isinstance(release, dict):
                raise ValueError("release history entry must be a JSON object")
            yield release


def latest_published_version(channel, history_file):
    latest = None
    for release in load_release_history(history_file):
        if release.get("draft") is not False:
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not tag.startswith("v"):
            continue
        version = tag[1:]
        try:
            validate_channel_version(channel, version, "published")
        except ValueError:
            continue
        if latest is None or compare_versions(version, latest) > 0:
            latest = version
    return latest


def main():
    args = parse_args()
    try:
        validate_channel_version(args.channel, args.candidate, "candidate")
        current = (
            args.current
            if args.current is not None
            else latest_published_version(args.channel, args.history_file)
        )
        if current is not None:
            validate_channel_version(args.channel, current, "current")
    except ValueError as error:
        raise SystemExit(str(error)) from error

    if current is None:
        print("first")
        return

    relation = compare_versions(args.candidate, current)
    if relation < 0:
        raise SystemExit(
            f"candidate would move {args.channel} backward from {current} to {args.candidate}"
        )
    print("equal" if relation == 0 else "newer")


if __name__ == "__main__":
    main()
