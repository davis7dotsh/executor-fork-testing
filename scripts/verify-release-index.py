#!/usr/bin/env python3
import argparse
import json
import sys


EXPECTED_PLATFORMS = {
    ("linux", "amd64"),
    ("linux", "arm64"),
}
VERSION_ANNOTATION = "org.opencontainers.image.version"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Verify the release OCI index platforms and version annotation"
    )
    parser.add_argument("--version", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        index = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        raise SystemExit(f"release index is not valid JSON: {error}") from error
    if not isinstance(index, dict):
        raise SystemExit("release index must be a JSON object")

    annotations = index.get("annotations")
    if not isinstance(annotations, dict):
        raise SystemExit("release index has no annotations object")
    if annotations.get(VERSION_ANNOTATION) != args.version:
        raise SystemExit(
            f"release index version annotation does not equal {args.version}"
        )

    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise SystemExit("release index has no manifests array")
    platforms = []
    for manifest in manifests:
        if not isinstance(manifest, dict) or not isinstance(manifest.get("platform"), dict):
            raise SystemExit("release index contains a manifest without a platform")
        platform = manifest["platform"]
        operating_system = platform.get("os")
        architecture = platform.get("architecture")
        if not isinstance(operating_system, str) or not isinstance(architecture, str):
            raise SystemExit("release index contains an invalid platform")
        platforms.append((operating_system, architecture))
    if len(platforms) != len(EXPECTED_PLATFORMS) or set(platforms) != EXPECTED_PLATFORMS:
        raise SystemExit(f"release index has unexpected platforms: {platforms}")

    print(f"verified release index for {args.version}")


if __name__ == "__main__":
    main()
