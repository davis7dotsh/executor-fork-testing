#!/usr/bin/env python3
import argparse
import gzip
import pathlib
import tarfile


ARCHIVE_MEMBERS = (
    ("executor", 0o755),
    ("LICENSE", 0o644),
    ("THIRD_PARTY_LICENSES.html", 0o644),
    ("THIRD_PARTY_JAVASCRIPT_LICENSES.json", 0o644),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a deterministic Executor release archive")
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.epoch < 0:
        raise SystemExit("--epoch must be a non-negative Unix timestamp")

    expected = {name for name, _ in ARCHIVE_MEMBERS}
    actual = {path.name for path in args.source.iterdir()}
    if actual != expected:
        raise SystemExit(
            f"release archive staging members differ: expected {sorted(expected)}, got {sorted(actual)}"
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=args.epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, mode in ARCHIVE_MEMBERS:
                    source = args.source / name
                    if not source.is_file() or source.is_symlink():
                        raise SystemExit(f"release archive member must be a regular file: {source}")
                    info = tarfile.TarInfo(name)
                    info.size = source.stat().st_size
                    info.mtime = args.epoch
                    info.mode = mode
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    with source.open("rb") as contents:
                        archive.addfile(info, contents)


if __name__ == "__main__":
    main()
