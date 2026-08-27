#!/usr/bin/env python3
"""Check that indexed research remains archived and deliberately accessed."""

import re
import shutil
import subprocess
import sys
from pathlib import Path

from _tree import walk

ARCHIVE_REF = re.compile(r"^Archive: `([A-Za-z0-9._-]+\.zst)`\.$", re.MULTILINE)
LINE_RANGE = re.compile(r"(?<!\w):(\d+)(?:-(\d+))?")


def text_files(root: Path):
    for name in walk(root):
        path = Path(name)
        if path.suffix == ".zst":
            continue
        try:
            yield path, path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            pass


def index_ranges(body: str):
    archive = None
    for line_number, line in enumerate(body.splitlines(), 1):
        if line.startswith("## "):
            archive = None
        match = ARCHIVE_REF.fullmatch(line)
        if match:
            archive = match.group(1)
            continue
        if not archive:
            continue
        prose = re.sub(r"`[^`]*`", "", line)
        for match in LINE_RANGE.finditer(prose):
            first = int(match.group(1))
            last = int(match.group(2) or match.group(1))
            yield line_number, archive, first, last


def main(root: Path) -> int:
    research = root / "docs" / "research"
    index = research / "INDEX.md"
    index_body = index.read_text(encoding="utf-8")
    archives = {path.name for path in research.glob("*.zst")}
    indexed = set(ARCHIVE_REF.findall(index_body))
    errors: list[str] = []

    raw = sorted(
        str(path.relative_to(research))
        for path in research.rglob("*.md")
        if path != index
    )
    if raw:
        errors.append(f"raw research Markdown present: {', '.join(raw)}")
    for name in sorted(indexed - archives):
        errors.append(f"INDEX.md names missing archive: {name}")
    for name in sorted(archives - indexed):
        errors.append(f"archive is absent from INDEX.md: {name}")

    bodies: dict[str, str] = {}
    zstd = shutil.which("zstd")
    if not zstd:
        errors.append("zstd is required to check research archives")
    else:
        for name in sorted(archives):
            result = subprocess.run(
                [zstd, "-qdc", "--", str(research / name)],
                check=False,
                capture_output=True,
            )
            if result.returncode:
                errors.append(f"cannot decompress {name}")
                continue
            try:
                body = result.stdout.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(f"decompressed {name} is not UTF-8")
                continue
            bodies[name] = body

    for line, name, first, last in index_ranges(index_body):
        if first > last:
            errors.append(f"INDEX.md:{line} has reversed range :{first}-{last}")
        elif name in bodies and last > len(bodies[name].splitlines()):
            errors.append(
                f"INDEX.md:{line} requests :{first}-{last} from {name}, "
                f"which has {len(bodies[name].splitlines())} lines"
            )

    for source, body in text_files(root):
        if source == index:
            continue
        for name in sorted(archives):
            if name in body:
                errors.append(
                    f"{source.relative_to(root)} cites archive {name}; "
                    "cite the research spike by name"
                )
    for source, body in bodies.items():
        for name in sorted(archives):
            if name in body:
                errors.append(
                    f"{source} cites archive {name}; cite the research spike by name"
                )

    if errors:
        print(f"{len(errors)} research archive error(s):", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    print(f"research: {len(archives)} compressed spike archives match INDEX.md")
    return 0


if __name__ == "__main__":
    here = Path(__file__).resolve()
    sys.exit(main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else here.parents[2]))
