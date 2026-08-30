#!/usr/bin/env python3
"""Validate, mark, and empty a disposable bench checkout."""

from __future__ import annotations

import errno
import os
import shutil
import sys
import time
from pathlib import Path
from typing import NoReturn


MARKER = ".kerbridge-ci-tree"
MARKER_VERSION = "kerbridge bench tree v1"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"prepare-ci-tree: {message}")


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def marker_contents(source: Path) -> str:
    return f"{MARKER_VERSION}\nsource={source}\n"


def remove_tree(target: Path) -> None:
    # Docker teardown and bind-mount release can briefly race removal of a
    # nested directory. Retry only the two transient directory errors, after
    # the caller has completed all containment and ownership checks.
    attempts = 8
    for attempt in range(attempts):
        try:
            shutil.rmtree(target)
            return
        except FileNotFoundError:
            return
        except OSError as error:
            if error.errno not in (errno.ENOTEMPTY, errno.EBUSY) or attempt == attempts - 1:
                raise
            time.sleep(0.05 * (attempt + 1))


def prepare(source_arg: str, target_arg: str) -> Path:
    source_lexical = Path(os.path.abspath(source_arg))
    source = source_lexical.resolve(strict=True)
    if not source.is_dir():
        fail(f"source is not a directory: {source}")

    # Resolve every existing symlink before judging or deleting the path.  The
    # resolved name is also returned to the caller, so validation cannot be
    # followed by an rm through the original symlink spelling.
    lexical_target = Path(os.path.abspath(target_arg))
    target = lexical_target.resolve(strict=False)
    root = Path(target.anchor)
    if target == root:
        fail(f"refusing filesystem root: {target}")
    if target == source:
        fail(f"refusing source checkout: {target}")
    if is_within(source, target):
        fail(f"refusing an ancestor of the source checkout: {target}")

    managed_root = source / ".local-tmp"
    # Judge membership under both spellings of the checkout. The target stays
    # lexical so a symlinked `.local-tmp` is still visible as traversal through
    # the managed root, while `source` is resolved. The two diverge whenever an
    # ancestor of the checkout is a symlink -- /var on macOS -- and comparing
    # across them answers "not in the managed root" for every such checkout,
    # retiring this guard silently. Bounded: a third alias for the target that
    # derives from neither spelling is not recognized here, and falls through to
    # the marker check below.
    managed_lexical = source_lexical / ".local-tmp"
    within_managed_root = is_within(lexical_target, managed_root) or is_within(
        lexical_target, managed_lexical
    )
    if within_managed_root and managed_root.is_symlink():
        fail(f"managed root must not be a symlink: {managed_root}")
    in_managed_root = is_within(target, managed_root)
    if target == managed_root:
        fail(f"refusing the managed root itself: {target}")
    if is_within(target, source) and not in_managed_root:
        fail(f"refusing an unmanaged path inside the source checkout: {target}")

    expected_marker = marker_contents(source)
    if target.exists():
        if not target.is_dir():
            fail(f"target is not a directory: {target}")
        entries = list(target.iterdir())
        if not in_managed_root and entries:
            marker = target / MARKER
            try:
                contents = marker.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                fail(f"populated external target has no valid {MARKER}: {target}")
            if contents != expected_marker:
                fail(f"external target belongs to another checkout: {target}")

        remove_tree(target)

    target.mkdir(parents=True)
    (target / MARKER).write_text(expected_marker, encoding="utf-8")
    return target


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: prepare-ci-tree.py SOURCE TARGET")
    print(prepare(sys.argv[1], sys.argv[2]))


if __name__ == "__main__":
    main()
