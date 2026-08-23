#!/usr/bin/env python3
"""Every copy of the apt signing key's fingerprint agrees.

The fingerprint is public, and it is restated on purpose: the workflow asserts
the imported key matches it.

`.github/workflows/apt.yml` is the source. It is the only copy a machine acts
on -- a signing run fails if the key does not match it -- so a copy that
disagrees with it is the wrong copy, whichever file it is in.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / ".github/workflows/apt.yml"

# 40 hex, standalone, uppercase. Loose on purpose: it finds a stale fingerprint
# anywhere in the tree, including one nobody remembered was written down.
#
# A git object name is the same shape. Uppercase excludes the ones git prints,
# and `has_letter` excludes the all-zero null SHA and any other digits-only
# run. A real fingerprint with no A-F in forty characters is a 1-in-10^9 event,
# and the cost of it is one spurious failure.
FINGERPRINT = re.compile(r"\b[0-9A-F]{40}\b")


def has_letter(hex40: str) -> bool:
    return any(c in "ABCDEF" for c in hex40)


# Binary, generated, or holding fingerprints of their own.
SKIP_DIRS = {".git", "target", "dist", "node_modules", ".local-tmp", "research"}


def main() -> int:
    want = next(
        (m for m in FINGERPRINT.findall(SOURCE.read_text()) if has_letter(m)), None
    )
    if not want:
        print(f"FAIL: {SOURCE.relative_to(ROOT)} names no 40-hex fingerprint")
        return 1

    bad = []
    seen = 0
    for path in ROOT.rglob("*"):
        if not path.is_file() or set(path.relative_to(ROOT).parts) & SKIP_DIRS:
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for found in set(FINGERPRINT.findall(text)):
            if not has_letter(found):
                continue
            seen += 1
            if found != want:
                bad.append(f"{path.relative_to(ROOT)}: {found}")

    if bad:
        print(f"FAIL: these do not match {want}, which {SOURCE.name} signs with:")
        print("\n".join(f"       {b}" for b in sorted(bad)))
        return 1
    print(f"signing key: {seen} copies of {want}, all agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
