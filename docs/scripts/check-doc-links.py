#!/usr/bin/env python3
"""Check relative Markdown links and doc paths cited from source.

Relative inline links must name an existing file. Markdown fragments must match
a GitHub-style heading or explicit HTML anchor. Reference-style links are
unsupported because the repository does not use them.

Backticked `.md` paths in source and configuration files resolve from the
repository root or, for a unique bare filename, by name. Parent-relative paths
are invalid because source comments have no common base directory. Only file
existence is checked. Markdown files are excluded because their paths are
relative to the file.

`doc-links: ignore` exempts all references on its line. Use it only for correct
references that cannot resolve in the repository. The result reports the
exemption count.
"""

import os
import re
import sys
import urllib.parse

from _tree import walk

SOURCE_EXT = {".rs", ".sh", ".py", ".yaml", ".yml", ".toml"}
SOURCE_NAMES = {"Makefile", "Dockerfile"}

# Inline links with whitespace-free targets. Image embeds can point outside the tree.
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
# GitHub accepts empty HTML anchors for compatibility fragments that outlive headings.
HTML_ANCHOR = re.compile(r'<a\s+(?:id|name)="([^"]+)"\s*></a>')
# A fenced block's contents are not headings: a shell transcript full of `# comment`
# lines would otherwise register every one of them as an anchor.
FENCE = re.compile(r"^\s*(```|~~~)")

# Backticked paths can end in a research line range (`:787` or `:787-792`).
# Whitespace marks prose, not a path.
DOC_REF = re.compile(r"`([^`\s]*\.md)(?::\d+(?:-\d+)?)?`")

IGNORE = re.compile(r"doc-links:\s*ignore")

# Released instructions can use either step-2 fragment; require both anchors.
REQUIRED_SETUP_ANCHORS = {
    "2-register-three-applications-in-entra",
    "2-set-up-your-cloud-identity-providers",
}


def line_of(body: str, pos: int) -> int:
    """0-based index of the line `pos` falls on."""
    return body.count("\n", 0, pos)


def exempt(lines: list[str], idx: int) -> bool:
    return idx < len(lines) and IGNORE.search(lines[idx]) is not None


def slug(heading: str) -> str:
    """Convert the supported subset of GitHub headings to anchors."""
    # GitHub omits inline-code and emphasis markers from anchors.
    text = re.sub(r"[`*_]", "", heading)
    # GitHub anchors keep link text and omit its target.
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return text.strip().lower().replace(" ", "-")


def anchors(path: str) -> set[str]:
    out: set[str] = set()
    seen: dict[str, int] = {}
    fenced = False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            for explicit in HTML_ANCHOR.finditer(line):
                out.add(explicit.group(1).casefold())
            m = HEADING.match(line)
            if not m:
                continue
            s = slug(m.group(2))
            if not s:
                continue
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
            out.add(s)
    return out


def cited_paths(
    root: str, rel: str, body: str, by_name: dict[str, str]
) -> tuple[int, int, list[str]]:
    """One source file's doc paths: how many checked, how many exempt, what broke."""
    out: list[str] = []
    lines = body.splitlines()
    checked = skipped = 0
    for m in DOC_REF.finditer(body):
        ref = m.group(1)
        # Wildcards, placeholders, and a bare `.md` extension are not paths.
        if any(c in ref for c in "*<>?") or os.path.basename(ref) == ".md":
            continue
        idx = line_of(body, m.start())
        if exempt(lines, idx):
            skipped += 1
            continue
        checked += 1
        where = f"{rel}:{idx + 1}"
        if ref.startswith("../") or "/../" in ref:
            out.append(f"{where}: `{ref}` -- relative to what? cite it from the repo root")
        elif os.path.isfile(os.path.join(root, ref)):
            pass
        elif os.path.basename(ref) != ref or ref not in by_name:
            out.append(f"{where}: `{ref}` -- no such file")
    return checked, skipped, out


def main(root: str) -> int:
    files: list[str] = []
    sources: list[str] = []
    for path in walk(root):
        name = os.path.basename(path)
        if name.endswith(".md"):
            files.append(path)
        elif os.path.splitext(name)[1] in SOURCE_EXT or name in SOURCE_NAMES:
            sources.append(path)
    files.sort()
    sources.sort()

    # Resolve unique bare filenames; duplicate names are ambiguous.
    seen_names: dict[str, int] = {}
    for path in files:
        seen_names[os.path.basename(path)] = seen_names.get(os.path.basename(path), 0) + 1
    by_name = {
        os.path.basename(p): p for p in files if seen_names[os.path.basename(p)] == 1
    }

    cache: dict[str, set[str]] = {}
    broken: list[str] = []
    checked = 0
    skipped = 0

    for path in files:
        rel = os.path.relpath(path, root)
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        lines = body.splitlines()
        for m in LINK.finditer(body):
            link = m.group(1)
            if link.startswith(("http://", "https://", "mailto:", "#!")):
                continue
            if exempt(lines, line_of(body, m.start())):
                skipped += 1
                continue
            checked += 1
            target_part, _, frag = link.partition("#")
            frag = urllib.parse.unquote(frag)
            if target_part:
                target = os.path.normpath(
                    os.path.join(os.path.dirname(path), urllib.parse.unquote(target_part))
                )
            else:
                target = path

            if not os.path.exists(target):
                broken.append(f"{rel}: {link} -- no such file")
                continue
            # Only Markdown fragments have anchors this checker can verify.
            if frag and target.endswith(".md"):
                if target not in cache:
                    cache[target] = anchors(target)
                if frag.lower() not in cache[target]:
                    broken.append(f"{rel}: {link} -- no such heading")

    setup = os.path.join(root, "SETUP.md")
    if os.path.isfile(setup):
        setup_anchors = cache.setdefault(setup, anchors(setup))
        for required in sorted(REQUIRED_SETUP_ANCHORS - setup_anchors):
            broken.append(f"SETUP.md: #{required} -- required compatibility anchor is missing")

    cited = 0
    for path in sources:
        with open(path, encoding="utf-8", errors="replace") as fh:
            n, exempted, bad = cited_paths(
                root, os.path.relpath(path, root), fh.read(), by_name
            )
        cited += n
        skipped += exempted
        broken.extend(bad)

    if broken:
        print(f"{len(broken)} broken reference(s):", file=sys.stderr)
        for b in broken:
            print(f"  {b}", file=sys.stderr)
        return 1

    # Name the bypass so exemption growth is visible.
    note = f", {skipped} exempted by `doc-links: ignore`" if skipped else ""
    print(f"docs: {checked} relative links across {len(files)} files, all resolve")
    print(f"source: {cited} doc paths cited across {len(sources)} files, all resolve{note}")
    return 0


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(here))))
