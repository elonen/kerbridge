#!/usr/bin/env python3
"""Every relative markdown link, and every doc path cited from source, resolves.

The docs are a route, not a pile: `SETUP.md` is eight steps and an optional
uninstall, and each step's depth lives in `docs/setup/`, reached by
`SETUP.md#<step-heading>` from both directions.
CLAUDE.md states the invariant that keeps that working -- *never rename a
`SETUP.md` step heading* -- and until now nothing enforced it. A rename breaks
eighteen links silently, and the reader who finds out is an operator halfway
through a deployment.

So this walks every `.md` file, resolves every link that is not http(s) or
mailto, and checks the file exists and the `#fragment` names a heading in it.
Anchors are slugged the way GitHub does it (lowercase, drop punctuation, spaces
to hyphens, duplicates suffixed `-1`, `-2`), because that is the renderer the
links are written for.

Reference-style links (`[text][label]` with `[label]: target` below) are not
followed: nothing here uses them, and supporting a form the repo does not use
would be untested code.

## Doc paths cited from source

Comments carry the other half of the route. A measurement's evidence, a design
decision, a research spike -- the anchor is the whole value of the comment, and a
pointer at a file that is not there is worse than no pointer, because it reads as
if someone checked. These are cited as a backticked path, so they are found by
looking for backticks rather than by parsing comment syntax: one rule covers
Rust, shell, Python, YAML, Makefiles and Dockerfiles, and a path in a string
literal is worth checking on the same terms as one in a comment.

**A cited path is resolved from the repository root**, or by bare filename for
the shorthand a few spikes are named by. A `../`-relative one is refused: a
comment has no base directory a reader can agree on, since the same
`../DESIGN.md` (doc-links: ignore -- it is the counter-example) sits two
directories from one source file and three from another, and every such pointer
in this tree resolved nowhere at all. Only existence is checked;
the trailing `:787-792` a research citation carries is stripped, and the `§` and
`@ "heading"` forms are left alone, because a heading reference that has drifted
is a judgment call rather than a break.

Markdown prose is deliberately excluded from this half. A `.md` file *does* have
a base directory, so its backticked `../docs/...` paths are correct as written
and only its links are ours to check.

## The bypass

`doc-links: ignore` anywhere on the line exempts every reference on it, in either
half. It is for the reference that is right and unresolvable -- a file this repo
does not carry, a path assembled at runtime -- and for the emergency where a
correct pointer is the only thing standing between a fix and a green build.

It is deliberately per line and never per file or per directory: a bypass has to
sit where the reader of the pointer will see it. The count of exempted references
is printed alongside the checked ones, so a growing number of them is visible
rather than quietly becoming the norm.

Exit 0 and print a count, or list every break and exit 1.
"""

import os
import re
import sys
import urllib.parse

SKIP_DIRS = {".git", "target", ".local-tmp", "dist", "node_modules", "secrets"}

# Where a doc path may be cited from. By extension, plus the two that are named
# rather than suffixed.
SOURCE_EXT = {".rs", ".sh", ".py", ".yaml", ".yml", ".toml"}
SOURCE_NAMES = {"Makefile", "Dockerfile"}

# `[text](target)` where target has no whitespace. The negative lookbehind drops
# image embeds -- `![alt](x.png)` points at a file, not a document, and the ones
# here live outside the tree this walks.
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
# A fenced block's contents are not headings: a shell transcript full of `# comment`
# lines would otherwise register every one of them as an anchor.
FENCE = re.compile(r"^\s*(```|~~~)")

# A backticked path ending `.md`, carrying the optional `:787` or `:787-792` a
# research citation ends with. Anything with whitespace in it is prose that
# happens to mention a file, not a path.
DOC_REF = re.compile(r"`([^`\s]*\.md)(?::\d+(?:-\d+)?)?`")

# The per-line opt-out. Spelled with the script's own name so a reader who meets
# one knows what to run to see what it is silencing.
IGNORE = re.compile(r"doc-links:\s*ignore")


def line_of(body: str, pos: int) -> int:
    """0-based index of the line `pos` falls on."""
    return body.count("\n", 0, pos)


def exempt(lines: list[str], idx: int) -> bool:
    return idx < len(lines) and IGNORE.search(lines[idx]) is not None


def slug(heading: str) -> str:
    """GitHub's heading -> anchor transform, for the subset that appears here."""
    # Inline code and emphasis are markup, not text: `docs/setup/` in a heading
    # anchors as docssetup, and the links in the tree are written that way.
    text = re.sub(r"[`*_]", "", heading)
    # Strip a trailing link target, keeping its text -- headings here do not have
    # them, but a heading that gained one should not silently change anchor.
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
        # A placeholder standing for a set of files, or the bare extension being
        # named as an extension. Neither is a path to anything.
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
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f.endswith(".md"):
                files.append(os.path.join(dirpath, f))
            elif os.path.splitext(f)[1] in SOURCE_EXT or f in SOURCE_NAMES:
                sources.append(os.path.join(dirpath, f))
    files.sort()
    sources.sort()

    # Bare filename -> its path, for the shorthand a few research spikes are
    # cited by. A name carried by two files is not a pointer, so it is dropped
    # rather than resolved to whichever was walked first.
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
                target = path  # a bare `#anchor` is same-file

            if not os.path.exists(target):
                broken.append(f"{rel}: {link} -- no such file")
                continue
            # Only markdown has anchors we can verify. A fragment into anything
            # else is not ours to judge.
            if frag and target.endswith(".md"):
                if target not in cache:
                    cache[target] = anchors(target)
                if frag.lower() not in cache[target]:
                    broken.append(f"{rel}: {link} -- no such heading")

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

    # Named rather than merely counted: a bypass is meant to be conspicuous.
    note = f", {skipped} exempted by `doc-links: ignore`" if skipped else ""
    print(f"docs: {checked} relative links across {len(files)} files, all resolve")
    print(f"source: {cited} doc paths cited across {len(sources)} files, all resolve{note}")
    return 0


if __name__ == "__main__":
    # Default to the repository root, two levels up from docs/scripts/.
    here = os.path.dirname(os.path.abspath(__file__))
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(here))))
