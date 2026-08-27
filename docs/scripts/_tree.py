"""The tree the checks describe, and what is not part of it.

A literal list rather than `.gitignore`: these run from a released tarball,
where there is neither git nor an index to ask. One copy, so the checks agree
on what the tree is.
"""

import os

# `.claude` holds agent worktrees -- whole second checkouts, whose copy of
# docs/research/INDEX.md every check would otherwise read as if it were ours.
SKIP_DIRS = {
    ".git",
    ".claude",
    ".local-tmp",
    "target",
    "dist",
    "node_modules",
    "secrets",
    "__pycache__",
}


def walk(root, skip_dirs=SKIP_DIRS):
    """Yield every file path under `root`, minus `skip_dirs` and their contents."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            yield os.path.join(dirpath, name)
