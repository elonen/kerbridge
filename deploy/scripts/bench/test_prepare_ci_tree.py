#!/usr/bin/env python3
"""Boundary tests for prepare-ci-tree.py; no Docker or network required."""

from __future__ import annotations

import errno
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("prepare-ci-tree.py")
SPEC = importlib.util.spec_from_file_location("prepare_ci_tree", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PrepareCiTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        # Resolved: on macOS the temp dir sits under /var, itself a symlink to
        # private/var, so the unresolved spelling would make every case here
        # compare a lexical path against a canonical one.
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "checkout"
        self.source.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_refused_without_removing(self, target: Path, sentinel: Path) -> None:
        with self.assertRaises(SystemExit):
            MODULE.prepare(str(self.source), str(target))
        self.assertTrue(sentinel.exists())

    def test_managed_subtree_is_cleaned_and_marked(self) -> None:
        target = self.source / ".local-tmp" / "custom" / "tree"
        target.mkdir(parents=True)
        stale = target / "stale"
        stale.write_text("keep out")

        got = MODULE.prepare(str(self.source), str(target))

        self.assertEqual(got, target)
        self.assertFalse(stale.exists())
        self.assertTrue((target / MODULE.MARKER).is_file())

    def test_empty_external_tree_can_be_adopted_and_reused(self) -> None:
        target = self.root / "runner" / "custom-tree"
        target.mkdir(parents=True)
        MODULE.prepare(str(self.source), str(target))
        stale = target / "stale"
        stale.write_text("remove me")

        MODULE.prepare(str(self.source), str(target))

        self.assertFalse(stale.exists())

    def test_transient_nonempty_failure_is_retried(self) -> None:
        target = self.source / ".local-tmp" / "custom-tree"
        target.mkdir(parents=True)
        stale = target / "deploy" / "sync"
        stale.mkdir(parents=True)
        real_rmtree = MODULE.shutil.rmtree
        calls = 0

        def transient_once(path: Path) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", stale)
            real_rmtree(path)

        with mock.patch.object(MODULE.shutil, "rmtree", side_effect=transient_once), mock.patch.object(
            MODULE.time, "sleep"
        ) as sleep:
            MODULE.prepare(str(self.source), str(target))

        self.assertEqual(calls, 2)
        sleep.assert_called_once_with(0.05)
        self.assertFalse(stale.exists())
        self.assertTrue((target / MODULE.MARKER).is_file())

    def test_source_checkout_is_refused(self) -> None:
        sentinel = self.source / "sentinel"
        sentinel.touch()
        self.assert_refused_without_removing(self.source, sentinel)

    def test_source_ancestor_is_refused(self) -> None:
        sentinel = self.source / "sentinel"
        sentinel.touch()
        self.assert_refused_without_removing(self.root, sentinel)

    def test_filesystem_root_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            MODULE.prepare(str(self.source), self.root.anchor)

    def test_managed_root_itself_is_refused(self) -> None:
        managed = self.source / ".local-tmp"
        managed.mkdir()
        sentinel = managed / "sentinel"
        sentinel.touch()
        self.assert_refused_without_removing(managed, sentinel)

    def test_populated_unmarked_external_tree_is_refused(self) -> None:
        target = self.root / "unmanaged"
        target.mkdir()
        sentinel = target / "sentinel"
        sentinel.touch()
        self.assert_refused_without_removing(target, sentinel)

    def test_unmanaged_checkout_subdirectory_is_refused(self) -> None:
        target = self.source / "deploy"
        target.mkdir()
        sentinel = target / "sentinel"
        sentinel.touch()
        self.assert_refused_without_removing(target, sentinel)

    def test_marker_for_another_checkout_is_refused(self) -> None:
        target = self.root / "other-tree"
        target.mkdir()
        marker = target / MODULE.MARKER
        marker.write_text(f"{MODULE.MARKER_VERSION}\nsource=/other/checkout\n")
        self.assert_refused_without_removing(target, marker)

    def test_symlink_cannot_make_managed_name_delete_external_tree(self) -> None:
        external = self.root / "external"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.touch()
        managed = self.source / ".local-tmp"
        managed.mkdir()
        link = managed / "tree"
        link.symlink_to(external, target_is_directory=True)

        self.assert_refused_without_removing(link, sentinel)

    def test_managed_root_symlink_is_refused_even_when_external_is_empty(self) -> None:
        external = self.root / "empty-external"
        external.mkdir()
        managed = self.source / ".local-tmp"
        managed.symlink_to(external, target_is_directory=True)

        with self.assertRaises(SystemExit):
            MODULE.prepare(str(self.source), str(managed / "tree"))
        self.assertEqual(list(external.iterdir()), [])


    def test_managed_root_symlink_is_refused_through_a_symlinked_checkout_path(self) -> None:
        """The guard must survive a checkout reached through a symlink.

        macOS reaches this by /var alone; Linux never spells a path this way by
        accident, so the alias is built explicitly and both platforms cover the
        divergence between the lexical and the resolved checkout.
        """
        external = self.root / "empty-external"
        external.mkdir()
        managed = self.source / ".local-tmp"
        managed.symlink_to(external, target_is_directory=True)
        alias = self.root / "checkout-alias"
        alias.symlink_to(self.source, target_is_directory=True)

        with self.assertRaises(SystemExit):
            MODULE.prepare(str(alias), str(alias / ".local-tmp" / "tree"))
        self.assertEqual(list(external.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
