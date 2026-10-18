"""Retention excludes live, recently changed and non-cache data."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("storage_hygiene", Path(__file__).parents[1] / "tools/storage_hygiene.py")
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class StorageHygieneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.projects = Path(self.temp.name)
        self.repo = self.projects / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        workspace = self.repo / "nested"
        workspace.mkdir()
        (workspace / "Cargo.toml").write_text("[workspace]\n")
        self.root = workspace / "target/dev-small/incremental"
        self.candidate = self.root / "crate-cache"
        self.candidate.mkdir(parents=True)
        (self.candidate / "cache.bin").write_bytes(b"cache")
        self.config = {"projects_root": str(self.projects), "cache_roots": [str(self.root)], "cache_min_age_days": 2}
        self.future = time.time() + 3 * 86400

    def test_nested_cache_removed_but_sources_and_executable_preserved(self):
        executable = self.root.parent / "app"
        executable.write_bytes(b"selected executable")
        report = hygiene.clean(self.config, apply=True, now=self.future, active_paths=set())
        self.assertEqual(report["cache_dirs_removed"], 1)
        self.assertFalse(self.candidate.exists())
        self.assertTrue(executable.exists())
        self.assertTrue((self.repo / "nested/Cargo.toml").exists())

    def test_count_budget_limits_each_pass(self):
        second = self.root / "second-cache"
        second.mkdir()
        (second / "cache.bin").write_bytes(b"cache")
        report = hygiene.clean({**self.config, "max_cache_dirs_per_run": 1}, apply=True,
                               now=self.future, active_paths=set())
        self.assertEqual(report["cache_dirs_removed"], 1)
        self.assertEqual(sum(p.exists() for p in [self.candidate, second]), 1)

    def test_active_or_mapped_project_is_preserved(self):
        report = hygiene.clean(self.config, apply=True, now=self.future, active_paths={self.root.parent / "app"})
        self.assertEqual(report["cache_dirs_removed"], 0)
        self.assertTrue(self.candidate.exists())

    def test_recent_cache_and_dry_run_are_preserved(self):
        for apply, now in [(True, time.time()), (False, self.future)]:
            report = hygiene.clean(self.config, apply=apply, now=now, active_paths=set())
            self.assertEqual(report["cache_dirs_removed"], 0)
            self.assertTrue(self.candidate.exists())

    def test_symlink_and_release_paths_rejected(self):
        linked = self.root.parent / "linked"
        linked.symlink_to(self.candidate, target_is_directory=True)
        hygiene.clean(self.config, apply=True, now=self.future, active_paths=set())
        self.assertTrue(linked.is_symlink())
        for path in [self.repo / "nested/target/release/incremental", self.root.parent / "deps"]:
            with self.assertRaises(ValueError):
                hygiene.clean({**self.config, "cache_roots": [str(path)]}, active_paths=set())

    def test_failed_host_inspection_prevents_deletion(self):
        with patch.object(hygiene, "process_paths", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(RuntimeError):
                hygiene.clean(self.config, apply=True, now=self.future)
        self.assertTrue(self.candidate.exists())

    def test_active_project_appearing_on_final_scan_is_preserved(self):
        with patch.object(hygiene, "process_paths", side_effect=[set(), {self.repo / "new-writer"}]):
            report = hygiene.clean(self.config, apply=True, now=self.future)
        self.assertEqual(report["cache_dirs_removed"], 0)
        self.assertTrue(self.candidate.exists())


if __name__ == "__main__":
    unittest.main()
